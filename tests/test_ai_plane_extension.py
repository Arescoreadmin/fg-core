from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.rag.chunking import ChunkingConfig, CorpusChunk, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.main import build_app
from services.ai.providers.base import ProviderResponse
from services.ai_plane_extension.service import write_ai_plane_evidence

_CHUNK_CONFIG = ChunkingConfig(max_chars=180, overlap_chars=0)


def _chunks(tenant_id: str, source_id: str, content: str) -> list[CorpusChunk]:
    result = ingest_corpus(
        IngestRequest(documents=[CorpusDocument(source_id=source_id, content=content)]),
        trusted_tenant_id=tenant_id,
    )
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


def _setup_client(
    tmp_path: Path, *, ai_enabled: bool = True
) -> tuple[TestClient, str, str]:
    db_path = tmp_path / "ai-plane.db"
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    os.environ["FG_AI_PLANE_ENABLED"] = "1" if ai_enabled else "0"
    os.environ["FG_AI_EXTERNAL_PROVIDER_ENABLED"] = "0"
    os.environ["FG_AI_ALLOWED_PROVIDERS"] = "simulated"
    os.environ["FG_AI_DEFAULT_PROVIDER"] = "simulated"
    os.environ["FG_AI_ENABLE_SIMULATED"] = "1"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    key_a = mint_key(
        "admin:write", "compliance:read", "governance:write", tenant_id="tenant-a"
    )
    key_b = mint_key(
        "admin:write", "compliance:read", "governance:write", tenant_id="tenant-b"
    )
    client = TestClient(build_app(auth_enabled=True))
    return client, key_a, key_b


def test_ai_infer_authz_401(tmp_path: Path) -> None:
    client, _, _ = _setup_client(tmp_path, ai_enabled=True)
    resp = client.post("/ai/infer", json={"query": "hello"})
    assert resp.status_code == 401


def test_ai_infer_tenant_mismatch_403(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    resp = client.post(
        "/ai/infer?tenant_id=tenant-z",
        json={"query": "hello"},
        headers={"X-API-Key": key_a},
    )
    assert resp.status_code == 403


def test_ai_input_policy_blocked_secret(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    resp = client.post(
        "/ai/infer",
        json={"query": "api_key=supersecretvalue"},
        headers={"X-API-Key": key_a},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "AI_INPUT_POLICY_BLOCKED"


def test_ai_output_deterministic_same_input_same_output(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    r1 = client.post(
        "/ai/infer", json={"query": "deterministic"}, headers={"X-API-Key": key_a}
    )
    r2 = client.post(
        "/ai/infer", json={"query": "deterministic"}, headers={"X-API-Key": key_a}
    )
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["response"] == r2.json()["response"]
    assert r1.json()["simulated"] is True


def test_ai_plane_no_phi_uses_guarded_dev_simulated_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-guarded-dev.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)
    monkeypatch.delenv("FG_AI_ALLOWED_PROVIDERS", raising=False)
    monkeypatch.delenv("FG_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("FG_AZURE_AI_KEY", raising=False)
    monkeypatch.delenv("FG_AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("FG_AZURE_OPENAI_DEPLOYMENT", raising=False)
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    result = AIPlaneService().infer(
        get_sessionmaker()(), "tenant-a", AIInferRequest(query="deterministic")
    )

    assert result["ok"] is True
    assert result["provider"] == "simulated"
    assert result["simulated"] is True


def test_ai_plane_no_phi_prod_without_default_fails_guarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-guarded-prod.db"
    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)
    monkeypatch.delenv("FG_AI_ALLOWED_PROVIDERS", raising=False)
    monkeypatch.delenv("FG_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("FG_AZURE_AI_KEY", raising=False)
    monkeypatch.delenv("FG_AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("FG_AZURE_OPENAI_DEPLOYMENT", raising=False)
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    with pytest.raises(ValueError, match="AI_PROVIDER_NOT_CONFIGURED"):
        AIPlaneService().infer(
            get_sessionmaker()(), "tenant-a", AIInferRequest(query="deterministic")
        )


def test_ai_plane_uses_real_rag_context_in_outgoing_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-rag.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    rag_chunks = _chunks(
        "tenant-a", "source-a", "authentication control evidence for alpha"
    ) + _chunks("tenant-b", "source-b", "authentication control evidence for beta")
    captured_prompt = ""
    events = []

    def _provider(**kw) -> ProviderResponse:
        nonlocal captured_prompt
        captured_prompt = str(kw["prompt"])
        return ProviderResponse(
            provider_id="simulated", text="safe response", model="m"
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    result = AIPlaneService(rag_chunks=rag_chunks).infer(
        get_sessionmaker()(),
        "tenant-a",
        AIInferRequest(query="authentication control"),
    )

    assert result["ok"] is True
    assert "Retrieved context:" in captured_prompt
    assert "authentication control evidence for alpha" in captured_prompt
    assert "authentication control evidence for beta" not in captured_prompt
    prompt_sha = hashlib.sha256(captured_prompt.encode("utf-8")).hexdigest()
    with get_sessionmaker()() as db:
        row = (
            db.execute(
                text(
                    "SELECT prompt_sha256, context_refs_json, retrieval_id "
                    "FROM ai_inference_records WHERE tenant_id='tenant-a' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
            .mappings()
            .first()
        )
    assert row is not None
    assert row["prompt_sha256"] == prompt_sha
    assert row["context_refs_json"] == '["source-a"]'
    assert str(row["retrieval_id"]).startswith("rag:")
    assert row["retrieval_id"] != "stub"
    audit_details = [
        event.details for event in events if event.reason == "ai_plane_infer"
    ][-1]
    assert audit_details["rag_used"] is True
    assert audit_details["rag_chunk_count"] == 1
    assert audit_details["rag_source_ids"] == ["source-a"]
    assert "authentication control evidence" not in str(audit_details)


def test_inference_record_hash_only_no_raw_prompt(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    prompt = "top-secret-prompt"
    resp = client.post(
        "/ai/infer", json={"query": prompt}, headers={"X-API-Key": key_a}
    )
    assert resp.status_code == 200

    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        row = (
            db.execute(
                text(
                    "SELECT prompt_sha256, output_sha256, response_text "
                    "FROM ai_inference_records WHERE tenant_id='tenant-a' AND model_id='SIMULATED_V1' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
            .mappings()
            .first()
        )
    assert row is not None
    assert row["prompt_sha256"] != prompt
    assert prompt not in row["prompt_sha256"]


def test_ai_route_not_mounted_when_feature_disabled(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=False)
    resp = client.post(
        "/ai/infer", json={"query": "hello"}, headers={"X-API-Key": key_a}
    )
    assert resp.status_code == 404


def test_external_provider_flag_fails_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "startup.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_AI_PLANE_ENABLED", "1")
    monkeypatch.setenv("FG_AI_EXTERNAL_PROVIDER_ENABLED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    app = build_app(auth_enabled=True)
    with pytest.raises(RuntimeError, match="AI_EXTERNAL_PROVIDER_NOT_ALLOWED"):
        with TestClient(app):
            pass


def test_ai_artifact_generation_schema_validation(tmp_path: Path) -> None:
    schema_path = Path("contracts/artifacts/ai_plane_evidence.schema.json")
    out_path = tmp_path / "ai_plane_evidence.json"
    payload = write_ai_plane_evidence(
        out_path=str(out_path),
        schema_path=str(schema_path),
        git_sha="abc123",
        feature_flag_snapshot={
            "FG_AI_PLANE_ENABLED": True,
            "FG_AI_EXTERNAL_PROVIDER_ENABLED": False,
        },
        total_inference_calls=2,
        total_blocked_calls=1,
        total_policy_violations=1,
        route_snapshot=["/ai/infer"],
    )
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["simulated_mode"] is True
    assert written["simulated_mode"] is True
