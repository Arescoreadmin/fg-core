from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.main import build_app
from services.ai_plane_extension import rag_stub
from services.ai_plane_extension.service import write_ai_plane_evidence


def _setup_client(tmp_path: Path, *, ai_enabled: bool = True) -> tuple[TestClient, str, str]:
    db_path = tmp_path / "ai-plane.db"
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    os.environ["FG_AI_PLANE_ENABLED"] = "1" if ai_enabled else "0"
    os.environ["FG_AI_EXTERNAL_PROVIDER_ENABLED"] = "0"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    key_a = mint_key("admin:write", "compliance:read", "governance:write", tenant_id="tenant-a")
    key_b = mint_key("admin:write", "compliance:read", "governance:write", tenant_id="tenant-b")
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
    r1 = client.post("/ai/infer", json={"query": "deterministic"}, headers={"X-API-Key": key_a})
    r2 = client.post("/ai/infer", json={"query": "deterministic"}, headers={"X-API-Key": key_a})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["response"] == r2.json()["response"]
    assert r1.json()["simulated"] is True


def test_rag_stub_never_touches_db(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args, **_kwargs):
        raise RuntimeError("db_touch_forbidden")

    import sqlite3

    monkeypatch.setattr(sqlite3, "connect", _boom)
    result = rag_stub.retrieve(tenant_id="tenant-a", query="hello")
    assert result["retrieval_id"] == "stub"
    assert result["ok"] is True


def test_inference_record_hash_only_no_raw_prompt(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    prompt = "top-secret-prompt"
    resp = client.post("/ai/infer", json={"query": prompt}, headers={"X-API-Key": key_a})
    assert resp.status_code == 200

    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        row = db.execute(
            text(
                "SELECT prompt_sha256, output_sha256, response_text "
                "FROM ai_inference_records WHERE tenant_id='tenant-a' AND model_id='SIMULATED_V1' "
                "ORDER BY id DESC LIMIT 1"
            )
        ).mappings().first()
    assert row is not None
    assert row["prompt_sha256"] != prompt
    assert prompt not in row["prompt_sha256"]


def test_ai_route_not_mounted_when_feature_disabled(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=False)
    resp = client.post("/ai/infer", json={"query": "hello"}, headers={"X-API-Key": key_a})
    assert resp.status_code == 404


def test_external_provider_flag_fails_startup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
        feature_flag_snapshot={"FG_AI_PLANE_ENABLED": True, "FG_AI_EXTERNAL_PROVIDER_ENABLED": False},
        total_inference_calls=2,
        total_blocked_calls=1,
        total_policy_violations=1,
        route_snapshot=["/ai/infer"],
    )
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["simulated_mode"] is True
    assert written["simulated_mode"] is True
