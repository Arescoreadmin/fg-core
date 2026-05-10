from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.rag.chunking import ChunkingConfig, CorpusChunk, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.main import build_app
from api.rag_corpus_store import create_corpus, create_document, store_chunks
from services.ai.providers.base import ProviderResponse
from services.ai_plane_extension.service import write_ai_plane_evidence

_CHUNK_CONFIG = ChunkingConfig(max_chars=180, overlap_chars=0)


def _chunks(tenant_id: str, source_id: str, content: str) -> list[CorpusChunk]:
    result = ingest_corpus(
        IngestRequest(documents=[CorpusDocument(source_id=source_id, content=content)]),
        trusted_tenant_id=tenant_id,
    )
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


def _seed_persisted_chunks(
    db,
    *,
    tenant_id: str,
    title: str = "Test RAG Document",
    source: str = "https://example.test/rag",
    chunks: list[dict[str, object]],
) -> list[dict[str, object]]:
    corpus = create_corpus(db, tenant_id=tenant_id, name=f"{tenant_id} corpus")
    document = create_document(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title=title,
        source=source,
    )
    return store_chunks(
        db,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=chunks,
    )


def _policy_file(
    tmp_path: Path,
    *,
    allowed_providers: list[str],
    default_provider: str,
    phi_provider: str,
) -> str:
    path = tmp_path / "ai-policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "allowed_providers": allowed_providers,
                "default_provider": default_provider,
                "phi_provider": phi_provider,
                "phi_rules": {
                    "require_baa": True,
                    "require_prompt_minimization": True,
                    "deny_if_phi_provider_unavailable": True,
                    "deny_explicit_non_phi_provider_for_phi": True,
                },
                "rag_rules": {
                    "enabled": True,
                    "require_grounded_response": True,
                    "no_answer_on_ungrounded": True,
                },
                "audit_rules": {
                    "require_request_hash": True,
                    "require_response_hash": True,
                    "include_routing_metadata": True,
                },
            }
        ),
        encoding="utf-8",
    )
    return str(path)


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


def test_ai_chat_authz_401(tmp_path: Path) -> None:
    client, _, _ = _setup_client(tmp_path, ai_enabled=True)
    resp = client.post("/ai/chat", json={"message": "hello"})
    assert resp.status_code == 401
    assert "detail" in resp.json()
    assert "error_code" not in resp.json()


def test_ai_chat_openapi_auth_errors_match_detail_envelope(tmp_path: Path) -> None:
    _setup_client(tmp_path, ai_enabled=True)
    schema = json.loads(Path("contracts/core/openapi.json").read_text(encoding="utf-8"))
    responses = schema["paths"]["/ai/chat"]["post"]["responses"]
    for status_code in ("401", "403"):
        body_schema = responses[status_code]["content"]["application/json"]["schema"]
        assert body_schema == {
            "properties": {"detail": {"type": "string"}},
            "required": ["detail"],
            "type": "object",
        }


def test_ai_chat_empty_message_rejected(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    resp = client.post("/ai/chat", json={"message": ""}, headers={"X-API-Key": key_a})
    assert resp.status_code == 422


def test_ai_chat_grounded_response_returns_safe_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ai_plane_extension as ai_api
    from services.ai_plane_extension.service import AIPlaneService

    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    rag_chunks = _chunks(
        "tenant-a", "source-a", "authentication control evidence for alpha"
    )
    monkeypatch.setattr(ai_api, "service", AIPlaneService(rag_chunks=rag_chunks))

    def _provider(**kw) -> ProviderResponse:
        assert "Retrieved context:" in str(kw["prompt"])
        return ProviderResponse(
            provider_id="simulated",
            text="authentication control evidence alpha",
            model="SIMULATED_V1",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    resp = client.post(
        "/ai/chat",
        json={"message": "authentication control"},
        headers={"X-API-Key": key_a},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "answer": "authentication control evidence alpha",
        "sources": [{"source_id": "source-a"}],
        "confidence": 1.0,
    }
    assert "authentication control evidence for alpha" not in str(body["sources"])


def test_ai_chat_ungrounded_response_returns_no_answer_and_hashes_final_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ai_plane_extension as ai_api
    from services.ai_plane_extension.service import AIPlaneService

    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    rag_chunks = _chunks(
        "tenant-a", "source-a", "authentication control evidence for alpha"
    )
    events = []
    provider_calls = 0
    monkeypatch.setattr(ai_api, "service", AIPlaneService(rag_chunks=rag_chunks))

    def _provider(**_kw) -> ProviderResponse:
        nonlocal provider_calls
        provider_calls += 1
        return ProviderResponse(
            provider_id="simulated",
            text="unsupported deployment procedure",
            model="SIMULATED_V1",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    resp = client.post(
        "/ai/chat",
        json={"message": "authentication control"},
        headers={"X-API-Key": key_a},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"] == "NO_ANSWER"
    assert body["sources"] == []
    assert body["confidence"] == 0.0
    assert provider_calls == 1
    assert "unsupported deployment procedure" not in str(body)
    no_answer_sha = hashlib.sha256(b"NO_ANSWER").hexdigest()
    audit_details = [
        event.details for event in events if event.reason == "ai_plane_infer"
    ][-1]
    assert audit_details["response_grounded"] is False
    assert audit_details["response_validation_result"] == "RESPONSE_UNGROUNDED"
    assert audit_details["response_hash"] == f"sha256:{no_answer_sha}"
    assert "unsupported deployment procedure" not in str(audit_details)
    assert "authentication control evidence for alpha" not in str(audit_details)


def test_ai_chat_phi_without_baa_denies_before_provider_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ai_plane_extension as ai_api
    from services.ai_plane_extension.service import AIPlaneService

    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    monkeypatch.setenv("FG_AZURE_AI_KEY", "test-key")
    monkeypatch.setenv("FG_AZURE_OPENAI_ENDPOINT", "https://azure.example.test")
    monkeypatch.setenv("FG_AZURE_OPENAI_DEPLOYMENT", "test-deployment")
    monkeypatch.setenv(
        "FG_AI_POLICY_PATH",
        _policy_file(
            tmp_path,
            allowed_providers=["azure_openai"],
            default_provider="azure_openai",
            phi_provider="azure_openai",
        ),
    )
    monkeypatch.setattr(ai_api, "service", AIPlaneService())
    provider_called = False

    def _provider(**_kw) -> ProviderResponse:
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(
            provider_id="azure_openai",
            text="should not be called",
            model="m",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    resp = client.post(
        "/ai/chat",
        json={"message": "Patient John Smith has diabetes."},
        headers={"X-API-Key": key_a},
    )

    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "AI_PHI_PROVIDER_NOT_BAA_CAPABLE"
    assert provider_called is False
    assert "John Smith" not in str(resp.json())


def test_ai_chat_policy_denies_disallowed_requested_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ai_plane_extension as ai_api
    from services.ai_plane_extension.service import AIPlaneService

    client, key_a, _ = _setup_client(tmp_path, ai_enabled=True)
    monkeypatch.setattr(ai_api, "service", AIPlaneService())
    provider_called = False

    def _provider(**_kw) -> ProviderResponse:
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(
            provider_id="anthropic",
            text="should not be called",
            model="m",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    resp = client.post(
        "/ai/chat",
        json={"message": "hello", "provider": "anthropic"},
        headers={"X-API-Key": key_a},
    )

    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "AI_PROVIDER_NOT_ALLOWED"
    assert provider_called is False


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
            provider_id="simulated",
            text="authentication control evidence alpha",
            model="m",
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
    assert result["response"] == "authentication control evidence alpha"
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
    assert audit_details["response_grounded"] is True
    assert audit_details["response_validation_result"] == "RESPONSE_GROUNDED"
    assert audit_details["response_citation_source_ids"] == ["source-a"]
    assert audit_details["response_evidence_count"] == 1


def test_ai_plane_calls_retrieval_before_provider_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import services.ai_plane_extension.service as service_mod
    from services.ai.rag_context import RagContextChunk, RagContextResult
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-retrieval-order.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    order: list[str] = []

    def _retrieval(**kw) -> RagContextResult:
        order.append("retrieval")
        assert kw["tenant_id"] == "tenant-a"
        return RagContextResult(
            chunks=(
                RagContextChunk(
                    source_id="ck-order",
                    chunk_id="ck-order",
                    chunk_index=0,
                    text="alpha control evidence",
                    phi_sensitivity_level=None,
                    phi_types=(),
                ),
            ),
            context_text="[chunk_id=ck-order]\nalpha control evidence",
            chunk_count=1,
            source_ids=("ck-order",),
            retrieval_reason_code="RAG_RETRIEVAL_SELECTED",
            query_phi_sensitivity="none",
            max_sensitivity_level=None,
            contains_phi=False,
            source_chunk_ids=("ck-order",),
        )

    def _provider(**kw) -> ProviderResponse:
        order.append("provider")
        assert order == ["retrieval", "provider"]
        assert "[chunk_id=ck-order]" in str(kw["prompt"])
        return ProviderResponse(
            provider_id="simulated",
            text="alpha control evidence",
            model="SIMULATED_V1",
        )

    monkeypatch.setattr(service_mod, "retrieve_persisted_rag_context", _retrieval)
    monkeypatch.setattr(service_mod, "_call_provider", _provider)

    result = AIPlaneService().infer(
        get_sessionmaker()(), "tenant-a", AIInferRequest(query="alpha control")
    )

    assert order == ["retrieval", "provider"]
    assert result["metadata"] == {
        "used_rag": True,
        "context_count": 1,
        "source_chunk_ids": ["ck-order"],
    }


def test_ai_plane_includes_persisted_retrieved_context_in_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-persisted-rag.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    captured_prompt = ""
    events = []
    with get_sessionmaker()() as db:
        chunks = _seed_persisted_chunks(
            db,
            tenant_id="tenant-a",
            chunks=[{"text": "alpha control evidence", "ordinal": 0}],
        )
        chunk_id = str(chunks[0]["chunk_id"])

        def _provider(**kw) -> ProviderResponse:
            nonlocal captured_prompt
            captured_prompt = str(kw["prompt"])
            return ProviderResponse(
                provider_id="simulated",
                text="alpha control evidence",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )
        monkeypatch.setattr(
            "api.security_audit.SecurityAuditor.log_event",
            lambda _self, event: events.append(event),
        )

        result = AIPlaneService().infer(
            db,
            "tenant-a",
            AIInferRequest(query="alpha control"),
        )

    assert result["ok"] is True
    assert result["response"] == "alpha control evidence"
    assert captured_prompt.startswith("Retrieved context:\n")
    assert f"[chunk_id={chunk_id}]" in captured_prompt
    assert "alpha control evidence" in captured_prompt
    assert captured_prompt.endswith("User query:\nalpha control")
    assert result["metadata"] == {
        "used_rag": True,
        "context_count": 1,
        "source_chunk_ids": [chunk_id],
    }
    assert result["sources"] == [{"source_id": chunk_id}]
    audit_details = [
        event.details for event in events if event.reason == "ai_plane_infer"
    ][-1]
    assert audit_details["rag_used"] is True
    assert audit_details["rag_chunk_count"] == 1
    assert audit_details["rag_source_chunk_ids"] == [chunk_id]
    assert str(audit_details["rag_retrieval_trace_id"]).startswith("rt-")
    assert audit_details["rag_retrieval_strategy"] == "lexical"
    assert audit_details["rag_candidate_count"] == 1
    assert audit_details["rag_returned_count"] == 1
    assert 0.0 <= audit_details["rag_confidence"] <= 1.0
    assert audit_details["rag_confidence_reason"]
    assert "alpha control evidence" not in str(audit_details)
    assert captured_prompt not in str(audit_details)


def test_ai_infer_exposes_safe_provenance_ui_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-provenance-ui.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    captured_prompt = ""
    sensitive_chunk_text = "alpha control evidence MRN12345 secretphrase"
    with get_sessionmaker()() as db:
        chunks = _seed_persisted_chunks(
            db,
            tenant_id="tenant-a",
            chunks=[{"text": sensitive_chunk_text, "ordinal": 0}],
        )
        chunk_id = str(chunks[0]["chunk_id"])

        def _provider(**kw) -> ProviderResponse:
            nonlocal captured_prompt
            captured_prompt = str(kw["prompt"])
            return ProviderResponse(
                provider_id="simulated",
                text=f"alpha control evidence [chunk_id={chunk_id}]",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )
        result = AIPlaneService().infer(
            db,
            "tenant-a",
            AIInferRequest(query="alpha control MRN12345 secretphrase"),
        )

    provenance = cast(dict[str, Any], result["provenance"])
    assert str(provenance["retrieval_trace_id"]).startswith("rt-")
    assert provenance["used_rag"] is True
    assert provenance["context_count"] == 1
    assert provenance["source_chunk_ids"] == [chunk_id]
    assert provenance["retrieval_strategy"] == "lexical"
    assert provenance["provenance_status"] == "PROVENANCE_VALID"
    assert 0.0 <= float(provenance["confidence"]) <= 1.0

    summaries = cast(list[dict[str, Any]], provenance["source_summaries"])
    assert summaries == [
        {
            "source_id": chunk_id,
            "chunk_id": chunk_id,
            "chunk_index": 0,
            "included_in_prompt": True,
            "phi_sensitivity_level": None,
            "phi_types": [],
        }
    ]
    why_by_chunk = cast(dict[str, Any], provenance["why_this_chunk"])
    why = cast(dict[str, Any], why_by_chunk[chunk_id])
    assert why["matched_term_count"] == 4
    assert why["matched_term_categories"] == ["letters", "letters_digits"]
    assert "score_components" in why

    serialized = json.dumps(provenance, sort_keys=True)
    assert sensitive_chunk_text not in serialized
    assert captured_prompt not in serialized
    assert "MRN12345" not in serialized
    assert "secretphrase" not in serialized
    assert "embedding" not in serialized.lower()
    assert "vector" not in serialized.lower()


def test_ai_infer_provenance_ui_payload_is_tenant_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, key_b = _setup_client(tmp_path, ai_enabled=True)
    with get_sessionmaker()() as db:
        _seed_persisted_chunks(
            db,
            tenant_id="tenant-a",
            chunks=[{"text": "tenant alpha control evidence", "ordinal": 0}],
        )

    resp = client.post(
        "/ai/infer",
        json={"query": "tenant alpha control"},
        headers={"X-API-Key": key_b},
    )

    assert resp.status_code == 200
    body = resp.json()
    provenance = body["provenance"]
    assert provenance["used_rag"] is False
    assert provenance["context_count"] == 0
    assert provenance["source_chunk_ids"] == []
    assert provenance["source_summaries"] == []
    assert provenance["why_this_chunk"] == {}
    assert provenance["provenance_status"] == "PROVENANCE_NO_CONTEXT_AVAILABLE"
    assert "tenant alpha control evidence" not in json.dumps(body, sort_keys=True)


def test_ai_infer_openapi_contract_remains_generic_for_additive_payload(
    tmp_path: Path,
) -> None:
    _setup_client(tmp_path, ai_enabled=True)
    schema = json.loads(Path("contracts/core/openapi.json").read_text(encoding="utf-8"))
    response_schema = schema["paths"]["/ai/infer"]["post"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]
    assert response_schema == {
        "title": "Response Ai Infer Ai Infer Post",
        "type": "object",
    }


def test_ai_plane_response_metadata_empty_when_no_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-no-context-metadata.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    provider_called = False

    def _provider(**_kw) -> ProviderResponse:
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="simulated", text="unused", model="m")

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    result = AIPlaneService().infer(
        get_sessionmaker()(),
        "tenant-a",
        AIInferRequest(query="missing context"),
    )

    assert provider_called is False
    assert result["response"] == "NO_ANSWER"
    assert result["metadata"] == {
        "used_rag": False,
        "context_count": 0,
        "source_chunk_ids": [],
    }


def test_ai_plane_retrieval_is_tenant_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-persisted-tenant.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    captured_prompt = ""
    with get_sessionmaker()() as db:
        _seed_persisted_chunks(
            db,
            tenant_id="tenant-a",
            chunks=[{"text": "shared control alpha evidence", "ordinal": 0}],
        )
        _seed_persisted_chunks(
            db,
            tenant_id="tenant-b",
            chunks=[{"text": "shared control beta secret", "ordinal": 0}],
        )

        def _provider(**kw) -> ProviderResponse:
            nonlocal captured_prompt
            captured_prompt = str(kw["prompt"])
            return ProviderResponse(
                provider_id="simulated",
                text="shared control alpha evidence",
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )
        result = AIPlaneService().infer(
            db,
            "tenant-a",
            AIInferRequest(query="shared control"),
        )

    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["used_rag"] is True
    assert "alpha evidence" in captured_prompt
    assert "beta secret" not in captured_prompt


def test_ai_plane_retrieval_error_does_not_call_legacy_placeholder_retrieval_or_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import inspect
    import services.ai_plane_extension.service as service_mod
    from services.ai.rag_context import RagContextError
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-retrieval-error.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    provider_called = False

    def _fail(**_kw) -> None:
        raise RagContextError("RAG_RETRIEVAL_FAILED", "safe failure")

    def _provider(**_kw) -> ProviderResponse:
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="simulated", text="unused", model="m")

    monkeypatch.setattr(service_mod, "retrieve_persisted_rag_context", _fail)
    monkeypatch.setattr(service_mod, "_call_provider", _provider)

    with pytest.raises(ValueError, match="RAG_RETRIEVAL_FAILED"):
        AIPlaneService().infer(
            get_sessionmaker()(),
            "tenant-a",
            AIInferRequest(query="alpha control"),
        )

    assert provider_called is False
    assert "legacy_placeholder_retrieval" not in inspect.getsource(AIPlaneService.infer)


def test_ai_plane_baa_policy_preserved_with_persisted_rag_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-rag-baa.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "azure_openai")
    monkeypatch.setenv("FG_AZURE_AI_KEY", "test-azure-key")
    monkeypatch.setenv("FG_AZURE_OPENAI_ENDPOINT", "https://azure.example.test")
    monkeypatch.setenv("FG_AZURE_OPENAI_DEPLOYMENT", "fg-test")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    provider_called = False
    with get_sessionmaker()() as db:
        _seed_persisted_chunks(
            db,
            tenant_id="tenant-a",
            chunks=[
                {
                    "text": "patient John Smith has diabetes clinical evidence",
                    "ordinal": 0,
                }
            ],
        )

        def _provider(**_kw) -> ProviderResponse:
            nonlocal provider_called
            provider_called = True
            return ProviderResponse(
                provider_id="azure_openai", text="unused", model="m"
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )

        with pytest.raises(ValueError, match="AI_PHI_PROVIDER_NOT_BAA_CAPABLE"):
            AIPlaneService().infer(
                db,
                "tenant-a",
                AIInferRequest(query="clinical evidence"),
            )

    assert provider_called is False


def test_ai_plane_does_not_call_embeddings_or_vector_db() -> None:
    import inspect
    import services.ai_plane_extension.service as service_mod

    source = inspect.getsource(service_mod.AIPlaneService.infer).lower()
    forbidden = ("embedding", "pgvector", "vector db", "vector_db")
    for token in forbidden:
        assert token not in source


def test_ai_plane_uses_json_policy_provider_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-json-policy.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    monkeypatch.setenv(
        "FG_AI_POLICY_PATH",
        _policy_file(
            tmp_path,
            allowed_providers=["simulated"],
            default_provider="simulated",
            phi_provider="simulated",
        ),
    )
    monkeypatch.delenv("FG_AI_ALLOWED_PROVIDERS", raising=False)
    monkeypatch.delenv("FG_AI_DEFAULT_PROVIDER", raising=False)
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    rag_chunks = _chunks(
        "tenant-a", "source-a", "authentication control evidence for alpha"
    )

    monkeypatch.setattr(
        "services.ai_plane_extension.service._call_provider",
        lambda **_kw: ProviderResponse(
            provider_id="simulated",
            text="authentication control evidence alpha",
            model="SIMULATED_V1",
        ),
    )

    result = AIPlaneService(rag_chunks=rag_chunks).infer(
        get_sessionmaker()(),
        "tenant-a",
        AIInferRequest(query="authentication control"),
    )

    assert result["ok"] is True
    assert result["provider"] == "simulated"
    assert result["simulated"] is True


def test_ai_plane_ungrounded_rag_response_returns_no_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-rag-ungrounded.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    rag_chunks = _chunks(
        "tenant-a", "source-a", "authentication control evidence for alpha"
    )
    provider_calls = 0
    events = []

    def _provider(**kw) -> ProviderResponse:
        nonlocal provider_calls
        provider_calls += 1
        assert "Retrieved context:" in str(kw["prompt"])
        return ProviderResponse(
            provider_id="simulated",
            text="unsupported deployment procedure",
            model="m",
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
    assert result["response"] == "NO_ANSWER"
    assert provider_calls == 1
    no_answer_sha = hashlib.sha256(b"NO_ANSWER").hexdigest()
    with get_sessionmaker()() as db:
        row = (
            db.execute(
                text(
                    "SELECT output_sha256, response_text "
                    "FROM ai_inference_records WHERE tenant_id='tenant-a' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
            .mappings()
            .first()
        )
    assert row is not None
    assert row["response_text"] == "NO_ANSWER"
    assert row["output_sha256"] == no_answer_sha
    audit_details = [
        event.details for event in events if event.reason == "ai_plane_infer"
    ][-1]
    assert audit_details["response_grounded"] is False
    assert audit_details["response_validation_result"] == "RESPONSE_UNGROUNDED"
    assert audit_details["response_hash"] == f"sha256:{no_answer_sha}"
    assert audit_details["response_citation_source_ids"] == []
    assert audit_details["response_evidence_count"] == 0
    assert "unsupported deployment procedure" not in str(audit_details)
    assert "authentication control evidence" not in str(audit_details)


def test_ai_plane_no_rag_context_returns_no_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "ai-plane-no-rag-answer.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    provider_called = False

    def _provider(**_kw) -> ProviderResponse:
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(
            provider_id="simulated",
            text="general unsupported answer",
            model="m",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    result = AIPlaneService().infer(
        get_sessionmaker()(),
        "tenant-a",
        AIInferRequest(query="general question"),
    )

    assert result["ok"] is True
    assert result["response"] == "NO_ANSWER"
    assert result["model"] == "simulated"
    assert provider_called is False


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
                    "FROM ai_inference_records WHERE tenant_id='tenant-a' AND model_id='simulated' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
            .mappings()
            .first()
        )
    assert row is not None
    assert row["response_text"] == "NO_ANSWER"
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
