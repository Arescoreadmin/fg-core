from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, cast

import pytest

from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.rag_corpus_store import create_corpus, create_document, store_chunks
from services.ai.providers.base import ProviderResponse
from services.ai.rag_context import RagContextError
from services.ai_plane_extension.models import AIInferRequest
from services.ai_plane_extension.service import AIPlaneService


def _configure_ai_plane_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "ai-plane-rag-security.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))


def _seed_persisted_chunk(
    db: Any,
    *,
    tenant_id: str,
    text: str,
    ordinal: int = 0,
) -> str:
    corpus = create_corpus(db, tenant_id=tenant_id, name=f"{tenant_id} corpus")
    document = create_document(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title="Security RAG Document",
        source="https://example.test/security-rag",
    )
    chunks = store_chunks(
        db,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[{"text": text, "ordinal": ordinal}],
    )
    return str(chunks[0]["chunk_id"])


def test_ai_plane_rag_audit_logs_safe_metadata_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_ai_plane_db(tmp_path, monkeypatch)
    captured_prompt = ""
    audit_events: list[Any] = []

    with get_sessionmaker()() as db:
        chunk_text = "alpha control evidence for audit security"
        chunk_id = _seed_persisted_chunk(
            db,
            tenant_id="tenant-a",
            text=chunk_text,
        )

        def _provider(**kwargs: Any) -> ProviderResponse:
            nonlocal captured_prompt
            captured_prompt = str(kwargs["prompt"])
            return ProviderResponse(
                provider_id="simulated",
                text=chunk_text,
                model="SIMULATED_V1",
            )

        monkeypatch.setattr(
            "services.ai_plane_extension.service._call_provider", _provider
        )
        monkeypatch.setattr(
            "api.security_audit.SecurityAuditor.log_event",
            lambda _self, event: audit_events.append(event),
        )

        result = AIPlaneService().infer(
            db,
            "tenant-a",
            AIInferRequest(query="alpha control"),
        )

    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata == {
        "used_rag": True,
        "context_count": 1,
        "source_chunk_ids": [chunk_id],
    }
    assert captured_prompt.startswith("Retrieved context:\n")
    assert f"[chunk_id={chunk_id}]" in captured_prompt
    assert chunk_text in captured_prompt

    audit_details = [
        event.details for event in audit_events if event.reason == "ai_plane_infer"
    ][-1]
    assert audit_details["rag_used"] is True
    assert audit_details["rag_chunk_count"] == 1
    assert audit_details["rag_source_chunk_ids"] == [chunk_id]
    assert chunk_text not in str(audit_details)
    assert captured_prompt not in str(audit_details)


def test_ai_plane_rag_wrong_tenant_context_not_included(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_ai_plane_db(tmp_path, monkeypatch)
    captured_prompt = ""

    with get_sessionmaker()() as db:
        _seed_persisted_chunk(
            db,
            tenant_id="tenant-a",
            text="shared control alpha evidence",
        )
        _seed_persisted_chunk(
            db,
            tenant_id="tenant-b",
            text="shared control beta secret",
        )

        def _provider(**kwargs: Any) -> ProviderResponse:
            nonlocal captured_prompt
            captured_prompt = str(kwargs["prompt"])
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


def test_ai_plane_rag_retrieval_error_fails_closed_without_stub_or_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import services.ai_plane_extension.service as service_mod

    _configure_ai_plane_db(tmp_path, monkeypatch)
    provider_called = False

    def _fail(**_kwargs: Any) -> None:
        raise RagContextError("RAG_RETRIEVAL_FAILED", "safe failure")

    def _provider(**_kwargs: Any) -> ProviderResponse:
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
    assert "rag_stub" not in inspect.getsource(AIPlaneService.infer)
