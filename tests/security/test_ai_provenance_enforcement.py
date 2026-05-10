from __future__ import annotations

from typing import Any, cast

import pytest

from api.rag.chunking import CorpusChunk
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.rag_corpus_store import create_corpus, create_document, store_chunks
from services.ai.provenance import (
    PROVENANCE_NO_CONTEXT_AVAILABLE,
    PROVENANCE_SOURCE_NOT_IN_PROMPT,
    PROVENANCE_SOURCE_NOT_RETRIEVED,
    PROVENANCE_VALID,
    validate_answer_provenance,
)
from services.ai.providers.base import ProviderResponse
from services.ai.rag_context import (
    RagContextChunk,
    RagContextResult,
    retrieve_rag_context,
)
from services.ai.response_validation import (
    NO_ANSWER_TEXT,
    RESPONSE_GROUNDED,
    RESPONSE_NO_RAG_CONTEXT,
    RESPONSE_VALIDATOR_VERSION,
    ResponseValidationResult,
)
from services.ai_plane_extension.models import AIInferRequest
from services.ai_plane_extension.service import AIPlaneService


def _validation(*source_ids: str) -> ResponseValidationResult:
    return ResponseValidationResult(
        grounded=bool(source_ids),
        final_text="alpha control evidence" if source_ids else NO_ANSWER_TEXT,
        reason_code=RESPONSE_GROUNDED if source_ids else RESPONSE_NO_RAG_CONTEXT,
        citation_source_ids=tuple(source_ids),
        validator_version=RESPONSE_VALIDATOR_VERSION,
        evidence_count=len(source_ids),
    )


def _context(
    *,
    source_chunk_ids: tuple[str, ...] = ("ck-a",),
    retrieved_source_chunk_ids: tuple[str, ...] = ("ck-a",),
) -> RagContextResult:
    chunks = tuple(
        RagContextChunk(
            source_id=chunk_id,
            chunk_id=chunk_id,
            chunk_index=index,
            text="alpha control evidence",
            phi_sensitivity_level=None,
            phi_types=(),
        )
        for index, chunk_id in enumerate(retrieved_source_chunk_ids)
    )
    return RagContextResult(
        chunks=chunks,
        context_text="\n\n".join(
            f"[chunk_id={chunk_id}]\nalpha control evidence"
            for chunk_id in source_chunk_ids
        ),
        chunk_count=len(chunks),
        source_ids=retrieved_source_chunk_ids,
        retrieval_reason_code="RAG_RETRIEVAL_SELECTED"
        if chunks
        else "RAG_RETRIEVAL_EMPTY",
        query_phi_sensitivity="none",
        max_sensitivity_level=None,
        contains_phi=False,
        source_chunk_ids=source_chunk_ids,
        retrieved_source_chunk_ids=retrieved_source_chunk_ids,
    )


def test_valid_citations_pass() -> None:
    validation, provenance = validate_answer_provenance(
        response_text="alpha control evidence [chunk_id=ck-a]",
        rag_context=_context(),
        response_validation=_validation("ck-a"),
    )

    assert validation.final_text == "alpha control evidence"
    assert provenance.valid is True
    assert provenance.reason_code == PROVENANCE_VALID
    assert provenance.citation_source_ids == ("ck-a",)


def test_nonexistent_chunk_citation_rejected() -> None:
    validation, provenance = validate_answer_provenance(
        response_text="alpha control evidence [chunk_id=ck-fake]",
        rag_context=_context(),
        response_validation=_validation("ck-a"),
    )

    assert validation.final_text == NO_ANSWER_TEXT
    assert validation.citation_source_ids == ()
    assert validation.provenance_reason_code == PROVENANCE_SOURCE_NOT_RETRIEVED
    assert provenance.valid is False
    assert provenance.invalid_source_ids == ("ck-fake",)


def test_retrieved_but_not_included_citation_rejected() -> None:
    validation, provenance = validate_answer_provenance(
        response_text="alpha control evidence [chunk_id=ck-b]",
        rag_context=_context(
            source_chunk_ids=("ck-a",),
            retrieved_source_chunk_ids=("ck-a", "ck-b"),
        ),
        response_validation=_validation("ck-b"),
    )

    assert validation.final_text == NO_ANSWER_TEXT
    assert validation.provenance_reason_code == PROVENANCE_SOURCE_NOT_IN_PROMPT
    assert provenance.invalid_source_ids == ("ck-b",)


def test_no_context_source_claim_rejected() -> None:
    validation, provenance = validate_answer_provenance(
        response_text="unsupported answer [chunk_id=ck-fake]",
        rag_context=_context(source_chunk_ids=(), retrieved_source_chunk_ids=()),
        response_validation=_validation(),
    )

    assert validation.final_text == NO_ANSWER_TEXT
    assert validation.provenance_reason_code == PROVENANCE_NO_CONTEXT_AVAILABLE
    assert provenance.reason_code == PROVENANCE_NO_CONTEXT_AVAILABLE


def test_source_chunk_ids_match_included_prompt_context() -> None:
    huge = "alpha " + ("x" * 5000)
    chunks = [
        CorpusChunk(
            tenant_id="tenant-a",
            source_id=f"src-{index}",
            document_id=f"doc-{index}",
            parent_content_hash=f"hash-{index}",
            chunk_index=index,
            chunk_id=f"ck-{index}",
            text=huge,
            safe_metadata={},
        )
        for index in range(8)
    ]

    result = retrieve_rag_context(
        tenant_id="tenant-a",
        query_text="alpha",
        chunks=chunks,
        limit=8,
        phi_detected=False,
    )

    assert result.retrieved_source_chunk_ids == tuple(
        f"ck-{index}" for index in range(8)
    )
    assert result.source_chunk_ids
    assert set(result.source_chunk_ids) < set(result.retrieved_source_chunk_ids)
    for chunk_id in result.source_chunk_ids:
        assert f"[chunk_id={chunk_id}]" in result.context_text


def _configure_db(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "ai-provenance.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))


def _seed_chunk(db: Any, text: str, *, tenant_id: str = "tenant-a") -> str:
    corpus = create_corpus(db, tenant_id=tenant_id, name=f"{tenant_id} corpus")
    document = create_document(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title="Provenance Doc",
        source="https://example.test/provenance",
    )
    chunks = store_chunks(
        db,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[{"text": text, "ordinal": 0}],
    )
    return str(chunks[0]["chunk_id"])


def test_provider_response_cannot_smuggle_fake_citation(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    audit_events: list[Any] = []
    with get_sessionmaker()() as db:
        _seed_chunk(db, "alpha control evidence")

        def _provider(**_kwargs: Any) -> ProviderResponse:
            return ProviderResponse(
                provider_id="simulated",
                text="alpha control evidence [chunk_id=ck-fake]",
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
            db, "tenant-a", AIInferRequest(query="alpha control")
        )

    assert result["response"] == NO_ANSWER_TEXT
    assert result["sources"] == []
    audit_details = [
        event.details for event in audit_events if event.reason == "ai_plane_infer"
    ][-1]
    assert (
        audit_details["provenance_validation_result"] == PROVENANCE_SOURCE_NOT_RETRIEVED
    )
    assert audit_details["provenance_valid"] is False
    assert "alpha control evidence" not in str(audit_details)


def test_valid_ai_plane_citation_audit_safe(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    audit_events: list[Any] = []
    chunk_text = "alpha control evidence"
    with get_sessionmaker()() as db:
        chunk_id = _seed_chunk(db, chunk_text)

        def _provider(**_kwargs: Any) -> ProviderResponse:
            return ProviderResponse(
                provider_id="simulated",
                text=f"alpha control evidence [chunk_id={chunk_id}]",
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
            db, "tenant-a", AIInferRequest(query="alpha control")
        )

    metadata = cast(dict[str, Any], result["metadata"])
    assert metadata["source_chunk_ids"] == [chunk_id]
    assert result["sources"] == [{"source_id": chunk_id}]
    audit_details = [
        event.details for event in audit_events if event.reason == "ai_plane_infer"
    ][-1]
    assert audit_details["provenance_validation_result"] == PROVENANCE_VALID
    assert audit_details["provenance_valid"] is True
    assert chunk_text not in str(audit_details)
