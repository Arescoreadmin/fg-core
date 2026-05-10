from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import text

from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.rag_corpus_store import create_corpus, create_document, store_chunks
from services.ai.provenance import (
    PROVENANCE_NO_CONTEXT_AVAILABLE,
    PROVENANCE_SOURCE_NOT_IN_PROMPT,
    PROVENANCE_SOURCE_NOT_RETRIEVED,
    validate_answer_provenance,
)
from services.ai.providers.base import ProviderResponse
from services.ai.rag_context import RagContextChunk, RagContextResult
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


def _rag_context(
    *,
    source_chunk_ids: tuple[str, ...],
    retrieved_source_chunk_ids: tuple[str, ...],
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
        source_ids=tuple(retrieved_source_chunk_ids),
        retrieval_reason_code="RAG_RETRIEVAL_SELECTED"
        if chunks
        else "RAG_RETRIEVAL_EMPTY",
        query_phi_sensitivity="none",
        max_sensitivity_level=None,
        contains_phi=False,
        source_chunk_ids=source_chunk_ids,
        retrieved_source_chunk_ids=retrieved_source_chunk_ids,
    )


def _configure_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "ai-plane-provenance-trust-path.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))


def _seed_chunk(db: Any, *, tenant_id: str, text: str) -> str:
    corpus = create_corpus(db, tenant_id=tenant_id, name=f"{tenant_id} corpus")
    document = create_document(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title="AI Plane Provenance Security",
        source="https://example.test/ai-plane-provenance-security",
    )
    chunks = store_chunks(
        db,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[{"text": text, "ordinal": 0}],
    )
    return str(chunks[0]["chunk_id"])


def test_ai_provenance_security_rejects_fake_citations() -> None:
    validation, provenance = validate_answer_provenance(
        response_text="alpha control evidence [chunk_id=ck-fake]",
        rag_context=_rag_context(
            source_chunk_ids=("ck-real",),
            retrieved_source_chunk_ids=("ck-real",),
        ),
        response_validation=_validation("ck-real"),
    )

    assert validation.final_text == NO_ANSWER_TEXT
    assert validation.citation_source_ids == ()
    assert validation.provenance_reason_code == PROVENANCE_SOURCE_NOT_RETRIEVED
    assert validation.provenance_valid is False
    assert provenance.valid is False
    assert provenance.invalid_source_ids == ("ck-fake",)


def test_ai_provenance_security_rejects_prompt_excluded_citations() -> None:
    validation, provenance = validate_answer_provenance(
        response_text="alpha control evidence [chunk_id=ck-truncated]",
        rag_context=_rag_context(
            source_chunk_ids=("ck-in-prompt",),
            retrieved_source_chunk_ids=("ck-in-prompt", "ck-truncated"),
        ),
        response_validation=_validation("ck-truncated"),
    )

    assert validation.final_text == NO_ANSWER_TEXT
    assert validation.citation_source_ids == ()
    assert validation.provenance_reason_code == PROVENANCE_SOURCE_NOT_IN_PROMPT
    assert validation.provenance_valid is False
    assert provenance.valid is False
    assert provenance.invalid_source_ids == ("ck-truncated",)


def test_ai_provenance_security_rejects_no_context_source_claims() -> None:
    validation, provenance = validate_answer_provenance(
        response_text="unsupported answer [chunk_id=ck-claimed]",
        rag_context=_rag_context(
            source_chunk_ids=(),
            retrieved_source_chunk_ids=(),
        ),
        response_validation=_validation(),
    )

    assert validation.final_text == NO_ANSWER_TEXT
    assert validation.citation_source_ids == ()
    assert validation.provenance_reason_code == PROVENANCE_NO_CONTEXT_AVAILABLE
    assert validation.provenance_valid is False
    assert provenance.valid is False
    assert provenance.invalid_source_ids == ("ck-claimed",)


def test_ai_plane_security_blocks_provider_citation_smuggling_fail_closed_and_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_db(tmp_path, monkeypatch)
    audit_events: list[Any] = []
    captured_prompt = ""
    raw_chunk_text = "alpha control evidence patientname MRN12345 secretphrase"
    with get_sessionmaker()() as db:
        _seed_chunk(db, tenant_id="tenant-a", text=raw_chunk_text)

        def _provider(**kwargs: Any) -> ProviderResponse:
            nonlocal captured_prompt
            captured_prompt = str(kwargs["prompt"])
            return ProviderResponse(
                provider_id="simulated",
                text="alpha control evidence [chunk_id=ck-fake-smuggled]",
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
            AIInferRequest(query="alpha control patientname MRN12345 secretphrase"),
        )

        stored = (
            db.execute(
                text(
                    "SELECT response_text FROM ai_inference_records "
                    "WHERE tenant_id=:tenant_id"
                ),
                {"tenant_id": "tenant-a"},
            )
            .mappings()
            .all()
        )

    assert result["response"] == NO_ANSWER_TEXT
    assert result["sources"] == []
    assert result["confidence"] == 0.0
    assert stored and all(row["response_text"] == NO_ANSWER_TEXT for row in stored)

    provenance = cast(dict[str, Any], result["provenance"])
    assert provenance["provenance_status"] == PROVENANCE_SOURCE_NOT_RETRIEVED
    assert provenance["source_chunk_ids"]
    assert provenance["source_summaries"]
    assert provenance["why_this_chunk"]

    audit_details = [
        event.details for event in audit_events if event.reason == "ai_plane_infer"
    ][-1]
    assert (
        audit_details["provenance_validation_result"] == PROVENANCE_SOURCE_NOT_RETRIEVED
    )
    assert audit_details["provenance_valid"] is False
    assert (
        audit_details["response_validation_result"] == PROVENANCE_SOURCE_NOT_RETRIEVED
    )
    assert audit_details["response_citation_source_ids"] == []
    assert audit_details["response_evidence_count"] == 0

    serialized_result = json.dumps(result, sort_keys=True)
    serialized_audit = json.dumps(audit_details, sort_keys=True)
    for forbidden in (
        raw_chunk_text,
        captured_prompt,
        "patientname",
        "MRN12345",
        "secretphrase",
        "ck-fake-smuggled",
        "raw_vector",
        "embedding_vector",
        "[0.1, 0.2, 0.3]",
    ):
        assert forbidden not in serialized_result
        assert forbidden not in serialized_audit
