from __future__ import annotations

import pytest

from services.ai.rag_context import RagContextChunk, RagContextResult
from services.ai.response_validation import (
    NO_ANSWER_TEXT,
    RESPONSE_EMPTY,
    RESPONSE_GROUNDED,
    RESPONSE_NO_RAG_CONTEXT,
    RESPONSE_UNGROUNDED,
    RESPONSE_VALIDATOR_VERSION,
    ResponseValidationError,
    validate_provider_response_grounding,
)


def _rag_context(*chunks: RagContextChunk) -> RagContextResult:
    return RagContextResult(
        chunks=tuple(chunks),
        context_text="\n".join(chunk.text for chunk in chunks),
        chunk_count=len(chunks),
        source_ids=tuple(dict.fromkeys(chunk.source_id for chunk in chunks)),
        retrieval_reason_code="RAG_RETRIEVAL_SELECTED"
        if chunks
        else "RAG_RETRIEVAL_EMPTY",
        query_phi_sensitivity="none",
        max_sensitivity_level="none",
        contains_phi=False,
    )


def _chunk(source_id: str, text: str) -> RagContextChunk:
    return RagContextChunk(
        source_id=source_id,
        chunk_id=f"{source_id}-chunk",
        chunk_index=0,
        text=text,
        phi_sensitivity_level="none",
        phi_types=(),
    )


def test_grounded_answer_returns_provider_text() -> None:
    result = validate_provider_response_grounding(
        response_text="Authentication control evidence alpha",
        rag_context=_rag_context(
            _chunk("source-a", "Authentication control evidence alpha")
        ),
        tenant_id="tenant-a",
    )

    assert result.grounded is True
    assert result.final_text == "Authentication control evidence alpha"
    assert result.reason_code == RESPONSE_GROUNDED
    assert result.citation_source_ids == ("source-a",)
    assert result.validator_version == RESPONSE_VALIDATOR_VERSION
    assert result.evidence_count == 1


def test_ungrounded_answer_returns_no_answer() -> None:
    result = validate_provider_response_grounding(
        response_text="Unsupported deployment procedure",
        rag_context=_rag_context(
            _chunk("source-a", "Authentication control evidence alpha")
        ),
        tenant_id="tenant-a",
    )

    assert result.grounded is False
    assert result.final_text == NO_ANSWER_TEXT
    assert result.reason_code == RESPONSE_UNGROUNDED
    assert result.citation_source_ids == ()
    assert result.evidence_count == 0


def test_empty_response_returns_no_answer() -> None:
    result = validate_provider_response_grounding(
        response_text=" ",
        rag_context=_rag_context(
            _chunk("source-a", "Authentication control evidence alpha")
        ),
        tenant_id="tenant-a",
    )

    assert result.final_text == NO_ANSWER_TEXT
    assert result.reason_code == RESPONSE_EMPTY


def test_no_rag_context_returns_no_answer() -> None:
    result = validate_provider_response_grounding(
        response_text="Authentication control evidence alpha",
        rag_context=_rag_context(),
        tenant_id="tenant-a",
    )

    assert result.final_text == NO_ANSWER_TEXT
    assert result.reason_code == RESPONSE_NO_RAG_CONTEXT


def test_missing_tenant_fails_closed() -> None:
    with pytest.raises(ResponseValidationError, match="tenant_id is required"):
        validate_provider_response_grounding(
            response_text="Authentication control evidence alpha",
            rag_context=_rag_context(
                _chunk("source-a", "Authentication control evidence alpha")
            ),
            tenant_id=" ",
        )


def test_citation_source_ids_and_evidence_count_are_deterministic() -> None:
    context = _rag_context(
        _chunk("source-b", "Backup policy restoration control"),
        _chunk("source-a", "Authentication control evidence alpha"),
        _chunk("source-b", "Authentication evidence retained"),
    )

    first = validate_provider_response_grounding(
        response_text="Authentication evidence",
        rag_context=context,
        tenant_id="tenant-a",
    )
    second = validate_provider_response_grounding(
        response_text="Authentication evidence",
        rag_context=context,
        tenant_id="tenant-a",
    )

    assert first == second
    assert first.citation_source_ids == ("source-a", "source-b")
    assert first.evidence_count == 2


def test_validation_result_excludes_raw_context_when_denied() -> None:
    result = validate_provider_response_grounding(
        response_text="Unsupported answer with secret",
        rag_context=_rag_context(_chunk("source-a", "raw context with 123-45-6789")),
        tenant_id="tenant-a",
    )

    payload = str(result)
    assert result.final_text == NO_ANSWER_TEXT
    assert "Unsupported answer with secret" not in payload
    assert "raw context" not in payload
    assert "123-45-6789" not in payload
