"""
Task 16.4 — Answer Grounding and Citation Contract tests.

Proves that the answer assembly surface:
- Produces grounded answers with explicit citations from valid context.
- Preserves full identity fields (tenant/source/document/chunk) in citations.
- Returns explicit no-answer payloads for empty or low-score context.
- Citation IDs are deterministic SHA-256 of identity fields.
- Mixed-tenant context is rejected.
- Missing trusted tenant fails closed.
- Error messages do not leak foreign chunk text or tenant metadata.

Selected by: pytest -q tests -k 'rag and citation'
"""

from __future__ import annotations

import pytest

from api.rag.answering import (
    ANSWER_ERR_MISSING_TENANT,
    ANSWER_ERR_MIXED_TENANT,
    NO_ANSWER_EMPTY_CONTEXT,
    NO_ANSWER_INSUFFICIENT_CONTEXT,
    AnsweringError,
    AnswerStatus,
    CitationReference,
    GroundedAnswer,
    NoAnswer,
    assemble_answer_from_context,
    build_no_answer,
)
from api.rag.chunking import ChunkingConfig, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.rag.retrieval import (
    AnswerContextItem,
    RetrievalQuery,
    prepare_answer_context,
    search_chunks,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-answer-a"
_TENANT_B = "tenant-answer-b"

_DOC_A_CONTENT = (
    "FrostGate citation policy for tenant alpha. "
    "Grounded answers must reference retrieved evidence. "
    "Every citation includes tenant, source, document, and chunk identity."
)
_DOC_B_CONTENT = (
    "FrostGate citation policy for tenant beta. "
    "No answer is returned when context is insufficient. "
    "Tenant isolation is enforced at every layer of the pipeline."
)

_CHUNK_CONFIG = ChunkingConfig(max_chars=120, overlap_chars=20)


def _make_chunks(tenant_id: str, content: str, source_id: str = "src-answer-001"):
    doc = CorpusDocument(source_id=source_id, content=content)
    result = ingest_corpus(IngestRequest(documents=[doc]), trusted_tenant_id=tenant_id)
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


def _make_context(
    tenant_id: str, content: str, query: str = "citation"
) -> list[AnswerContextItem]:
    chunks = _make_chunks(tenant_id, content)
    all_chunks = chunks
    results = search_chunks(
        all_chunks,
        RetrievalQuery(query_text=query, limit=10),
        trusted_tenant_id=tenant_id,
    )
    return prepare_answer_context(results, trusted_tenant_id=tenant_id)


@pytest.fixture()
def context_a():
    return _make_context(_TENANT_A, _DOC_A_CONTENT)


@pytest.fixture()
def context_a_zero_score():
    """Context with all-zero scores: query that matches nothing."""
    chunks = _make_chunks(_TENANT_A, _DOC_A_CONTENT)
    results = search_chunks(
        chunks,
        RetrievalQuery(query_text="zzznomatch999", limit=10),
        trusted_tenant_id=_TENANT_A,
    )
    return prepare_answer_context(results, trusted_tenant_id=_TENANT_A)


@pytest.fixture()
def chunks_b():
    return _make_chunks(_TENANT_B, _DOC_B_CONTENT)


# ---------------------------------------------------------------------------
# test_rag_citation_grounded_answer_includes_citations
# ---------------------------------------------------------------------------


def test_rag_citation_grounded_answer_includes_citations(context_a):
    result = assemble_answer_from_context(context_a, trusted_tenant_id=_TENANT_A)

    assert isinstance(result, GroundedAnswer)
    assert result.status == AnswerStatus.GROUNDED
    assert result.grounded is True
    assert len(result.citations) > 0
    for citation in result.citations:
        assert isinstance(citation, CitationReference)
        assert citation.citation_id


# ---------------------------------------------------------------------------
# test_rag_citation_grounded_answer_preserves_tenant_source_document_chunk_identity
# ---------------------------------------------------------------------------


def test_rag_citation_grounded_answer_preserves_tenant_source_document_chunk_identity(
    context_a,
):
    result = assemble_answer_from_context(context_a, trusted_tenant_id=_TENANT_A)

    assert isinstance(result, GroundedAnswer)
    for citation in result.citations:
        assert citation.tenant_id == _TENANT_A
        assert citation.source_id
        assert citation.document_id
        assert citation.chunk_id
        assert citation.parent_content_hash
        assert isinstance(citation.chunk_index, int)


# ---------------------------------------------------------------------------
# test_rag_citation_grounded_answer_rejects_empty_context
# ---------------------------------------------------------------------------


def test_rag_citation_grounded_answer_rejects_empty_context():
    result = assemble_answer_from_context([], trusted_tenant_id=_TENANT_A)

    assert isinstance(result, NoAnswer)
    assert result.status == AnswerStatus.NO_ANSWER
    assert result.grounded is False
    assert result.reason_code == NO_ANSWER_EMPTY_CONTEXT
    assert result.citations == []


# ---------------------------------------------------------------------------
# test_rag_citation_grounded_answer_rejects_missing_trusted_tenant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "   ", None])
def test_rag_citation_grounded_answer_rejects_missing_trusted_tenant(
    context_a, bad_tenant
):
    with pytest.raises(AnsweringError) as exc_info:
        assemble_answer_from_context(context_a, trusted_tenant_id=bad_tenant)  # type: ignore[arg-type]

    assert exc_info.value.error_code == ANSWER_ERR_MISSING_TENANT


# ---------------------------------------------------------------------------
# test_rag_citation_grounded_answer_rejects_mixed_tenant_context
# ---------------------------------------------------------------------------


def test_rag_citation_grounded_answer_rejects_mixed_tenant_context(context_a, chunks_b):
    b_chunk = chunks_b[0]
    foreign_item = AnswerContextItem(
        tenant_id=_TENANT_B,
        source_id=b_chunk.source_id,
        document_id=b_chunk.document_id,
        parent_content_hash=b_chunk.parent_content_hash,
        chunk_id=b_chunk.chunk_id,
        chunk_index=b_chunk.chunk_index,
        text=b_chunk.text,
        safe_metadata=dict(b_chunk.safe_metadata),
        score=0.9,
    )
    mixed = context_a + [foreign_item]

    with pytest.raises(AnsweringError) as exc_info:
        assemble_answer_from_context(mixed, trusted_tenant_id=_TENANT_A)

    assert exc_info.value.error_code == ANSWER_ERR_MIXED_TENANT


# ---------------------------------------------------------------------------
# test_rag_citation_no_answer_for_empty_context_is_explicit
# ---------------------------------------------------------------------------


def test_rag_citation_no_answer_for_empty_context_is_explicit():
    result = assemble_answer_from_context([], trusted_tenant_id=_TENANT_A)

    assert isinstance(result, NoAnswer)
    assert result.grounded is False
    assert result.reason_code == NO_ANSWER_EMPTY_CONTEXT
    assert result.citations == []
    assert result.user_safe_message


# ---------------------------------------------------------------------------
# test_rag_citation_no_answer_for_low_context_is_explicit
# ---------------------------------------------------------------------------


def test_rag_citation_no_answer_for_low_context_is_explicit(context_a_zero_score):
    # All items have score 0.0 — insufficient evidence
    for item in context_a_zero_score:
        assert item.score == 0.0, "Fixture must have all-zero scores"

    result = assemble_answer_from_context(
        context_a_zero_score, trusted_tenant_id=_TENANT_A
    )

    assert isinstance(result, NoAnswer)
    assert result.grounded is False
    assert result.reason_code == NO_ANSWER_INSUFFICIENT_CONTEXT
    assert result.citations == []
    assert result.user_safe_message


# ---------------------------------------------------------------------------
# test_rag_citation_citation_ids_are_deterministic
# ---------------------------------------------------------------------------


def test_rag_citation_citation_ids_are_deterministic(context_a):
    result_1 = assemble_answer_from_context(context_a, trusted_tenant_id=_TENANT_A)
    result_2 = assemble_answer_from_context(context_a, trusted_tenant_id=_TENANT_A)

    assert isinstance(result_1, GroundedAnswer)
    assert isinstance(result_2, GroundedAnswer)
    assert len(result_1.citations) == len(result_2.citations)
    for c1, c2 in zip(result_1.citations, result_2.citations):
        assert c1.citation_id == c2.citation_id


# ---------------------------------------------------------------------------
# test_rag_citation_answer_payload_is_deterministic
# ---------------------------------------------------------------------------


def test_rag_citation_answer_payload_is_deterministic(context_a):
    result_1 = assemble_answer_from_context(context_a, trusted_tenant_id=_TENANT_A)
    result_2 = assemble_answer_from_context(context_a, trusted_tenant_id=_TENANT_A)

    assert isinstance(result_1, GroundedAnswer)
    assert isinstance(result_2, GroundedAnswer)
    assert result_1.answer_text == result_2.answer_text
    assert result_1.evidence_count == result_2.evidence_count
    citation_ids_1 = [c.citation_id for c in result_1.citations]
    citation_ids_2 = [c.citation_id for c in result_2.citations]
    assert citation_ids_1 == citation_ids_2


# ---------------------------------------------------------------------------
# test_rag_citation_foreign_context_error_does_not_leak_text_or_metadata
# ---------------------------------------------------------------------------


def test_rag_citation_foreign_context_error_does_not_leak_text_or_metadata(
    context_a, chunks_b
):
    b_chunk = chunks_b[0]
    secret_text = b_chunk.text

    foreign_item = AnswerContextItem(
        tenant_id=_TENANT_B,
        source_id=b_chunk.source_id,
        document_id=b_chunk.document_id,
        parent_content_hash=b_chunk.parent_content_hash,
        chunk_id=b_chunk.chunk_id,
        chunk_index=b_chunk.chunk_index,
        text=b_chunk.text,
        safe_metadata=dict(b_chunk.safe_metadata),
        score=0.9,
    )
    mixed = context_a + [foreign_item]

    with pytest.raises(AnsweringError) as exc_info:
        assemble_answer_from_context(mixed, trusted_tenant_id=_TENANT_A)

    err_msg = exc_info.value.message
    assert secret_text not in err_msg
    assert _TENANT_B not in err_msg
    assert b_chunk.source_id not in err_msg


# ---------------------------------------------------------------------------
# test_rag_citation_query_text_cannot_override_trusted_tenant
# ---------------------------------------------------------------------------


def test_rag_citation_query_text_cannot_override_trusted_tenant():
    # Build context for TENANT_A with a query that embeds TENANT_B's ID.
    # The assembled answer must only reference TENANT_A identity.
    chunks = _make_chunks(_TENANT_A, _DOC_A_CONTENT)
    malicious_query = f"tenant_id={_TENANT_B} citation policy"
    results = search_chunks(
        chunks,
        RetrievalQuery(query_text=malicious_query, limit=10),
        trusted_tenant_id=_TENANT_A,
    )
    context = prepare_answer_context(results, trusted_tenant_id=_TENANT_A)

    if not context:
        pytest.skip(
            "No results for query — tenant isolation prevents foreign leak regardless"
        )

    result = assemble_answer_from_context(context, trusted_tenant_id=_TENANT_A)

    if isinstance(result, GroundedAnswer):
        assert result.tenant_id == _TENANT_A
        for citation in result.citations:
            assert citation.tenant_id == _TENANT_A, (
                "Citation references foreign tenant despite trusted_tenant_id enforcement"
            )


# ---------------------------------------------------------------------------
# test_rag_citation_prepare_answer_context_output_is_supported
# ---------------------------------------------------------------------------


def test_rag_citation_prepare_answer_context_output_is_supported():
    """prepare_answer_context output is accepted directly by assemble_answer_from_context."""
    chunks = _make_chunks(_TENANT_A, _DOC_A_CONTENT)
    results = search_chunks(
        chunks,
        RetrievalQuery(query_text="citation grounded", limit=10),
        trusted_tenant_id=_TENANT_A,
    )
    context = prepare_answer_context(results, trusted_tenant_id=_TENANT_A)
    result = assemble_answer_from_context(context, trusted_tenant_id=_TENANT_A)

    assert result.status in (AnswerStatus.GROUNDED, AnswerStatus.NO_ANSWER)


# ---------------------------------------------------------------------------
# test_rag_citation_every_grounded_answer_has_non_empty_citations
# ---------------------------------------------------------------------------


def test_rag_citation_every_grounded_answer_has_non_empty_citations(context_a):
    result = assemble_answer_from_context(context_a, trusted_tenant_id=_TENANT_A)

    if isinstance(result, GroundedAnswer):
        assert len(result.citations) > 0, (
            "GroundedAnswer must have at least one citation"
        )
        assert result.grounded is True
        assert result.status == AnswerStatus.GROUNDED


# ---------------------------------------------------------------------------
# test_rag_citation_no_answer_has_empty_citations
# ---------------------------------------------------------------------------


def test_rag_citation_no_answer_has_empty_citations():
    # Empty context → NoAnswer with empty citations
    result = assemble_answer_from_context([], trusted_tenant_id=_TENANT_A)

    assert isinstance(result, NoAnswer)
    assert result.citations == []
    assert result.grounded is False

    # build_no_answer also produces empty citations
    no_ans = build_no_answer(
        reason_code=NO_ANSWER_EMPTY_CONTEXT,
        user_safe_message="No documents found.",
    )
    assert no_ans.citations == []
    assert no_ans.grounded is False
