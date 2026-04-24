"""
Task 16.3 — Retrieval Tenant Isolation security tests.

Proves that the retrieval surface enforces tenant_id strictly:
- Foreign tenant chunks are never returned.
- Fetch-by-ID respects tenant boundary.
- Query text/payload cannot override trusted tenant.
- Missing trusted tenant fails closed.
- Error messages do not leak foreign chunk text or metadata.

Selected by: pytest -q tests/security -k 'rag and tenant'
"""

from __future__ import annotations

import pytest

from api.rag.chunking import ChunkingConfig, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.rag.retrieval import (
    RETRIEVAL_ERR_CHUNK_NOT_FOUND,
    RETRIEVAL_ERR_INVALID_LIMIT,
    RETRIEVAL_ERR_MISSING_TENANT,
    RETRIEVAL_ERR_MIXED_TENANT,
    AnswerContextItem,
    RetrievalError,
    RetrievalQuery,
    RetrievalResult,
    fetch_chunk,
    prepare_answer_context,
    search_chunks,
)

# ---------------------------------------------------------------------------
# Fixtures — two tenants with overlapping query terms
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-rag-a"
_TENANT_B = "tenant-rag-b"

# Both documents contain the word "security" so a naive search without
# tenant filtering would return chunks from both tenants.
_DOC_A_CONTENT = (
    "FrostGate security policy for tenant alpha. "
    "This document covers authentication and authorization requirements. "
    "Security controls must be enforced at every layer."
)
_DOC_B_CONTENT = (
    "FrostGate security policy for tenant beta. "
    "This document covers audit logging and compliance requirements. "
    "Security events must be captured and retained."
)

_CHUNK_CONFIG = ChunkingConfig(max_chars=120, overlap_chars=20)


def _make_chunks(tenant_id: str, content: str, source_id: str = "src-001"):
    doc = CorpusDocument(source_id=source_id, content=content)
    result = ingest_corpus(IngestRequest(documents=[doc]), trusted_tenant_id=tenant_id)
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


@pytest.fixture()
def chunks_a():
    return _make_chunks(_TENANT_A, _DOC_A_CONTENT)


@pytest.fixture()
def chunks_b():
    return _make_chunks(_TENANT_B, _DOC_B_CONTENT)


@pytest.fixture()
def all_chunks(chunks_a, chunks_b):
    """Combined pool with chunks from both tenants — simulates shared store."""
    return chunks_a + chunks_b


# ---------------------------------------------------------------------------
# test_rag_tenant_search_returns_only_same_tenant_chunks
# ---------------------------------------------------------------------------


def test_rag_tenant_search_returns_only_same_tenant_chunks(all_chunks):
    query = RetrievalQuery(query_text="security", limit=50)
    results = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)

    assert len(results) > 0
    for result in results:
        assert result.tenant_id == _TENANT_A, (
            f"Foreign tenant chunk leaked into results: {result.tenant_id}"
        )


# ---------------------------------------------------------------------------
# test_rag_tenant_search_cross_tenant_candidates_are_not_returned
# ---------------------------------------------------------------------------


def test_rag_tenant_search_cross_tenant_candidates_are_not_returned(
    all_chunks, chunks_b
):
    # Query deliberately matches TENANT_B document text.
    # Results must still be empty (no tenant_b chunks; tenant_a has no match).
    query = RetrievalQuery(query_text="beta audit logging compliance", limit=50)
    results = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)

    for result in results:
        assert result.tenant_id == _TENANT_A, (
            "Cross-tenant chunk returned despite query matching foreign content"
        )

    # Confirm the query WOULD match tenant_b chunks (so the filter is doing work)
    b_results = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_B)
    assert any(r.score > 0 for r in b_results), (
        "Test fixture broken: query should match tenant_b chunks"
    )


# ---------------------------------------------------------------------------
# test_rag_tenant_search_same_tenant_succeeds
# ---------------------------------------------------------------------------


def test_rag_tenant_search_same_tenant_succeeds(all_chunks):
    query = RetrievalQuery(query_text="authentication authorization", limit=10)
    results = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)

    assert len(results) > 0
    assert all(r.tenant_id == _TENANT_A for r in results)
    # At least one result should have a non-zero score
    assert any(r.score > 0 for r in results)


# ---------------------------------------------------------------------------
# test_rag_tenant_fetch_same_tenant_chunk_succeeds
# ---------------------------------------------------------------------------


def test_rag_tenant_fetch_same_tenant_chunk_succeeds(chunks_a, all_chunks):
    target_chunk = chunks_a[0]
    result = fetch_chunk(all_chunks, target_chunk.chunk_id, trusted_tenant_id=_TENANT_A)

    assert isinstance(result, RetrievalResult)
    assert result.chunk_id == target_chunk.chunk_id
    assert result.tenant_id == _TENANT_A


# ---------------------------------------------------------------------------
# test_rag_tenant_fetch_foreign_chunk_id_denied_or_not_found
# ---------------------------------------------------------------------------


def test_rag_tenant_fetch_foreign_chunk_id_denied_or_not_found(chunks_b, all_chunks):
    # Use a valid chunk_id that belongs to TENANT_B; request it as TENANT_A.
    foreign_chunk_id = chunks_b[0].chunk_id

    with pytest.raises(RetrievalError) as exc_info:
        fetch_chunk(all_chunks, foreign_chunk_id, trusted_tenant_id=_TENANT_A)

    # Must return not-found (same as absent) — no existence side channel.
    assert exc_info.value.error_code == RETRIEVAL_ERR_CHUNK_NOT_FOUND


# ---------------------------------------------------------------------------
# test_rag_tenant_missing_trusted_tenant_fails_closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "   ", None])
def test_rag_tenant_missing_trusted_tenant_fails_closed(all_chunks, bad_tenant):
    query = RetrievalQuery(query_text="security")

    with pytest.raises(RetrievalError) as exc_info:
        search_chunks(all_chunks, query, trusted_tenant_id=bad_tenant)  # type: ignore[arg-type]
    assert exc_info.value.error_code == RETRIEVAL_ERR_MISSING_TENANT

    if all_chunks:
        with pytest.raises(RetrievalError) as exc_info2:
            fetch_chunk(
                all_chunks, all_chunks[0].chunk_id, trusted_tenant_id=bad_tenant
            )  # type: ignore[arg-type]
        assert exc_info2.value.error_code == RETRIEVAL_ERR_MISSING_TENANT


# ---------------------------------------------------------------------------
# test_rag_tenant_query_cannot_override_trusted_tenant
# ---------------------------------------------------------------------------


def test_rag_tenant_query_cannot_override_trusted_tenant(all_chunks, chunks_b):
    # Embedding a tenant ID into query text must not affect tenant filtering.
    malicious_query = f"tenant_id={_TENANT_B} security policy"
    results = search_chunks(
        all_chunks,
        RetrievalQuery(query_text=malicious_query),
        trusted_tenant_id=_TENANT_A,
    )

    for result in results:
        assert result.tenant_id == _TENANT_A, (
            "Query text containing foreign tenant ID leaked cross-tenant chunk"
        )


# ---------------------------------------------------------------------------
# test_rag_tenant_answer_context_preserves_tenant_source_metadata
# ---------------------------------------------------------------------------


def test_rag_tenant_answer_context_preserves_tenant_source_metadata(all_chunks):
    query = RetrievalQuery(query_text="security", limit=5)
    results = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)
    context = prepare_answer_context(results, trusted_tenant_id=_TENANT_A)

    assert len(context) > 0
    for item in context:
        assert isinstance(item, AnswerContextItem)
        assert item.tenant_id == _TENANT_A
        assert item.source_id
        assert item.document_id
        assert item.parent_content_hash
        assert item.chunk_id
        assert item.text


# ---------------------------------------------------------------------------
# test_rag_tenant_answer_context_rejects_or_filters_mixed_tenant_results
# ---------------------------------------------------------------------------


def test_rag_tenant_answer_context_rejects_or_filters_mixed_tenant_results(
    all_chunks, chunks_b
):
    # Construct a mixed result list by fetching TENANT_A results and manually
    # appending a TENANT_B result object (simulates a bypass attempt).
    query = RetrievalQuery(query_text="security", limit=5)
    results_a = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)

    b_chunk = chunks_b[0]
    foreign_result = RetrievalResult(
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
    mixed = results_a + [foreign_result]

    with pytest.raises(RetrievalError) as exc_info:
        prepare_answer_context(mixed, trusted_tenant_id=_TENANT_A)

    assert exc_info.value.error_code == RETRIEVAL_ERR_MIXED_TENANT


# ---------------------------------------------------------------------------
# test_rag_tenant_result_order_is_deterministic
# ---------------------------------------------------------------------------


def test_rag_tenant_result_order_is_deterministic(all_chunks):
    query = RetrievalQuery(query_text="security policy", limit=50)

    results_1 = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)
    results_2 = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)

    assert len(results_1) == len(results_2)
    for r1, r2 in zip(results_1, results_2):
        assert r1.chunk_id == r2.chunk_id
        assert r1.score == r2.score


# ---------------------------------------------------------------------------
# test_rag_tenant_foreign_fetch_error_does_not_leak_text_or_metadata
# ---------------------------------------------------------------------------


def test_rag_tenant_foreign_fetch_error_does_not_leak_text_or_metadata(
    chunks_b, all_chunks
):
    foreign_chunk = chunks_b[0]
    secret_text = foreign_chunk.text  # this is tenant_b's content

    with pytest.raises(RetrievalError) as exc_info:
        fetch_chunk(all_chunks, foreign_chunk.chunk_id, trusted_tenant_id=_TENANT_A)

    err_msg = exc_info.value.message
    # Raw foreign text must not appear in the error
    assert secret_text not in err_msg
    # Foreign tenant ID must not appear in the error
    assert _TENANT_B not in err_msg
    # Foreign source_id must not appear in the error
    assert foreign_chunk.source_id not in err_msg


# ---------------------------------------------------------------------------
# test_rag_tenant_limit_is_bounded_and_deterministic
# ---------------------------------------------------------------------------


def test_rag_tenant_limit_is_bounded_and_deterministic(all_chunks):
    query_1 = RetrievalQuery(query_text="security", limit=1)
    query_2 = RetrievalQuery(query_text="security", limit=1)

    results_1 = search_chunks(all_chunks, query_1, trusted_tenant_id=_TENANT_A)
    results_2 = search_chunks(all_chunks, query_2, trusted_tenant_id=_TENANT_A)

    assert len(results_1) <= 1
    assert len(results_2) <= 1
    if results_1 and results_2:
        assert results_1[0].chunk_id == results_2[0].chunk_id

    # Invalid limits must be rejected
    for bad_limit in [0, -1, _MAX_LIMIT + 1]:
        bad_query = RetrievalQuery(query_text="security", limit=bad_limit)
        with pytest.raises(RetrievalError) as exc_info:
            search_chunks(all_chunks, bad_query, trusted_tenant_id=_TENANT_A)
        assert exc_info.value.error_code == RETRIEVAL_ERR_INVALID_LIMIT


# Need this import for the parametrize test above
_MAX_LIMIT = 100
