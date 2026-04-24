"""
Task 16.5 — Retrieval Ranking Determinism tests.

Proves that the enhanced ranking layer:
- Produces deterministic output for fixed input.
- Improves relevance ordering over no-ranking.
- Applies a stable tie-break (chunk_index ASC, chunk_id ASC).
- Respects tenant boundaries — never adds or changes tenant_id.
- Does not alter the result set (same chunk_ids in, same chunk_ids out).
- Integrates cleanly with the answer grounding pipeline.
- Handles empty input safely.
- Does not introduce cross-tenant chunks.

Selected by: pytest -k 'rag and ranking'
"""

from __future__ import annotations

import pytest

from api.rag.answering import AnswerStatus, GroundedAnswer, assemble_answer_from_context
from api.rag.chunking import ChunkingConfig, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.rag.retrieval import (
    RetrievalQuery,
    RetrievalResult,
    prepare_answer_context,
    rank_chunks,
    search_chunks,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-ranking-a"
_TENANT_B = "tenant-ranking-b"

# DOC_A has dense coverage of "authentication" — should rank above DOC_A_LOW
_DOC_A_HIGH = (
    "FrostGate authentication policy. "
    "Authentication is required for every request. "
    "Failed authentication must be logged. "
    "Authentication tokens expire after 15 minutes."
)
_DOC_A_LOW = (
    "FrostGate general configuration notes. "
    "Default timeouts and retry policies are documented here."
)
_DOC_B_CONTENT = (
    "FrostGate tenant beta configuration. "
    "Authentication settings for tenant beta are separate."
)

_CHUNK_CONFIG = ChunkingConfig(max_chars=200, overlap_chars=20)


def _make_chunks(tenant_id: str, content: str, source_id: str = "src-rank-001"):
    doc = CorpusDocument(source_id=source_id, content=content)
    result = ingest_corpus(IngestRequest(documents=[doc]), trusted_tenant_id=tenant_id)
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


def _make_result(
    tenant_id: str,
    chunk_id: str,
    chunk_index: int,
    text: str,
    score: float = 0.5,
    source_id: str = "src-rank-001",
    document_id: str = "doc-rank-001",
    parent_content_hash: str = "hash-rank-001",
) -> RetrievalResult:
    return RetrievalResult(
        tenant_id=tenant_id,
        source_id=source_id,
        document_id=document_id,
        parent_content_hash=parent_content_hash,
        chunk_id=chunk_id,
        chunk_index=chunk_index,
        text=text,
        safe_metadata={},
        score=score,
    )


@pytest.fixture()
def chunks_a_high():
    return _make_chunks(_TENANT_A, _DOC_A_HIGH)


@pytest.fixture()
def chunks_a_low():
    return _make_chunks(_TENANT_A, _DOC_A_LOW, source_id="src-rank-002")


@pytest.fixture()
def chunks_b():
    return _make_chunks(_TENANT_B, _DOC_B_CONTENT, source_id="src-rank-b")


@pytest.fixture()
def all_chunks_a(chunks_a_high, chunks_a_low):
    return chunks_a_high + chunks_a_low


@pytest.fixture()
def all_chunks(chunks_a_high, chunks_a_low, chunks_b):
    return chunks_a_high + chunks_a_low + chunks_b


# ---------------------------------------------------------------------------
# test_rag_ranking_is_deterministic
# ---------------------------------------------------------------------------


def test_rag_ranking_is_deterministic(all_chunks_a):
    query = RetrievalQuery(query_text="authentication", limit=50)
    results = search_chunks(all_chunks_a, query, trusted_tenant_id=_TENANT_A)

    ranked_1 = rank_chunks(results, "authentication")
    ranked_2 = rank_chunks(results, "authentication")

    assert len(ranked_1) == len(ranked_2)
    for r1, r2 in zip(ranked_1, ranked_2):
        assert r1.chunk_id == r2.chunk_id
        assert r1.score == r2.score


# ---------------------------------------------------------------------------
# test_rag_ranking_orders_by_relevance
# ---------------------------------------------------------------------------


def test_rag_ranking_orders_by_relevance():
    # Construct two results explicitly: high-relevance has the query term
    # repeated, low-relevance does not mention it at all.
    high = _make_result(
        _TENANT_A,
        "chunk-high",
        chunk_index=1,
        text="authentication token authentication required authentication",
    )
    low = _make_result(
        _TENANT_A,
        "chunk-low",
        chunk_index=0,  # lower index — would win tie-break, but score should lose
        text="default timeout configuration retry policy",
    )

    ranked = rank_chunks([low, high], "authentication")

    assert len(ranked) == 2
    assert ranked[0].chunk_id == "chunk-high", (
        "Higher-relevance chunk must rank first regardless of chunk_index"
    )
    assert ranked[0].score > ranked[1].score


# ---------------------------------------------------------------------------
# test_rag_ranking_tie_break_is_stable
# ---------------------------------------------------------------------------


def test_rag_ranking_tie_break_is_stable():
    # Three results with identical text → identical scores.
    # Tie-break must be chunk_index ASC then chunk_id ASC.
    shared_text = "authentication policy required"
    r0 = _make_result(_TENANT_A, "chunk-z", chunk_index=2, text=shared_text)
    r1 = _make_result(_TENANT_A, "chunk-a", chunk_index=0, text=shared_text)
    r2 = _make_result(_TENANT_A, "chunk-m", chunk_index=0, text=shared_text)

    ranked = rank_chunks([r0, r1, r2], "authentication policy")

    # All scores equal; chunk_index 0 beats 2; among index-0, chunk-a < chunk-m
    assert ranked[0].chunk_id == "chunk-a"
    assert ranked[1].chunk_id == "chunk-m"
    assert ranked[2].chunk_id == "chunk-z"


# ---------------------------------------------------------------------------
# test_rag_ranking_respects_tenant_filter
# ---------------------------------------------------------------------------


def test_rag_ranking_respects_tenant_filter(all_chunks_a):
    query = RetrievalQuery(query_text="authentication", limit=50)
    results = search_chunks(all_chunks_a, query, trusted_tenant_id=_TENANT_A)
    ranked = rank_chunks(results, "authentication")

    for r in ranked:
        assert r.tenant_id == _TENANT_A, (
            f"rank_chunks must not change or introduce foreign tenant_id: {r.tenant_id}"
        )


# ---------------------------------------------------------------------------
# test_rag_ranking_does_not_change_result_set
# ---------------------------------------------------------------------------


def test_rag_ranking_does_not_change_result_set(all_chunks_a):
    query = RetrievalQuery(query_text="authentication policy", limit=50)
    results = search_chunks(all_chunks_a, query, trusted_tenant_id=_TENANT_A)

    before_ids = {r.chunk_id for r in results}
    ranked = rank_chunks(results, "authentication policy")
    after_ids = {r.chunk_id for r in ranked}

    assert before_ids == after_ids, (
        "rank_chunks must not add or remove chunks — only reorder them"
    )
    assert len(ranked) == len(results)


# ---------------------------------------------------------------------------
# test_rag_ranking_integrates_with_answering
# ---------------------------------------------------------------------------


def test_rag_ranking_integrates_with_answering(all_chunks_a):
    query = RetrievalQuery(query_text="authentication", limit=10)
    results = search_chunks(all_chunks_a, query, trusted_tenant_id=_TENANT_A)
    ranked = rank_chunks(results, "authentication")
    context = prepare_answer_context(ranked, trusted_tenant_id=_TENANT_A)
    answer = assemble_answer_from_context(context, trusted_tenant_id=_TENANT_A)

    assert answer.status in (AnswerStatus.GROUNDED, AnswerStatus.NO_ANSWER)
    if isinstance(answer, GroundedAnswer):
        assert answer.tenant_id == _TENANT_A
        assert len(answer.citations) > 0


# ---------------------------------------------------------------------------
# test_rag_ranking_empty_input_safe
# ---------------------------------------------------------------------------


def test_rag_ranking_empty_input_safe():
    ranked = rank_chunks([], "authentication")
    assert ranked == []

    # Empty query on non-empty input: all scores 0, result set unchanged
    r = _make_result(_TENANT_A, "chunk-x", chunk_index=0, text="some text here")
    ranked_empty_query = rank_chunks([r], "")
    assert len(ranked_empty_query) == 1
    assert ranked_empty_query[0].score == 0.0


# ---------------------------------------------------------------------------
# test_rag_ranking_does_not_leak_cross_tenant
# ---------------------------------------------------------------------------


def test_rag_ranking_does_not_leak_cross_tenant(all_chunks, chunks_b):
    # search_chunks already filters to TENANT_A; rank_chunks must not add TENANT_B
    query = RetrievalQuery(query_text="authentication", limit=50)
    results = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_A)

    # Confirm tenant isolation upstream is working
    for r in results:
        assert r.tenant_id == _TENANT_A

    ranked = rank_chunks(results, "authentication")

    for r in ranked:
        assert r.tenant_id == _TENANT_A, (
            "rank_chunks must not introduce chunks from foreign tenants"
        )

    # Confirm foreign chunks exist in the pool (filter is doing real work)
    b_results = search_chunks(all_chunks, query, trusted_tenant_id=_TENANT_B)
    assert any(r.score > 0 for r in b_results), (
        "Test fixture broken: TENANT_B chunks should match the query"
    )
