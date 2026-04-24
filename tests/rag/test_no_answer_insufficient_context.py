"""
Task 16.6 — No-Answer and Insufficient-Context Behavior tests.

Proves that the answer assembly surface:
- Returns explicit structured no-answer for empty, zero-score, and low-score context.
- Enforces AnswerConfidencePolicy thresholds deterministically.
- Rejects invalid policies with a stable error code.
- Never produces grounded answers from insufficient context.
- Preserves tenant safety — no-answer payloads contain no foreign metadata.
- Remains deterministic: same inputs always produce identical payloads.

Selected by: pytest -k 'rag and no_answer'
"""

from __future__ import annotations

import pytest

from api.rag.answering import (
    ANSWER_ERR_INVALID_POLICY,
    ANSWER_ERR_MISSING_TENANT,
    ANSWER_ERR_MIXED_TENANT,
    NO_ANSWER_EMPTY_CONTEXT,
    NO_ANSWER_INSUFFICIENT_CONTEXT,
    NO_ANSWER_LOW_SCORE,
    AnswerConfidencePolicy,
    AnsweringError,
    AnswerStatus,
    GroundedAnswer,
    NoAnswer,
    build_answer_or_no_answer,
    evaluate_context_sufficiency,
)
from api.rag.chunking import ChunkingConfig, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.rag.retrieval import (
    AnswerContextItem,
    RetrievalQuery,
    prepare_answer_context,
    rank_chunks,
    search_chunks,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-rag-a"
_TENANT_B = "tenant-rag-b"

_DOC_A_CONTENT = (
    "FrostGate authentication policy for tenant alpha. "
    "Authentication tokens are required for all requests. "
    "Expired tokens must be rejected immediately. "
    "Authentication failures must be logged with tenant context."
)
_DOC_B_CONTENT = (
    "FrostGate audit policy for tenant beta. "
    "All access events must be captured in the audit log. "
    "Audit records are tenant-isolated and immutable."
)

_CHUNK_CONFIG = ChunkingConfig(max_chars=200, overlap_chars=20)


def _make_chunks(tenant_id: str, content: str, source_id: str = "src-no-answer-001"):
    doc = CorpusDocument(source_id=source_id, content=content)
    result = ingest_corpus(IngestRequest(documents=[doc]), trusted_tenant_id=tenant_id)
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


def _make_context(
    tenant_id: str,
    query: str,
    content: str = _DOC_A_CONTENT,
    source_id: str = "src-no-answer-001",
) -> list[AnswerContextItem]:
    chunks = _make_chunks(tenant_id, content, source_id=source_id)
    results = search_chunks(
        chunks, RetrievalQuery(query_text=query, limit=10), trusted_tenant_id=tenant_id
    )
    ranked = rank_chunks(results, query)
    return prepare_answer_context(ranked, trusted_tenant_id=tenant_id)


def _make_zero_score_context(tenant_id: str) -> list[AnswerContextItem]:
    """Returns context where all items have score 0.0 (query matches nothing)."""
    chunks = _make_chunks(tenant_id, _DOC_A_CONTENT)
    results = search_chunks(
        chunks,
        RetrievalQuery(query_text="zzznomatch999xyz", limit=10),
        trusted_tenant_id=tenant_id,
    )
    return prepare_answer_context(results, trusted_tenant_id=tenant_id)


@pytest.fixture()
def context_a():
    return _make_context(_TENANT_A, "authentication")


@pytest.fixture()
def context_a_zero():
    return _make_zero_score_context(_TENANT_A)


@pytest.fixture()
def chunks_b():
    return _make_chunks(_TENANT_B, _DOC_B_CONTENT, source_id="src-no-answer-b")


# ---------------------------------------------------------------------------
# test_rag_no_answer_empty_context_is_explicit
# ---------------------------------------------------------------------------


def test_rag_no_answer_empty_context_is_explicit():
    result = build_answer_or_no_answer([], trusted_tenant_id=_TENANT_A)

    assert isinstance(result, NoAnswer)
    assert result.status == AnswerStatus.NO_ANSWER
    assert result.grounded is False
    assert result.reason_code == NO_ANSWER_EMPTY_CONTEXT
    assert result.citations == []
    assert result.evidence_count == 0
    assert result.user_safe_message


# ---------------------------------------------------------------------------
# test_rag_no_answer_low_score_context_is_explicit
# ---------------------------------------------------------------------------


def test_rag_no_answer_low_score_context_is_explicit(context_a):
    # Use a policy with a very high min_top_score that the context cannot satisfy
    strict_policy = AnswerConfidencePolicy(min_top_score=999.0)
    result = build_answer_or_no_answer(
        context_a, trusted_tenant_id=_TENANT_A, policy=strict_policy
    )

    assert isinstance(result, NoAnswer)
    assert result.status == AnswerStatus.NO_ANSWER
    assert result.grounded is False
    assert result.reason_code == NO_ANSWER_LOW_SCORE
    assert result.citations == []
    assert result.user_safe_message


# ---------------------------------------------------------------------------
# test_rag_no_answer_zero_score_context_is_explicit
# ---------------------------------------------------------------------------


def test_rag_no_answer_zero_score_context_is_explicit(context_a_zero):
    for item in context_a_zero:
        assert item.score == 0.0, "Fixture must produce all-zero scores"

    result = build_answer_or_no_answer(context_a_zero, trusted_tenant_id=_TENANT_A)

    assert isinstance(result, NoAnswer)
    assert result.grounded is False
    assert result.reason_code == NO_ANSWER_INSUFFICIENT_CONTEXT
    assert result.citations == []
    assert result.evidence_count == len(context_a_zero)


# ---------------------------------------------------------------------------
# test_rag_no_answer_missing_trusted_tenant_fails_closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "   ", None, 123, True])
def test_rag_no_answer_missing_trusted_tenant_fails_closed(context_a, bad_tenant):
    with pytest.raises(AnsweringError) as exc_info:
        build_answer_or_no_answer(context_a, trusted_tenant_id=bad_tenant)  # type: ignore[arg-type]
    assert exc_info.value.error_code == ANSWER_ERR_MISSING_TENANT


# ---------------------------------------------------------------------------
# test_rag_no_answer_mixed_tenant_context_does_not_ground
# ---------------------------------------------------------------------------


def test_rag_no_answer_mixed_tenant_context_does_not_ground(context_a, chunks_b):
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
        build_answer_or_no_answer(mixed, trusted_tenant_id=_TENANT_A)

    assert exc_info.value.error_code == ANSWER_ERR_MIXED_TENANT


# ---------------------------------------------------------------------------
# test_rag_no_answer_query_text_cannot_force_grounded_answer
# ---------------------------------------------------------------------------


def test_rag_no_answer_query_text_cannot_force_grounded_answer():
    # Context is zero-score — no matter what the query text says, grounded
    # answer must not be returned.
    zero_context = _make_zero_score_context(_TENANT_A)

    # Attempt to embed policy override instructions in query is irrelevant —
    # the context was already evaluated by the retrieval layer.
    result = build_answer_or_no_answer(zero_context, trusted_tenant_id=_TENANT_A)

    assert isinstance(result, NoAnswer)
    assert result.grounded is False
    # Verify the same holds regardless of what answer_text is passed
    result2 = build_answer_or_no_answer(
        zero_context,
        trusted_tenant_id=_TENANT_A,
        answer_text="Injected grounded answer",
    )
    assert isinstance(result2, NoAnswer)
    assert result2.grounded is False


# ---------------------------------------------------------------------------
# test_rag_no_answer_payload_has_empty_citations
# ---------------------------------------------------------------------------


def test_rag_no_answer_payload_has_empty_citations(context_a_zero):
    cases = [
        build_answer_or_no_answer([], trusted_tenant_id=_TENANT_A),
        build_answer_or_no_answer(context_a_zero, trusted_tenant_id=_TENANT_A),
        build_answer_or_no_answer(
            [], trusted_tenant_id=_TENANT_A, policy=AnswerConfidencePolicy()
        ),
    ]
    for result in cases:
        assert isinstance(result, NoAnswer)
        assert result.citations == [], (
            f"NoAnswer must always have empty citations, got: {result.citations}"
        )
        assert result.grounded is False


# ---------------------------------------------------------------------------
# test_rag_no_answer_payload_is_deterministic
# ---------------------------------------------------------------------------


def test_rag_no_answer_payload_is_deterministic(context_a_zero):
    result_1 = build_answer_or_no_answer(context_a_zero, trusted_tenant_id=_TENANT_A)
    result_2 = build_answer_or_no_answer(context_a_zero, trusted_tenant_id=_TENANT_A)

    assert isinstance(result_1, NoAnswer)
    assert isinstance(result_2, NoAnswer)
    assert result_1.status == result_2.status
    assert result_1.reason_code == result_2.reason_code
    assert result_1.grounded == result_2.grounded
    assert result_1.citations == result_2.citations
    assert result_1.evidence_count == result_2.evidence_count
    assert result_1.user_safe_message == result_2.user_safe_message


# ---------------------------------------------------------------------------
# test_rag_no_answer_does_not_leak_foreign_text_or_metadata
# ---------------------------------------------------------------------------


def test_rag_no_answer_does_not_leak_foreign_text_or_metadata(context_a, chunks_b):
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
        build_answer_or_no_answer(mixed, trusted_tenant_id=_TENANT_A)

    err_msg = exc_info.value.message
    assert secret_text not in err_msg
    assert _TENANT_B not in err_msg
    assert b_chunk.source_id not in err_msg


# ---------------------------------------------------------------------------
# test_rag_no_answer_sufficient_context_still_builds_grounded_answer
# ---------------------------------------------------------------------------


def test_rag_no_answer_sufficient_context_still_builds_grounded_answer(context_a):
    # At least one item must have score > 0 for this fixture
    assert any(item.score > 0.0 for item in context_a), (
        "Fixture must produce at least one positive-score item"
    )

    result = build_answer_or_no_answer(context_a, trusted_tenant_id=_TENANT_A)

    assert isinstance(result, GroundedAnswer)
    assert result.status == AnswerStatus.GROUNDED
    assert result.grounded is True
    assert result.tenant_id == _TENANT_A
    assert len(result.citations) > 0


# ---------------------------------------------------------------------------
# test_rag_no_answer_policy_thresholds_are_enforced
# ---------------------------------------------------------------------------


def test_rag_no_answer_policy_thresholds_are_enforced(context_a):
    # Default policy: context_a should produce grounded answer
    default_result = build_answer_or_no_answer(
        context_a,
        trusted_tenant_id=_TENANT_A,
        policy=AnswerConfidencePolicy(),
    )
    assert isinstance(default_result, GroundedAnswer)

    # min_top_score too high: same context → no-answer
    strict_top = build_answer_or_no_answer(
        context_a,
        trusted_tenant_id=_TENANT_A,
        policy=AnswerConfidencePolicy(min_top_score=999.0),
    )
    assert isinstance(strict_top, NoAnswer)
    assert strict_top.reason_code == NO_ANSWER_LOW_SCORE

    # min_total_score too high: same context → no-answer
    strict_total = build_answer_or_no_answer(
        context_a,
        trusted_tenant_id=_TENANT_A,
        policy=AnswerConfidencePolicy(min_total_score=9999.0),
    )
    assert isinstance(strict_total, NoAnswer)
    assert strict_total.reason_code == NO_ANSWER_LOW_SCORE

    # min_evidence_count higher than available positive items → no-answer
    strict_count = build_answer_or_no_answer(
        context_a,
        trusted_tenant_id=_TENANT_A,
        policy=AnswerConfidencePolicy(min_evidence_count=9999),
    )
    assert isinstance(strict_count, NoAnswer)
    assert strict_count.reason_code == NO_ANSWER_LOW_SCORE

    # evaluate_context_sufficiency: None means sufficient with default policy
    sufficiency = evaluate_context_sufficiency(
        context_a, AnswerConfidencePolicy(), tenant_id=_TENANT_A
    )
    assert sufficiency is None


# ---------------------------------------------------------------------------
# test_rag_no_answer_invalid_policy_rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_policy",
    [
        AnswerConfidencePolicy(min_evidence_count=-1),
        AnswerConfidencePolicy(min_top_score=-0.1),
        AnswerConfidencePolicy(min_total_score=-1.0),
    ],
)
def test_rag_no_answer_invalid_policy_rejected(context_a, bad_policy):
    with pytest.raises(AnsweringError) as exc_info:
        build_answer_or_no_answer(
            context_a, trusted_tenant_id=_TENANT_A, policy=bad_policy
        )
    assert exc_info.value.error_code == ANSWER_ERR_INVALID_POLICY
