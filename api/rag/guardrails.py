"""
RAG Retrieval Latency and Cost Guardrails — Task 16.9

Deterministic, production-safe guardrails that bound retrieval and answer-assembly
work so oversized requests degrade explicitly instead of silently consuming
unbounded CPU, memory, or future provider cost.

No LLM calls.  No external services.  No network.  No randomness.
Scope: deterministic bounds enforcement and auditable budget reports only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from api.rag.chunking import CorpusChunk
from api.rag.retrieval import AnswerContextItem, RetrievalResult

log = logging.getLogger("frostgate.rag.guardrails")

# ---------------------------------------------------------------------------
# Error codes (stable, never change meaning once published)
# ---------------------------------------------------------------------------

GUARDRAIL_ERR_INVALID_POLICY = "RAG_GUARDRAIL_E001"
GUARDRAIL_ERR_QUERY_TOO_LARGE = "RAG_GUARDRAIL_E002"
GUARDRAIL_ERR_CONTEXT_BUDGET_EXCEEDED = "RAG_GUARDRAIL_E003"
GUARDRAIL_ERR_CANDIDATE_BUDGET_EXCEEDED = "RAG_GUARDRAIL_E004"

# No-answer reason codes for guardrail-triggered degradation
NO_ANSWER_CONTEXT_BUDGET_EXCEEDED = "RAG_NO_ANSWER_CONTEXT_BUDGET_EXCEEDED"
NO_ANSWER_QUERY_TOO_LARGE = "RAG_NO_ANSWER_QUERY_TOO_LARGE"

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RagBudgetPolicy:
    """Deterministic, immutable budget policy for RAG operations.

    All limits are non-negative integers or characters counts.
    Defaults are safe for production use.  Same policy + same input always
    produces the same guardrail outcome.

    Fields:
        max_candidate_chunks: Maximum candidate chunks inspected after
            tenant filter.  Enforced before ranking.
        max_results: Maximum retrieval results returned after ranking.
        max_context_items: Maximum AnswerContextItem objects passed to
            answer assembly.
        max_total_context_chars: Maximum total character count across all
            context item texts.  Character-based proxy for token cost.
        max_query_chars: Maximum query string length accepted.
        max_citation_count: Maximum citations included in a grounded answer.
        max_chunk_chars_inspected: Maximum characters from each chunk
            inspected during scoring.
    """

    max_candidate_chunks: int = 100
    max_results: int = 10
    max_context_items: int = 5
    max_total_context_chars: int = 8000
    max_query_chars: int = 1000
    max_citation_count: int = 5
    max_chunk_chars_inspected: int = 2000


# ---------------------------------------------------------------------------
# Budget report
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RagBudgetReport:
    """Deterministic, auditable record of guardrail enforcement.

    Produced by every apply_* call.  Contains only counts and flags —
    no raw text, no tenant identifiers, no foreign metadata.

    Fields:
        max_candidate_chunks: Policy limit applied to candidate chunks.
        inspected_candidate_count: Candidates presented to the guardrail.
        returned_result_count: Results returned after limit enforcement.
        context_item_count: Context items returned after limit enforcement.
        total_context_chars: Total characters across returned context items.
        truncated: True if any limit caused items to be dropped.
        degraded: True if budget enforcement caused explicit no-answer.
        reason_code: Stable guardrail reason code if degraded, else None.
        policy_name: String identifier for the applied policy.
    """

    max_candidate_chunks: int
    inspected_candidate_count: int
    returned_result_count: int
    context_item_count: int
    total_context_chars: int
    truncated: bool
    degraded: bool
    reason_code: str | None
    policy_name: str = "RagBudgetPolicy"


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class RagGuardrailError(Exception):
    """Raised for invalid policy configuration.

    error_code is always a stable RAG_GUARDRAIL_Exxx constant.
    message MUST NOT contain raw document text or foreign metadata.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------


def _validate_policy(policy: RagBudgetPolicy) -> None:
    """Validate all policy fields. Raises RagGuardrailError on invalid input."""
    if not isinstance(policy, RagBudgetPolicy):
        raise RagGuardrailError(
            GUARDRAIL_ERR_INVALID_POLICY,
            "policy must be a RagBudgetPolicy",
        )

    int_fields = (
        ("max_candidate_chunks", policy.max_candidate_chunks),
        ("max_results", policy.max_results),
        ("max_context_items", policy.max_context_items),
        ("max_total_context_chars", policy.max_total_context_chars),
        ("max_query_chars", policy.max_query_chars),
        ("max_citation_count", policy.max_citation_count),
        ("max_chunk_chars_inspected", policy.max_chunk_chars_inspected),
    )
    for name, value in int_fields:
        if not isinstance(value, int) or isinstance(value, bool):
            raise RagGuardrailError(
                GUARDRAIL_ERR_INVALID_POLICY,
                f"{name} must be a positive integer",
            )
        if value < 1:
            raise RagGuardrailError(
                GUARDRAIL_ERR_INVALID_POLICY,
                f"{name} must be >= 1",
            )


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def estimate_context_cost_chars(items: list[AnswerContextItem]) -> int:
    """Return total character count across all context item texts.

    Deterministic character-based proxy for token cost.
    Same inputs always return the same count.
    No LLM calls, no tokenizer dependency.
    """
    return sum(len(item.text) for item in items)


def validate_query_budget(query_text: str, policy: RagBudgetPolicy) -> None:
    """Validate query length against policy.  Raises RagGuardrailError if exceeded.

    Args:
        query_text: The query string to validate.
        policy: Budget policy to enforce.

    Raises:
        RagGuardrailError(GUARDRAIL_ERR_INVALID_POLICY): invalid policy.
        RagGuardrailError(GUARDRAIL_ERR_QUERY_TOO_LARGE): query exceeds limit.

    Security invariant: error message does not include raw query text.
    """
    _validate_policy(policy)
    if not isinstance(query_text, str):
        return  # non-string handled upstream; safe default here
    if len(query_text) > policy.max_query_chars:
        log.warning(
            "rag.guardrails: query exceeds max_query_chars",
            extra={
                "query_len": len(query_text),
                "max_query_chars": policy.max_query_chars,
            },
        )
        raise RagGuardrailError(
            GUARDRAIL_ERR_QUERY_TOO_LARGE,
            f"query length {len(query_text)} exceeds max_query_chars {policy.max_query_chars}",
        )


def apply_candidate_budget(
    candidates: list[CorpusChunk],
    policy: RagBudgetPolicy | None = None,
) -> tuple[list[CorpusChunk], RagBudgetReport]:
    """Cap tenant-filtered candidates before scoring/ranking.

    This MUST be called after tenant filtering and BEFORE scoring/ranking so
    that the scoring work itself is bounded.  Calling after scoring defeats the
    latency/work-bound contract.

    Args:
        candidates: Tenant-filtered CorpusChunk list — must not contain foreign
            tenant chunks.
        policy: Budget policy to enforce.  Defaults to RagBudgetPolicy().

    Returns:
        (bounded_candidates, RagBudgetReport)

    Raises:
        RagGuardrailError(GUARDRAIL_ERR_INVALID_POLICY): invalid policy.

    Security invariants:
        - Must only receive tenant-filtered candidates.  Never inspect foreign
          chunks — that filtering is the caller's responsibility (e.g. retrieval.py).
        - Candidate order is preserved (deterministic if input is deterministic).
        - truncated=True when candidates are dropped.
        - Deterministic: same inputs + same policy → same output.
    """
    effective_policy = policy if policy is not None else RagBudgetPolicy()
    _validate_policy(effective_policy)

    total = len(candidates)
    bounded = candidates[: effective_policy.max_candidate_chunks]
    truncated = len(bounded) < total

    report = RagBudgetReport(
        max_candidate_chunks=effective_policy.max_candidate_chunks,
        inspected_candidate_count=total,
        returned_result_count=len(bounded),
        context_item_count=0,
        total_context_chars=0,
        truncated=truncated,
        degraded=False,
        reason_code=None,
    )

    if truncated:
        log.info(
            "rag.guardrails: candidate pool truncated by budget",
            extra={
                "total_candidates": total,
                "candidate_limit": effective_policy.max_candidate_chunks,
                "bounded_count": len(bounded),
            },
        )

    return bounded, report


def apply_retrieval_budget(
    results: list[RetrievalResult],
    policy: RagBudgetPolicy | None = None,
    *,
    candidate_count: int | None = None,
) -> tuple[list[RetrievalResult], RagBudgetReport]:
    """Apply candidate and result limits to ranked retrieval results.

    Must be called after tenant filtering and ranking — guardrails never
    inspect or drop foreign-tenant chunks.

    Args:
        results: Already-tenant-filtered, already-ranked RetrievalResult list.
        policy: Budget policy to enforce.  Defaults to RagBudgetPolicy().
        candidate_count: Optional total candidate count before ranking (for
            the budget report).  If None, len(results) is used.

    Returns:
        (bounded_results, RagBudgetReport)

    Raises:
        RagGuardrailError(GUARDRAIL_ERR_INVALID_POLICY): invalid policy.

    Security invariants:
        - No foreign tenant chunks are inspected or returned.
        - Ranking order of retained items is preserved.
        - truncated=True when items are dropped.
        - Deterministic: same inputs + same policy → same output.
    """
    effective_policy = policy if policy is not None else RagBudgetPolicy()
    _validate_policy(effective_policy)

    inspected = len(results) if candidate_count is None else candidate_count

    # Bound candidates first (items already ranked — take from top)
    candidate_bounded = results[: effective_policy.max_candidate_chunks]

    # Then bound returned results
    result_bounded = candidate_bounded[: effective_policy.max_results]

    truncated = len(result_bounded) < len(results)

    report = RagBudgetReport(
        max_candidate_chunks=effective_policy.max_candidate_chunks,
        inspected_candidate_count=inspected,
        returned_result_count=len(result_bounded),
        context_item_count=0,  # not applicable at retrieval stage
        total_context_chars=0,  # not applicable at retrieval stage
        truncated=truncated,
        degraded=False,
        reason_code=None,
    )

    if truncated:
        log.info(
            "rag.guardrails: retrieval results truncated by budget",
            extra={
                "inspected": inspected,
                "candidate_limit": effective_policy.max_candidate_chunks,
                "result_limit": effective_policy.max_results,
                "returned": len(result_bounded),
            },
        )

    return result_bounded, report


def apply_answer_context_budget(
    context_items: list[AnswerContextItem],
    policy: RagBudgetPolicy | None = None,
) -> tuple[list[AnswerContextItem], RagBudgetReport]:
    """Apply item count and total character limits to answer context.

    Must be called after prompt-injection assessment so that injection_assessment
    metadata is preserved on all retained items.

    Args:
        context_items: Context items to bound.  Must already be tenant-filtered
            and injection-assessed.
        policy: Budget policy to enforce.  Defaults to RagBudgetPolicy().

    Returns:
        (bounded_items, RagBudgetReport)

    Raises:
        RagGuardrailError(GUARDRAIL_ERR_INVALID_POLICY): invalid policy.

    Security invariants:
        - injection_assessment on retained items is never cleared.
        - tenant_id of retained items is never altered.
        - truncated=True when items are dropped.
        - Silent truncation never occurs — report always reflects actual state.
        - Deterministic: same inputs + same policy → same output.
    """
    effective_policy = policy if policy is not None else RagBudgetPolicy()
    _validate_policy(effective_policy)

    # Fix 3: effective count cap = min(max_context_items, max_citation_count).
    # Citation cap is binding when it is lower than the context-item cap.
    effective_count_cap = min(
        effective_policy.max_context_items, effective_policy.max_citation_count
    )
    count_bounded = context_items[:effective_count_cap]

    # citation_cap_is_binding: the citation limit (not context-item limit) caused
    # items to be dropped — this constitutes degradation.
    citation_cap_is_binding = (
        effective_policy.max_citation_count < effective_policy.max_context_items
        and len(context_items) > effective_policy.max_citation_count
    )

    # Fix 2: Skip oversized individual items instead of stopping at the first one.
    # Items that exceed the remaining char budget are skipped; later smaller items
    # that fit are retained.  Deterministic order is preserved for retained items.
    char_bounded: list[AnswerContextItem] = []
    running_chars = 0
    char_skipped = 0
    for item in count_bounded:
        item_chars = len(item.text)
        if running_chars + item_chars > effective_policy.max_total_context_chars:
            char_skipped += 1
            continue  # skip this item, keep scanning for smaller ones that fit
        char_bounded.append(item)
        running_chars += item_chars

    total_chars = running_chars
    truncated = len(char_bounded) < len(context_items)
    # degraded when any item was actively skipped (char budget or citation cap)
    degraded = char_skipped > 0 or citation_cap_is_binding

    report = RagBudgetReport(
        max_candidate_chunks=effective_policy.max_candidate_chunks,
        inspected_candidate_count=0,  # not applicable at context stage
        returned_result_count=0,  # not applicable at context stage
        context_item_count=len(char_bounded),
        total_context_chars=total_chars,
        truncated=truncated,
        degraded=degraded,
        reason_code=None,
    )

    if truncated:
        log.info(
            "rag.guardrails: answer context truncated by budget",
            extra={
                "input_count": len(context_items),
                "output_count": len(char_bounded),
                "total_chars": total_chars,
                "char_skipped": char_skipped,
                "citation_cap_is_binding": citation_cap_is_binding,
                "max_context_items": effective_policy.max_context_items,
                "max_citation_count": effective_policy.max_citation_count,
                "max_total_context_chars": effective_policy.max_total_context_chars,
            },
        )

    return char_bounded, report


def build_budget_exceeded_no_answer(
    reason_code: str,
    user_safe_message: str,
    report: RagBudgetReport,
    tenant_id: str | None = None,
) -> tuple[object, RagBudgetReport]:
    """Build a NoAnswer payload for guardrail-triggered budget exhaustion.

    Imports NoAnswer from answering at call time to avoid circular import.
    Returns (NoAnswer, degraded_report).

    Args:
        reason_code: Stable NO_ANSWER_* or GUARDRAIL reason code.
        user_safe_message: Safe user-facing message string.
        report: Budget report from the triggering apply_* call.
        tenant_id: Pre-validated tenant ID for audit context.

    Returns:
        (NoAnswer, RagBudgetReport) with degraded=True on the report.
    """
    # Import here to avoid circular dep (answering imports from retrieval/safety)
    from api.rag.answering import AnswerStatus, NoAnswer  # noqa: PLC0415

    degraded_report = RagBudgetReport(
        max_candidate_chunks=report.max_candidate_chunks,
        inspected_candidate_count=report.inspected_candidate_count,
        returned_result_count=report.returned_result_count,
        context_item_count=report.context_item_count,
        total_context_chars=report.total_context_chars,
        truncated=report.truncated,
        degraded=True,
        reason_code=reason_code,
        policy_name=report.policy_name,
    )

    no_answer = NoAnswer(
        status=AnswerStatus.NO_ANSWER,
        grounded=False,
        reason_code=reason_code,
        user_safe_message=user_safe_message,
        citations=[],
        tenant_id=tenant_id,
    )

    return no_answer, degraded_report
