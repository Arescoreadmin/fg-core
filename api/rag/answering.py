"""
RAG Answer Grounding, Citation Contract, and No-Answer Behavior — Tasks 16.4 / 16.6

Transforms tenant-isolated retrieval evidence into grounded answer payloads
with explicit citations, or explicit no-answer payloads when evidence is
insufficient.

No LLM calls. No embeddings. No vector DB. No external services.
Scope: answer contract, citation construction, no-answer behavior, and
confidence-policy-governed assembly.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from api.rag.provenance import ProvenanceReport, build_provenance_report
from api.rag.retrieval import AnswerContextItem, RetrievalResult
from api.rag.safety import assess_context_items, constrain_answer_context

log = logging.getLogger("frostgate.rag.answering")

# ---------------------------------------------------------------------------
# Error codes (stable, never change meaning once published)
# ---------------------------------------------------------------------------

ANSWER_ERR_MISSING_TENANT = "RAG_ANSWER_E001"
ANSWER_ERR_MIXED_TENANT = "RAG_ANSWER_E002"
ANSWER_ERR_CITATION_REQUIRED = "RAG_ANSWER_E003"
ANSWER_ERR_INVALID_CITATION_INPUT = "RAG_ANSWER_E004"
ANSWER_ERR_INVALID_POLICY = "RAG_ANSWER_E005"

# No-answer reason codes (not errors — explicit safe states)
NO_ANSWER_EMPTY_CONTEXT = "RAG_NO_ANSWER_EMPTY_CONTEXT"
NO_ANSWER_INSUFFICIENT_CONTEXT = "RAG_NO_ANSWER_INSUFFICIENT_CONTEXT"
NO_ANSWER_LOW_SCORE = "RAG_NO_ANSWER_LOW_SCORE"
NO_ANSWER_TENANT_MISMATCH = "RAG_NO_ANSWER_TENANT_MISMATCH"
NO_ANSWER_MISSING_TENANT = "RAG_NO_ANSWER_MISSING_TENANT"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CANONICAL_ENCODING = "utf-8"
_EXCERPT_MAX_CHARS = 300  # bounded excerpt length for extractive answers

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AnswerStatus(str, Enum):
    GROUNDED = "grounded"
    NO_ANSWER = "no_answer"


@dataclass(frozen=True)
class CitationReference:
    """Stable, auditable citation pointing to a specific retrieved chunk.

    citation_id is deterministic: SHA-256 of canonical identity fields.
    No unsafe metadata or raw secrets are included.
    """

    citation_id: str  # deterministic SHA-256
    tenant_id: str
    source_id: str
    document_id: str
    chunk_id: str
    chunk_index: int
    parent_content_hash: str
    excerpt: str  # bounded excerpt from chunk text; never exceeds _EXCERPT_MAX_CHARS


@dataclass(frozen=True)
class GroundedAnswer:
    """An answer grounded in retrieved evidence with explicit citations.

    Invariant: citations is always non-empty.
    Invariant: grounded is always True.
    Invariant: all citations belong to tenant_id.
    """

    status: AnswerStatus
    grounded: bool
    tenant_id: str
    answer_text: str
    citations: list[CitationReference]
    evidence_count: int
    safe_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NoAnswer:
    """Explicit, structured no-answer payload.

    Returned when context is empty, low-score, or otherwise insufficient.
    Never contains foreign chunk text or tenant metadata.
    Invariant: grounded is always False.
    Invariant: citations is always empty.
    """

    status: AnswerStatus
    grounded: bool
    reason_code: str
    user_safe_message: str
    citations: list[CitationReference]  # always []
    evidence_count: int = 0  # number of context items evaluated
    tenant_id: str | None = None  # set when trusted tenant is pre-validated


@dataclass(frozen=True)
class AnswerConfidencePolicy:
    """Deterministic, bounded policy governing when to refuse or downgrade answers.

    All fields are immutable. No external calls. No randomness. No timestamps.
    Default values reproduce the pre-policy behavior of assemble_answer_from_context:
    any context with at least one positive-score item passes.

    Fields:
        min_evidence_count: Minimum number of items with score > 0.0 required.
        min_top_score: Top-item score must be strictly greater than this value.
        min_total_score: Sum of all item scores must be strictly greater than this.
        require_citations: Grounded answer must include at least one citation.
    """

    min_evidence_count: int = 1
    min_top_score: float = 0.0
    min_total_score: float = 0.0
    require_citations: bool = True


# Union type for answer assembly result
AnswerAssemblyResult = GroundedAnswer | NoAnswer


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AnsweringError(Exception):
    """Raised for unrecoverable answer assembly failures.

    error_code is always a stable RAG_ANSWER_Exxx constant.
    message MUST NOT contain raw foreign chunk text or tenant-sensitive data.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode(_CANONICAL_ENCODING)).hexdigest()


def _deterministic_citation_id(
    tenant_id: str,
    source_id: str,
    document_id: str,
    chunk_id: str,
    chunk_index: int,
    parent_content_hash: str,
) -> str:
    canonical = json.dumps(
        {
            "chunk_id": chunk_id,
            "chunk_index": chunk_index,
            "document_id": document_id,
            "parent_content_hash": parent_content_hash,
            "source_id": source_id,
            "tenant_id": tenant_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(canonical)


def _make_citation(item: AnswerContextItem) -> CitationReference:
    citation_id = _deterministic_citation_id(
        tenant_id=item.tenant_id,
        source_id=item.source_id,
        document_id=item.document_id,
        chunk_id=item.chunk_id,
        chunk_index=item.chunk_index,
        parent_content_hash=item.parent_content_hash,
    )
    excerpt = item.text[:_EXCERPT_MAX_CHARS]
    return CitationReference(
        citation_id=citation_id,
        tenant_id=item.tenant_id,
        source_id=item.source_id,
        document_id=item.document_id,
        chunk_id=item.chunk_id,
        chunk_index=item.chunk_index,
        parent_content_hash=item.parent_content_hash,
        excerpt=excerpt,
    )


def _require_trusted_tenant(trusted_tenant_id: str) -> str:
    if not isinstance(trusted_tenant_id, str):
        raise AnsweringError(
            ANSWER_ERR_MISSING_TENANT,
            "trusted_tenant_id is required and must not be blank",
        )
    if not trusted_tenant_id.strip():
        raise AnsweringError(
            ANSWER_ERR_MISSING_TENANT,
            "trusted_tenant_id is required and must not be blank",
        )
    return trusted_tenant_id.strip()


def _validate_policy(policy: AnswerConfidencePolicy) -> None:
    """Validate policy field types and bounds. Raises AnsweringError on invalid input."""
    if not isinstance(policy, AnswerConfidencePolicy):
        raise AnsweringError(
            ANSWER_ERR_INVALID_POLICY,
            "policy must be an AnswerConfidencePolicy",
        )

    if not isinstance(policy.min_evidence_count, int) or isinstance(
        policy.min_evidence_count, bool
    ):
        raise AnsweringError(
            ANSWER_ERR_INVALID_POLICY,
            "min_evidence_count must be a non-negative integer",
        )
    if policy.min_evidence_count < 0:
        raise AnsweringError(
            ANSWER_ERR_INVALID_POLICY,
            "min_evidence_count must be >= 0",
        )
    if not isinstance(policy.min_top_score, (int, float)) or isinstance(
        policy.min_top_score, bool
    ):
        raise AnsweringError(
            ANSWER_ERR_INVALID_POLICY,
            "min_top_score must be a non-negative number",
        )
    if policy.min_top_score < 0.0:
        raise AnsweringError(
            ANSWER_ERR_INVALID_POLICY,
            "min_top_score must be >= 0.0",
        )
    if not isinstance(policy.min_total_score, (int, float)) or isinstance(
        policy.min_total_score, bool
    ):
        raise AnsweringError(
            ANSWER_ERR_INVALID_POLICY,
            "min_total_score must be a non-negative number",
        )
    if policy.min_total_score < 0.0:
        raise AnsweringError(
            ANSWER_ERR_INVALID_POLICY,
            "min_total_score must be >= 0.0",
        )


def _check_mixed_tenant(context: list[AnswerContextItem], tenant_id: str) -> None:
    for item in context:
        if item.tenant_id != tenant_id:
            log.warning(
                "rag.answering: mixed-tenant context rejected",
                extra={
                    "trusted_tenant_id": tenant_id,
                    "error_code": ANSWER_ERR_MIXED_TENANT,
                },
            )
            raise AnsweringError(
                ANSWER_ERR_MIXED_TENANT,
                "answer context contains results from a different tenant",
            )


def _extractive_answer(context: list[AnswerContextItem]) -> str:
    """Produce a bounded deterministic extractive answer from top evidence.

    Uses the first context item's text (assumed ordered by score DESC from
    the retrieval layer). Bounded to _EXCERPT_MAX_CHARS characters.
    No LLM calls. No summarization. No fabrication.
    """
    return context[0].text[:_EXCERPT_MAX_CHARS]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assemble_answer_from_context(
    context: list[AnswerContextItem],
    trusted_tenant_id: str,
    answer_text: str | None = None,
) -> AnswerAssemblyResult:
    """Assemble a grounded answer or explicit no-answer from retrieval context.

    Args:
        context: List of AnswerContextItem from prepare_answer_context().
            Must all belong to trusted_tenant_id.
        trusted_tenant_id: Tenant identity from trusted execution context.
            MUST NOT come from context items, query text, or client payload.
        answer_text: Optional caller-supplied answer text. If provided and
            sufficient context exists, it is used verbatim. If omitted,
            an extractive answer is derived from the top context item.

    Returns:
        GroundedAnswer if valid evidence exists (score > 0 on at least one
        item), or NoAnswer if context is empty or all scores are zero.

    Raises:
        AnsweringError: On missing/blank trusted tenant or mixed-tenant input.

    Security invariants:
        - trusted_tenant_id is the only source of tenant authority.
        - Mixed-tenant context raises ANSWER_ERR_MIXED_TENANT.
        - Empty context returns NoAnswer(NO_ANSWER_EMPTY_CONTEXT).
        - All-zero-score context returns NoAnswer(NO_ANSWER_INSUFFICIENT_CONTEXT).
        - Every grounded answer has at least one citation.
        - Citation IDs are deterministic SHA-256 of identity fields.
        - Error messages contain no raw foreign chunk text.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)

    # Guard: mixed-tenant input is an invariant violation
    _check_mixed_tenant(context, tenant_id)

    # Guard: empty context → explicit no-answer
    if not context:
        log.info(
            "rag.answering: no-answer (empty context)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_EMPTY_CONTEXT},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_EMPTY_CONTEXT,
            user_safe_message="No relevant documents were found for your query.",
            citations=[],
            evidence_count=0,
            tenant_id=tenant_id,
        )

    # Guard: low context — all scores are zero → no useful evidence
    if all(item.score == 0.0 for item in context):
        log.info(
            "rag.answering: no-answer (insufficient context)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_INSUFFICIENT_CONTEXT},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_INSUFFICIENT_CONTEXT,
            user_safe_message=(
                "The retrieved documents did not contain sufficient relevant "
                "information to produce a grounded answer."
            ),
            citations=[],
            evidence_count=len(context),
            tenant_id=tenant_id,
        )

    # Build citations from context items in input order (caller is responsible
    # for ordering via the retrieval layer).
    citations = [_make_citation(item) for item in context]

    # Defensive: grounded answer MUST have citations
    if not citations:
        raise AnsweringError(
            ANSWER_ERR_CITATION_REQUIRED,
            "grounded answer requires at least one citation",
        )

    effective_answer = (
        answer_text if answer_text is not None else _extractive_answer(context)
    )

    log.info(
        "rag.answering: grounded answer assembled",
        extra={
            "tenant_id": tenant_id,
            "evidence_count": len(context),
            "citation_count": len(citations),
        },
    )

    return GroundedAnswer(
        status=AnswerStatus.GROUNDED,
        grounded=True,
        tenant_id=tenant_id,
        answer_text=effective_answer,
        citations=citations,
        evidence_count=len(context),
    )


def evaluate_context_sufficiency(
    context: list[AnswerContextItem],
    policy: AnswerConfidencePolicy,
    tenant_id: str | None = None,
) -> NoAnswer | None:
    """Evaluate whether context meets policy thresholds for grounded answer assembly.

    Args:
        context: Tenant-filtered list of AnswerContextItem to evaluate.
        policy: AnswerConfidencePolicy thresholds to enforce.
        tenant_id: Optional pre-validated tenant ID to include in NoAnswer payloads.
            MUST be pre-validated by the caller. MUST NOT be sourced from context items.

    Returns:
        NoAnswer if context is insufficient per policy, or None if context passes
        all thresholds. Never raises for context deficiency — always returns
        a structured NoAnswer payload.

    Raises:
        AnsweringError(ANSWER_ERR_INVALID_POLICY): if policy contains invalid values.

    Determinism invariant: same inputs always produce identical NoAnswer or None.
    No randomness. No external calls. No timestamps.
    """
    _validate_policy(policy)

    if not context:
        log.info(
            "rag.answering: no-answer (empty context)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_EMPTY_CONTEXT},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_EMPTY_CONTEXT,
            user_safe_message="No relevant documents were found for your query.",
            citations=[],
            evidence_count=0,
            tenant_id=tenant_id,
        )

    positive_items = [item for item in context if item.score > 0.0]

    # No items with positive score — no useful evidence at all
    if not positive_items:
        log.info(
            "rag.answering: no-answer (insufficient context — all scores zero)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_INSUFFICIENT_CONTEXT},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_INSUFFICIENT_CONTEXT,
            user_safe_message=(
                "The retrieved documents did not contain sufficient relevant "
                "information to produce a grounded answer."
            ),
            citations=[],
            evidence_count=len(context),
            tenant_id=tenant_id,
        )

    # Fewer positive-score items than policy minimum
    if len(positive_items) < policy.min_evidence_count:
        log.info(
            "rag.answering: no-answer (low score — insufficient positive evidence count)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_LOW_SCORE},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_LOW_SCORE,
            user_safe_message=(
                "Retrieved evidence did not meet the minimum confidence threshold."
            ),
            citations=[],
            evidence_count=len(context),
            tenant_id=tenant_id,
        )

    # Top-item score below policy minimum
    top_score = max(item.score for item in context)
    if top_score <= policy.min_top_score:
        log.info(
            "rag.answering: no-answer (low score — top score below threshold)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_LOW_SCORE},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_LOW_SCORE,
            user_safe_message=(
                "Retrieved evidence did not meet the minimum confidence threshold."
            ),
            citations=[],
            evidence_count=len(context),
            tenant_id=tenant_id,
        )

    # Total score below policy minimum
    total_score = sum(item.score for item in context)
    if total_score <= policy.min_total_score:
        log.info(
            "rag.answering: no-answer (low score — total score below threshold)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_LOW_SCORE},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_LOW_SCORE,
            user_safe_message=(
                "Retrieved evidence did not meet the minimum confidence threshold."
            ),
            citations=[],
            evidence_count=len(context),
            tenant_id=tenant_id,
        )

    return None  # context passes all policy checks


def build_answer_or_no_answer(
    context: list[AnswerContextItem],
    trusted_tenant_id: str,
    policy: AnswerConfidencePolicy | None = None,
    answer_text: str | None = None,
) -> AnswerAssemblyResult:
    """Policy-governed entry point for answer assembly.

    Validates tenant, enforces tenant isolation, evaluates context against the
    confidence policy, and delegates to grounded assembly only when all checks pass.

    Args:
        context: List of AnswerContextItem from prepare_answer_context().
            Must all belong to trusted_tenant_id.
        trusted_tenant_id: Tenant identity from trusted execution context.
            MUST NOT come from context items, query text, or client payload.
        policy: AnswerConfidencePolicy thresholds. Defaults to AnswerConfidencePolicy()
            which reproduces existing assemble_answer_from_context behavior.
        answer_text: Optional caller-supplied answer text.

    Returns:
        GroundedAnswer if context satisfies all policy checks; NoAnswer otherwise.

    Raises:
        AnsweringError(ANSWER_ERR_MISSING_TENANT): invalid/blank/non-string tenant.
        AnsweringError(ANSWER_ERR_MIXED_TENANT): foreign tenant item in context.
        AnsweringError(ANSWER_ERR_INVALID_POLICY): invalid policy field values.

    Security invariants:
        - trusted_tenant_id is the only source of tenant authority.
        - Mixed-tenant context raises before policy evaluation.
        - No-answer payloads do not leak foreign chunk text or tenant metadata.
        - Policy evaluation is deterministic; same inputs always yield same result.
        - Query text cannot override policy or tenant.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)
    _check_mixed_tenant(context, tenant_id)

    # Prompt-injection guard: annotate and zero-score suspicious items.
    # Clean items first so policy evaluation uses the strongest evidence.
    safe_context = constrain_answer_context(context, tenant_id)
    safe_context = sorted(
        safe_context,
        key=lambda item: (
            1
            if item.injection_assessment is not None
            and item.injection_assessment.is_suspicious
            else 0,
            item.score * -1,
        ),
    )

    effective_policy = policy if policy is not None else AnswerConfidencePolicy()
    _validate_policy(effective_policy)

    insufficient = evaluate_context_sufficiency(
        safe_context, effective_policy, tenant_id
    )
    if insufficient is not None:
        return insufficient

    # Context passed all policy checks — assemble grounded answer
    return assemble_answer_from_context(safe_context, trusted_tenant_id, answer_text)


def build_no_answer(
    reason_code: str,
    user_safe_message: str,
    trusted_tenant_id: str | None = None,
) -> NoAnswer:
    """Build an explicit no-answer payload with a stable reason code.

    May be called without trusted_tenant_id for cases where tenant context
    is missing entirely (e.g., upstream validation failure).

    Returns:
        NoAnswer with grounded=False, empty citations, and stable reason_code.
    """
    return NoAnswer(
        status=AnswerStatus.NO_ANSWER,
        grounded=False,
        reason_code=reason_code,
        user_safe_message=user_safe_message,
        citations=[],
    )


def build_answer_with_provenance(
    context: list[AnswerContextItem],
    trusted_tenant_id: str,
    query: str,
    retrieval_results: list[RetrievalResult] | None = None,
    ranked_results: list[RetrievalResult] | None = None,
    policy: AnswerConfidencePolicy | None = None,
    guardrail_report: object | None = None,
    answer_text: str | None = None,
) -> tuple[AnswerAssemblyResult, ProvenanceReport]:
    """Policy-governed answer assembly with deterministic provenance.

    Delegates to build_answer_or_no_answer for all answer logic, then builds
    a read-only ProvenanceReport describing every pipeline stage decision.

    Args:
        context: List of AnswerContextItem from prepare_answer_context().
            Must all belong to trusted_tenant_id.
        trusted_tenant_id: Tenant identity from trusted execution context.
            MUST NOT come from context items, query text, or client payload.
        query: The original query string, included in the provenance report
            for operator audit purposes only.
        retrieval_results: Optional list of RetrievalResult from search_chunks,
            used to populate per-chunk provenance.
        ranked_results: Optional list after re-ranking; falls back to
            retrieval_results if omitted.
        policy: AnswerConfidencePolicy thresholds.
        guardrail_report: Optional RagBudgetReport from guardrail enforcement.
        answer_text: Optional caller-supplied answer text.

    Returns:
        (AnswerAssemblyResult, ProvenanceReport) — both deterministic.

    Raises:
        AnsweringError: Same conditions as build_answer_or_no_answer.

    Security invariants:
        - Provenance is read-only; no pipeline behavior is altered.
        - ProvenanceReport contains no raw document text, no foreign chunk
          IDs, no foreign source IDs, and no foreign tenant metadata.
        - trusted_tenant_id is the only source of tenant authority.
        - Deterministic: same inputs always produce same answer and provenance.
    """
    # Produce the answer using the standard policy-governed path
    answer = build_answer_or_no_answer(context, trusted_tenant_id, policy, answer_text)

    # Aggregate injection assessment over the input context (deterministic)
    injection_assessment = assess_context_items(context) if context else None

    # Build provenance report — purely observational
    provenance = build_provenance_report(
        query=query,
        tenant_id=trusted_tenant_id.strip()
        if isinstance(trusted_tenant_id, str)
        else "",
        retrieval_results=retrieval_results or [],
        ranked_results=ranked_results or [],
        context_items=context,
        answer_result=answer,
        guardrail_report=guardrail_report,  # type: ignore[arg-type]
        injection_assessment=injection_assessment,
    )

    return answer, provenance
