"""
RAG Operator / Debug Answer Provenance — Task 16.10

Deterministic, tenant-safe, read-only provenance surface.
Explains exactly how an answer or no-answer was produced: which chunks were
retrieved, ranked, selected, excluded, flagged, or budget-truncated.

No LLM calls.  No external services.  No network.  No randomness.
Scope: observational only — does not modify retrieval, ranking, answering,
safety, guardrails, lifecycle, chunking, or ingestion.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from api.rag.guardrails import RagBudgetReport
from api.rag.retrieval import AnswerContextItem, RetrievalResult
from api.rag.safety import assess_prompt_injection

log = logging.getLogger("frostgate.rag.provenance")

# ---------------------------------------------------------------------------
# Stable exclusion reason codes (never change meaning once published)
# ---------------------------------------------------------------------------

EXCLUSION_FILTERED_OUT = "filtered_out"
EXCLUSION_LOW_SCORE = "low_score"
EXCLUSION_BUDGET_EXCEEDED = "budget_exceeded"
EXCLUSION_INJECTION_FLAGGED = "injection_flagged"
EXCLUSION_NOT_SELECTED = "not_selected"

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProvenanceChunk:
    """Per-chunk provenance record.

    Contains only chunk identity and score metadata — no raw document text,
    no foreign tenant data.
    """

    chunk_id: str
    source_id: str
    score: float
    rank: int  # 1-based position in ranked output; 0 if not ranked
    included_in_answer: bool
    exclusion_reason: str | None  # one of EXCLUSION_* constants, or None


@dataclass(frozen=True)
class ProvenanceReport:
    """Deterministic, tenant-safe provenance report for a single RAG pipeline run.

    Records every pipeline stage decision for a single query without exposing
    raw document text, secrets, or foreign tenant data.

    Fields:
        tenant_id: Trusted tenant this report belongs to.
        query: The query string that drove retrieval.
        retrieved_count: Number of chunks returned by retrieval.
        ranked_count: Number of chunks after ranking.
        context_count: Number of items passed to answer assembly.
        chunks: Per-chunk provenance, in rank order.
        answer_status: "grounded" or "no_answer".
        no_answer_reason: Stable reason code if answer_status="no_answer", else None.
        injection_detected: True if any context item triggered injection detection.
        guardrail_applied: True if any guardrail limit caused truncation or degradation.
        truncated: True if any item was dropped by a guardrail.
        degraded: True if budget degradation produced an explicit no-answer.
    """

    tenant_id: str
    query: str

    retrieved_count: int
    ranked_count: int
    context_count: int

    chunks: tuple[ProvenanceChunk, ...]  # frozen; tuple preserves immutability contract

    answer_status: str  # "grounded" | "no_answer"
    no_answer_reason: str | None

    injection_detected: bool
    guardrail_applied: bool

    truncated: bool
    degraded: bool


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_provenance_report(
    query: str,
    tenant_id: str,
    retrieval_results: list[RetrievalResult],
    ranked_results: list[RetrievalResult],
    context_items: list[AnswerContextItem],
    answer_result: Any,
    guardrail_report: RagBudgetReport | None = None,
    injection_assessment: Any | None = None,
) -> ProvenanceReport:
    """Build a deterministic, tenant-safe provenance report.

    Observational only — does not modify any pipeline object.

    Args:
        query: The original query string (operator-visible; not a secret).
        tenant_id: Pre-validated trusted tenant ID.  Must not be sourced from
            document content.
        retrieval_results: Tenant-filtered RetrievalResult list from search_chunks.
        ranked_results: Results after ranking (may equal retrieval_results).
            If empty, retrieval_results is used as the canonical ranked order.
        context_items: AnswerContextItem list passed to answer assembly
            (after guardrails / injection assessment).
        answer_result: GroundedAnswer or NoAnswer from build_answer_or_no_answer.
        guardrail_report: Optional RagBudgetReport from guardrail enforcement.
        injection_assessment: Optional aggregate PromptInjectionAssessment.

    Returns:
        ProvenanceReport — deterministic, same inputs always produce same output.

    Security invariants:
        - No raw document text in the report.
        - No foreign tenant chunk_id, source_id, or metadata.
        - tenant_id is the only source of tenant authority.
        - Deterministic: no timestamps, no randomness, no UUIDs.
    """
    # Canonical ranked order: prefer ranked_results if non-empty.
    # Fix 2: filter to trusted tenant before building any index — foreign chunks
    # must not influence rank_map, ranked_chunk_ids, or context lookups.
    _raw_ranked = ranked_results if ranked_results else retrieval_results
    canonical_ranked = [
        r for r in _raw_ranked if getattr(r, "tenant_id", tenant_id) == tenant_id
    ]
    context_items = [
        c for c in context_items if getattr(c, "tenant_id", tenant_id) == tenant_id
    ]

    # Build lookup sets for O(1) membership tests
    ranked_chunk_ids: set[str] = {r.chunk_id for r in canonical_ranked}
    context_chunk_ids: set[str] = {c.chunk_id for c in context_items}

    # Rank map: chunk_id → (1-based rank, score from ranked order)
    rank_map: dict[str, tuple[int, float]] = {
        r.chunk_id: (i + 1, r.score) for i, r in enumerate(canonical_ranked)
    }

    # Injection-flagged items: check items in context using injection_assessment
    # field (set by constrain_answer_context) or by independently assessing text.
    # Both paths are deterministic.
    injection_flagged_ids: set[str] = set()
    for c in context_items:
        is_flagged = False
        if c.injection_assessment is not None:
            is_flagged = c.injection_assessment.is_suspicious
        else:
            # Assess independently — consistent with the internal pipeline
            a = assess_prompt_injection(c.text)
            is_flagged = a.is_suspicious
        if is_flagged:
            injection_flagged_ids.add(c.chunk_id)

    # Citations from GroundedAnswer (empty list for NoAnswer)
    citations = getattr(answer_result, "citations", None) or []
    cited_chunk_ids: set[str] = {cit.chunk_id for cit in citations}

    # Answer status — AnswerStatus is a str Enum so direct string comparison works
    answer_status_val = getattr(answer_result, "status", None)
    answer_status = (
        str(answer_status_val.value) if answer_status_val is not None else "no_answer"
    )
    no_answer_reason: str | None = getattr(answer_result, "reason_code", None)

    # Guardrail state
    guardrail_applied = guardrail_report is not None and (
        guardrail_report.truncated or guardrail_report.degraded
    )
    truncated = guardrail_report.truncated if guardrail_report is not None else False
    degraded = guardrail_report.degraded if guardrail_report is not None else False

    # Injection detected: from aggregate assessment or from flagged items
    agg_injection = injection_assessment is not None and getattr(
        injection_assessment, "is_suspicious", False
    )
    injection_detected = agg_injection or len(injection_flagged_ids) > 0

    # Build per-chunk provenance for every retrieved result.
    # Fix 2: skip foreign-tenant results entirely — never emit, never log.
    prov_chunks: list[ProvenanceChunk] = []
    for i, result in enumerate(retrieval_results):
        # Tenant guard: foreign chunks must not appear in this tenant's provenance.
        if getattr(result, "tenant_id", tenant_id) != tenant_id:
            continue

        chunk_id = result.chunk_id

        if chunk_id in rank_map:
            rank, score = rank_map[chunk_id]
        else:
            rank = 0  # not in ranked output
            score = result.score

        # Determine inclusion and exclusion reason.
        # Fix 1: citations always win — if a chunk is in the answer citations it is
        # included regardless of injection signal.  Provenance = what happened.
        if chunk_id in context_chunk_ids:
            if chunk_id in cited_chunk_ids:
                # Cited chunks are included; injection_detected flag at report level
                # preserves the signal without contradicting reality.
                included = True
                reason: str | None = None
            elif chunk_id in injection_flagged_ids:
                included = False
                reason = EXCLUSION_INJECTION_FLAGGED
            else:
                # In context but not cited: either no_answer or zero-score
                included = False
                reason = EXCLUSION_LOW_SCORE
        elif chunk_id in ranked_chunk_ids:
            included = False
            if guardrail_report is not None and guardrail_report.truncated:
                reason = EXCLUSION_BUDGET_EXCEEDED
            else:
                reason = EXCLUSION_NOT_SELECTED
        else:
            included = False
            reason = EXCLUSION_FILTERED_OUT

        prov_chunks.append(
            ProvenanceChunk(
                chunk_id=chunk_id,
                source_id=result.source_id,
                score=score,
                rank=rank,
                included_in_answer=included,
                exclusion_reason=reason,
            )
        )

    # Sort deterministically: rank ASC (0-rank items last), then chunk_id ASC
    prov_chunks.sort(key=lambda c: (c.rank if c.rank > 0 else 999999, c.chunk_id))

    log.debug(
        "rag.provenance: report built",
        extra={
            "tenant_id": tenant_id,
            "retrieved_count": len(retrieval_results),
            "ranked_count": len(canonical_ranked),
            "context_count": len(context_items),
            "answer_status": answer_status,
            "injection_detected": injection_detected,
            "guardrail_applied": guardrail_applied,
        },
    )

    return ProvenanceReport(
        tenant_id=tenant_id,
        query=query,
        retrieved_count=len(retrieval_results),
        ranked_count=len(canonical_ranked),
        context_count=len(context_items),
        chunks=tuple(prov_chunks),
        answer_status=answer_status,
        no_answer_reason=no_answer_reason,
        injection_detected=injection_detected,
        guardrail_applied=guardrail_applied,
        truncated=truncated,
        degraded=degraded,
    )
