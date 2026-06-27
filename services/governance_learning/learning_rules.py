"""services/governance_learning/learning_rules.py

Deterministic recommendation logic. No AI. No LLMs.
All recommendations are derived from aggregate statistics only.

PR 17.6B — Governance Learning Loop Authority
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from services.governance_learning.models import ConfidenceLevel
from services.governance_learning.schemas import GovernanceRecommendation


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _success_rate(agg) -> float:
    """Weighted success rate: success=1.0, partial=0.5, failure=0."""
    total = agg.success_count + agg.failure_count + agg.partial_success_count
    if total <= 0:
        return 0.0
    return (agg.success_count + agg.partial_success_count * 0.5) / total


def _failure_rate(agg) -> float:
    """Failure rate: failures / total."""
    total = agg.success_count + agg.failure_count + agg.partial_success_count
    if total <= 0:
        return 0.0
    return agg.failure_count / total


def generate_recommendations(
    aggregates: list,
    total_records: int,
    avg_health_delta_30d: Optional[float],
) -> list[GovernanceRecommendation]:
    """Generate deterministic governance recommendations from learning aggregates.

    Rules applied (in order):
    1. If no aggregates: recommend collecting more data.
    2. Best category (highest success rate ≥ 0.6): PRIORITIZE_REMEDIATION_CATEGORY.
    3. Worst category (failure rate ≥ 0.5 and ≥3 total): ESCALATE_OR_REVIEW.
    4. Declining health (avg_health_delta_30d < -3): GOVERNANCE_REVIEW.
    """
    recs: list[GovernanceRecommendation] = []

    if not aggregates:
        recs.append(
            GovernanceRecommendation(
                recommendation_id=_new_id(),
                recommended_next_action="COLLECT_MORE_OUTCOME_DATA",
                recommended_remediation_category=None,
                recommended_control_focus=None,
                recommendation_reason=(
                    "Insufficient outcome history to generate evidence-based recommendations"
                ),
                recommendation_confidence=ConfidenceLevel.UNKNOWN.value,
                evidence_summary="0 outcomes recorded",
                supporting_outcome_count=0,
                expected_health_delta=None,
                generated_at=_now_iso(),
            )
        )
        return recs

    # Sort aggregates by success_rate descending
    sorted_aggs = sorted(aggregates, key=_success_rate, reverse=True)

    # Rec 1: Most reliable remediation category
    best = sorted_aggs[0]
    sr = _success_rate(best)
    if sr >= 0.6:
        total_best = (
            best.success_count + best.failure_count + best.partial_success_count
        )
        recs.append(
            GovernanceRecommendation(
                recommendation_id=_new_id(),
                recommended_next_action="PRIORITIZE_REMEDIATION_CATEGORY",
                recommended_remediation_category=best.remediation_category,
                recommended_control_focus=None,
                recommendation_reason=(
                    f"{best.remediation_category} has the highest success rate of "
                    f"{round(sr * 100, 1)}% across {total_best} outcomes"
                ),
                recommendation_confidence=best.confidence,
                evidence_summary=(
                    f"success={best.success_count} partial={best.partial_success_count} "
                    f"fail={best.failure_count} avg_health_delta={best.average_health_delta}"
                ),
                supporting_outcome_count=total_best,
                expected_health_delta=best.average_health_delta,
                generated_at=_now_iso(),
            )
        )

    # Rec 2: Avoid worst category if high failure rate
    worst = sorted_aggs[-1]
    fr = _failure_rate(worst)
    total_worst = (
        worst.success_count + worst.failure_count + worst.partial_success_count
    )
    if fr >= 0.5 and total_worst >= 3:
        recs.append(
            GovernanceRecommendation(
                recommendation_id=_new_id(),
                recommended_next_action="ESCALATE_OR_REVIEW",
                recommended_remediation_category=worst.remediation_category,
                recommended_control_focus=None,
                recommendation_reason=(
                    f"{worst.remediation_category} has a high failure rate of "
                    f"{round(fr * 100, 1)}% — escalation or alternative approach recommended"
                ),
                recommendation_confidence=worst.confidence,
                evidence_summary=(
                    f"success={worst.success_count} partial={worst.partial_success_count} "
                    f"fail={worst.failure_count}"
                ),
                supporting_outcome_count=worst.failure_count + worst.success_count,
                expected_health_delta=worst.average_health_delta,
                generated_at=_now_iso(),
            )
        )

    # Rec 3: Declining health overall
    if avg_health_delta_30d is not None and avg_health_delta_30d < -3.0:
        recs.append(
            GovernanceRecommendation(
                recommendation_id=_new_id(),
                recommended_next_action="GOVERNANCE_REVIEW",
                recommended_remediation_category=None,
                recommended_control_focus=None,
                recommendation_reason=(
                    f"Governance health is declining "
                    f"(avg 30d delta = {avg_health_delta_30d:.1f}) — "
                    "a full governance review is recommended"
                ),
                recommendation_confidence=ConfidenceLevel.MEDIUM.value,
                evidence_summary=(
                    f"avg_health_delta_30d={avg_health_delta_30d:.2f} "
                    f"total_records={total_records}"
                ),
                supporting_outcome_count=total_records,
                expected_health_delta=None,
                generated_at=_now_iso(),
            )
        )

    return recs
