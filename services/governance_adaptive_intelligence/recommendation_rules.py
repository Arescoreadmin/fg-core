"""services/governance_adaptive_intelligence/recommendation_rules.py

Deterministic adaptive recommendation logic.
Consumes BOTH learning aggregates AND historical accuracy aggregates.
No AI. No LLMs.

PR 17.6C — Governance Adaptive Intelligence Authority
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from services.governance_adaptive_intelligence.models import (
    CalibratedConfidence,
    RecommendationType,
    compute_accuracy_score,
)
from services.governance_adaptive_intelligence.schemas import AdaptiveRecommendation


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _total(agg) -> int:
    """Total outcomes including neutral NO_CHANGE."""
    return (
        agg.success_count
        + agg.failure_count
        + agg.partial_success_count
        + agg.no_change_count
    )


def _success_rate(agg) -> float:
    """Weighted success rate from learning aggregate (includes no_change in denominator)."""
    t = _total(agg)
    if t <= 0:
        return 0.0
    return (agg.success_count + agg.partial_success_count * 0.5) / t


def _accuracy_for_type(
    accuracy_aggregates: list, recommendation_type: str
) -> Optional[object]:
    """Return the accuracy aggregate for a given recommendation_type, or None."""
    for agg in accuracy_aggregates:
        if agg.recommendation_type == recommendation_type:
            return agg
    return None


def generate_adaptive_recommendations(
    aggregates: list,
    accuracy_aggregates: list,
    total_records: int,
    avg_health_delta_30d: Optional[float],
) -> list[AdaptiveRecommendation]:
    """Generate deterministic adaptive recommendations.

    Rules (applied in order):
    1. PRIORITIZE_BEST_CATEGORY — category with highest success rate.
       Only recommended if its accuracy_aggregate shows accuracy_score >= 0.5
       OR no history yet (accuracy_aggregate absent).
    2. ESCALATE_WORST_CATEGORY — category with lowest success rate.
       Deprioritized (should_deprioritize=True) if accuracy shows it repeatedly
       fails to improve (accuracy_score < 0.25). Still emitted, caller decides.
    3. GOVERNANCE_REVIEW — if avg_health_delta_30d < -2.0.
    4. IMPROVE_EFFECTIVENESS — if any category avg_effectiveness_delta < -5.0.
    5. IMPROVE_VERIFICATION  — if any category avg_verification_delta < -5.0.
    """
    recs: list[AdaptiveRecommendation] = []
    now = _now_iso()

    if not aggregates:
        return recs

    # Sort by success rate
    sorted_aggs = sorted(aggregates, key=_success_rate, reverse=True)
    best = sorted_aggs[0]
    worst = sorted_aggs[-1]

    # --- Rule 1: PRIORITIZE_BEST_CATEGORY ---
    best_acc = _accuracy_for_type(
        accuracy_aggregates, RecommendationType.PRIORITIZE_BEST_CATEGORY.value
    )
    if best_acc is not None:
        acc_score = compute_accuracy_score(
            best_acc.recommendations_successful, best_acc.recommendations_executed
        )
        skip_best = acc_score < 0.5
        hist_sr: Optional[float] = acc_score
    else:
        skip_best = False
        hist_sr = None

    if not skip_best:
        sr = _success_rate(best)
        total_best = _total(best)
        recs.append(
            AdaptiveRecommendation(
                recommendation_id=_new_id(),
                type=RecommendationType.PRIORITIZE_BEST_CATEGORY.value,
                category=best.remediation_category,
                reason=(
                    f"{best.remediation_category} has the highest success rate of "
                    f"{round(sr * 100, 1)}% across {total_best} outcomes. "
                    "Prioritize this remediation approach."
                ),
                confidence=best.confidence,
                expected_health_delta=best.average_health_delta,
                historical_success_rate=hist_sr,
                should_deprioritize=False,
                supporting_outcome_count=total_best,
                generated_at=now,
            )
        )

    # --- Rule 2: ESCALATE_WORST_CATEGORY ---
    worst_acc = _accuracy_for_type(
        accuracy_aggregates, RecommendationType.ESCALATE_WORST_CATEGORY.value
    )
    if worst_acc is not None:
        worst_acc_score = compute_accuracy_score(
            worst_acc.recommendations_successful, worst_acc.recommendations_executed
        )
        should_deprioritize = worst_acc_score < 0.25
        worst_hist_sr: Optional[float] = worst_acc_score
    else:
        should_deprioritize = False
        worst_hist_sr = None

    sr_worst = _success_rate(worst)
    total_worst = _total(worst)
    recs.append(
        AdaptiveRecommendation(
            recommendation_id=_new_id(),
            type=RecommendationType.ESCALATE_WORST_CATEGORY.value,
            category=worst.remediation_category,
            reason=(
                f"{worst.remediation_category} has the lowest success rate of "
                f"{round(sr_worst * 100, 1)}% across {total_worst} outcomes. "
                "Consider escalating or reviewing this remediation category."
            ),
            confidence=worst.confidence,
            expected_health_delta=worst.average_health_delta,
            historical_success_rate=worst_hist_sr,
            should_deprioritize=should_deprioritize,
            supporting_outcome_count=total_worst,
            generated_at=now,
        )
    )

    # --- Rule 3: GOVERNANCE_REVIEW ---
    if avg_health_delta_30d is not None and avg_health_delta_30d < -2.0:
        recs.append(
            AdaptiveRecommendation(
                recommendation_id=_new_id(),
                type=RecommendationType.GOVERNANCE_REVIEW.value,
                category=None,
                reason=(
                    f"Governance health is declining "
                    f"(avg 30d health delta = {avg_health_delta_30d:.2f}). "
                    "A full governance review is recommended."
                ),
                confidence=CalibratedConfidence.CALIBRATED_MEDIUM.value,
                expected_health_delta=avg_health_delta_30d,
                historical_success_rate=None,
                should_deprioritize=False,
                supporting_outcome_count=total_records,
                generated_at=now,
            )
        )

    # --- Rule 4: IMPROVE_EFFECTIVENESS ---
    for agg in aggregates:
        if (
            agg.average_effectiveness_delta is not None
            and agg.average_effectiveness_delta < -5.0
        ):
            recs.append(
                AdaptiveRecommendation(
                    recommendation_id=_new_id(),
                    type=RecommendationType.IMPROVE_EFFECTIVENESS.value,
                    category=agg.remediation_category,
                    reason=(
                        f"{agg.remediation_category} shows declining effectiveness "
                        f"(avg delta = {agg.average_effectiveness_delta:.2f}). "
                        "Focus on improving control effectiveness."
                    ),
                    confidence=agg.confidence,
                    expected_health_delta=agg.average_health_delta,
                    historical_success_rate=None,
                    should_deprioritize=False,
                    supporting_outcome_count=_total(agg),
                    generated_at=now,
                )
            )
            break  # one recommendation per rule

    # --- Rule 5: IMPROVE_VERIFICATION ---
    for agg in aggregates:
        if (
            agg.average_verification_delta is not None
            and agg.average_verification_delta < -5.0
        ):
            recs.append(
                AdaptiveRecommendation(
                    recommendation_id=_new_id(),
                    type=RecommendationType.IMPROVE_VERIFICATION.value,
                    category=agg.remediation_category,
                    reason=(
                        f"{agg.remediation_category} shows declining verification "
                        f"(avg delta = {agg.average_verification_delta:.2f}). "
                        "Improve verification coverage."
                    ),
                    confidence=agg.confidence,
                    expected_health_delta=agg.average_health_delta,
                    historical_success_rate=None,
                    should_deprioritize=False,
                    supporting_outcome_count=_total(agg),
                    generated_at=now,
                )
            )
            break  # one recommendation per rule

    return recs
