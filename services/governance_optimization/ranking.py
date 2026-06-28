"""services/governance_optimization/ranking.py

Core ranking logic for the Governance Optimization Engine.
No I/O during ranking — all data is passed in, all results are returned.
No AI. No LLMs. All computation is deterministic and auditable.

PR 17.6D — Governance Optimization Engine
"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.governance_optimization.models import (
    OptimizationType,
    TargetType,
    classify_optimization_confidence,
    clamp,
    compute_priority_score,
)


@dataclass
class RankedItem:
    target_id: str
    target_type: str
    optimization_type: str
    priority_score: float
    rank: int
    reason: str
    evidence_summary: str
    source_authorities: list[str] = field(default_factory=list)
    source_record_ids: list[str] = field(default_factory=list)
    confidence: str = "INSUFFICIENT"
    sample_size: int = 0


# ---------------------------------------------------------------------------
# rank_recommendations
# ---------------------------------------------------------------------------


def rank_recommendations(
    accuracy_aggregates: list,
) -> list[RankedItem]:
    """Rank recommendation types by calibrated performance.

    Score = compute_priority_score(accuracy_score, avg_health_delta,
                                   avg_effectiveness_delta, failure_rate,
                                   recommendations_executed, deprioritize)
    where deprioritize = (calibrated_confidence == CALIBRATED_LOW and accuracy < 0.25)
    """
    from services.governance_adaptive_intelligence.models import compute_accuracy_score

    items: list[RankedItem] = []

    for agg in accuracy_aggregates:
        executed = agg.recommendations_executed
        successful = agg.recommendations_successful
        failed = agg.recommendations_failed

        accuracy_score = compute_accuracy_score(successful, executed)
        failure_rate = (failed / executed) if executed > 0 else 0.0

        deprioritize = (
            agg.calibrated_confidence == "CALIBRATED_LOW" and accuracy_score < 0.25
        )

        score = compute_priority_score(
            accuracy_score=accuracy_score,
            avg_health_delta=agg.avg_health_delta,
            avg_effectiveness_delta=agg.avg_effectiveness_delta,
            failure_penalty=failure_rate,
            sample_size=executed,
            deprioritize=deprioritize,
        )

        confidence = classify_optimization_confidence(score, executed)
        dep_note = " (deprioritized: consistently low accuracy)" if deprioritize else ""

        reason = (
            f"Recommendation type {agg.recommendation_type} has accuracy score "
            f"{round(accuracy_score * 100, 1)}% over {executed} executions"
            f"{dep_note}."
        )
        evidence_summary = (
            f"executed={executed}, successful={successful}, failed={failed}, "
            f"avg_health_delta={agg.avg_health_delta}, "
            f"avg_effectiveness_delta={agg.avg_effectiveness_delta}, "
            f"calibrated_confidence={agg.calibrated_confidence}"
        )

        items.append(
            RankedItem(
                target_id=agg.recommendation_type,
                target_type=TargetType.RECOMMENDATION.value,
                optimization_type=OptimizationType.RECOMMENDATION_RANKING.value,
                priority_score=round(score, 4),
                rank=0,  # assigned by apply_optimization_context
                reason=reason,
                evidence_summary=evidence_summary,
                source_authorities=["governance_adaptive_intelligence"],
                source_record_ids=[agg.id],
                confidence=confidence.value,
                sample_size=executed,
            )
        )

    return items


# ---------------------------------------------------------------------------
# rank_remediations
# ---------------------------------------------------------------------------


def rank_remediations(
    learning_aggregates: list,
) -> list[RankedItem]:
    """Rank remediation categories by historical success.

    Score = compute_priority_score(success_rate, avg_health_delta,
                                   avg_effectiveness_delta, failure_rate,
                                   total_count, deprioritize=False)
    """
    items: list[RankedItem] = []

    for agg in learning_aggregates:
        total = (
            agg.success_count
            + agg.failure_count
            + agg.partial_success_count
            + agg.no_change_count
        )
        if total == 0:
            success_rate = 0.0
            failure_rate = 0.0
        else:
            success_rate = (agg.success_count + agg.partial_success_count * 0.5) / total
            failure_rate = agg.failure_count / total

        score = compute_priority_score(
            accuracy_score=success_rate,
            avg_health_delta=agg.average_health_delta,
            avg_effectiveness_delta=agg.average_effectiveness_delta,
            failure_penalty=failure_rate,
            sample_size=total,
            deprioritize=False,
        )

        confidence = classify_optimization_confidence(score, total)

        reason = (
            f"Remediation category {agg.remediation_category} has success rate "
            f"{round(success_rate * 100, 1)}% over {total} outcomes."
        )
        evidence_summary = (
            f"total={total}, success={agg.success_count}, "
            f"partial={agg.partial_success_count}, failure={agg.failure_count}, "
            f"no_change={agg.no_change_count}, "
            f"avg_health_delta={agg.average_health_delta}, "
            f"avg_effectiveness_delta={agg.average_effectiveness_delta}"
        )

        items.append(
            RankedItem(
                target_id=agg.remediation_category,
                target_type=TargetType.REMEDIATION.value,
                optimization_type=OptimizationType.REMEDIATION_PRIORITIZATION.value,
                priority_score=round(score, 4),
                rank=0,
                reason=reason,
                evidence_summary=evidence_summary,
                source_authorities=["governance_learning"],
                source_record_ids=[agg.id],
                confidence=confidence.value,
                sample_size=total,
            )
        )

    return items


# ---------------------------------------------------------------------------
# rank_bridges
# ---------------------------------------------------------------------------


def rank_bridges(
    chain_executions: list,
) -> list[RankedItem]:
    """Rank governance chain bridges by health.

    Per bridge: compute success_rate, failure_rate, skip_rate from execution history.
    Score = compute_priority_score(success_rate, None, None, failure_rate, sample_size)
    HIGH SCORE = NEEDS MOST ATTENTION (inverse: high failure rate → high priority).
    Note when bridge has high skip_rate (workflow gap).
    """
    # Group executions by bridge_type
    bridge_stats: dict[str, dict] = {}
    for ex in chain_executions:
        bt = ex.bridge_type
        if bt not in bridge_stats:
            bridge_stats[bt] = {
                "success": 0,
                "failure": 0,
                "skipped": 0,
                "total": 0,
                "ids": [],
            }
        bridge_stats[bt]["total"] += 1
        bridge_stats[bt]["ids"].append(ex.id)

        result = (ex.execution_result or "").upper()
        if result in ("SUCCESS", "COMPLETED"):
            bridge_stats[bt]["success"] += 1
        elif result in ("SKIPPED", "SKIPPED_UNAVAILABLE"):
            bridge_stats[bt]["skipped"] += 1
        else:
            bridge_stats[bt]["failure"] += 1

    items: list[RankedItem] = []

    for bridge_type, stats in bridge_stats.items():
        total = stats["total"]
        success = stats["success"]
        failure = stats["failure"]
        skipped = stats["skipped"]

        if total == 0:
            success_rate = 0.0
            failure_rate = 0.0
            skip_rate = 0.0
        else:
            success_rate = success / total
            failure_rate = failure / total
            skip_rate = skipped / total

        # Bridge scoring: high failure rate = high priority score (needs attention).
        # We invert the success_rate perspective: use failure_rate as the "accuracy"
        # so high failure → high base score → high rank → most attention.
        score = compute_priority_score(
            accuracy_score=failure_rate,
            avg_health_delta=None,
            avg_effectiveness_delta=None,
            failure_penalty=0.0,  # failure_rate already captured in accuracy_score
            sample_size=total,
            deprioritize=False,
        )

        confidence = classify_optimization_confidence(score, total)

        skip_note = ""
        if skip_rate >= 0.3:
            skip_note = (
                f" High skip rate ({round(skip_rate * 100, 1)}%) indicates a "
                "workflow gap — bridge is frequently unavailable."
            )

        reason = (
            f"Bridge {bridge_type} has failure rate {round(failure_rate * 100, 1)}% "
            f"over {total} executions. High score indicates this bridge needs "
            f"the most attention.{skip_note}"
        )
        evidence_summary = (
            f"total={total}, success={success}, failure={failure}, skipped={skipped}, "
            f"success_rate={round(success_rate, 4)}, "
            f"failure_rate={round(failure_rate, 4)}, "
            f"skip_rate={round(skip_rate, 4)}"
        )

        items.append(
            RankedItem(
                target_id=bridge_type,
                target_type=TargetType.BRIDGE.value,
                optimization_type=OptimizationType.BRIDGE_PRIORITIZATION.value,
                priority_score=round(score, 4),
                rank=0,
                reason=reason,
                evidence_summary=evidence_summary,
                source_authorities=["governance_chain"],
                source_record_ids=stats["ids"][:10],  # cap to 10
                confidence=confidence.value,
                sample_size=total,
            )
        )

    return items


# ---------------------------------------------------------------------------
# rank_strategies
# ---------------------------------------------------------------------------


def rank_strategies(
    playbooks: list,
    strategy_profiles: dict,
) -> list[RankedItem]:
    """Rank strategy profiles by playbook performance.

    Match playbooks to strategy profiles by playbook_type.
    Score = playbook.success_rate * 60 + clamp(avg_health_improvement * 2, 0, 40)
    """
    items: list[RankedItem] = []

    for profile_name, _profile_data in strategy_profiles.items():
        # Match playbooks associated with this strategy profile name
        # by checking if the profile name appears in playbook type or using all
        # playbooks as the basis for strategy profile scoring
        matched_playbooks = [
            pb
            for pb in playbooks
            if pb.playbook_type.upper() in profile_name.upper()
            or profile_name.upper() in pb.playbook_type.upper()
        ]

        if not matched_playbooks:
            # Use all playbooks as a fallback aggregate for this profile
            matched_playbooks = playbooks

        if not matched_playbooks:
            score = 0.0
            sample_size = 0
            avg_health = None
            best_success = 0.0
        else:
            total_success = sum(pb.success_rate for pb in matched_playbooks)
            avg_success = total_success / len(matched_playbooks)
            health_vals = [
                pb.avg_health_improvement
                for pb in matched_playbooks
                if pb.avg_health_improvement is not None
            ]
            avg_health = sum(health_vals) / len(health_vals) if health_vals else None
            sample_size = sum(pb.sample_size for pb in matched_playbooks)
            best_success = avg_success

            health_bonus = (
                clamp(avg_health * 2.0, 0.0, 40.0) if avg_health is not None else 0.0
            )
            score = clamp(best_success * 60.0 + health_bonus, 0.0, 100.0)

        confidence = classify_optimization_confidence(score, sample_size)

        reason = (
            f"Strategy profile {profile_name} scored {round(score, 1)} based on "
            f"playbook performance across {len(matched_playbooks)} matched playbook(s)."
        )
        evidence_summary = (
            f"matched_playbooks={len(matched_playbooks)}, "
            f"sample_size={sample_size}, "
            f"avg_health_improvement={avg_health}"
        )

        items.append(
            RankedItem(
                target_id=profile_name,
                target_type=TargetType.STRATEGY.value,
                optimization_type=OptimizationType.STRATEGY_WEIGHTING.value,
                priority_score=round(score, 4),
                rank=0,
                reason=reason,
                evidence_summary=evidence_summary,
                source_authorities=["governance_adaptive_intelligence"],
                source_record_ids=[pb.id for pb in matched_playbooks[:10]],
                confidence=confidence.value,
                sample_size=sample_size,
            )
        )

    return items
