"""services/governance_optimization/engine.py

Governance Optimization Engine.

Produces:
  - Recommendation ranking by calibrated accuracy
  - Remediation prioritization by historical success
  - Bridge prioritization by execution failure rate
  - Strategy weighting by playbook performance
  - Dashboard summary and aggregate views
  - CGIN anonymized benchmark snapshot

Cross-authority data access: imports ORM models directly from other authority
DB modules to avoid circular dependencies (never instantiates other engines).

No AI. No LLMs. All computation is deterministic and auditable.

PR 17.6D — Governance Optimization Engine
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_governance_optimization import (
    FaGovernanceOptimizationDecision,
    FaGovernanceOptimizationSnapshot,
)
from services.governance_optimization import ranking as ranking_module
from services.governance_optimization.models import (
    GOVERNANCE_OPTIMIZATION_VERSION,
    OptimizationType,
    TargetType,
    classify_optimization_confidence,
)
from services.governance_optimization.optimization_rules import (
    apply_optimization_context,
    should_surface_as_optimization_target,
)
from services.governance_optimization.ranking import RankedItem
from services.governance_optimization.repository import GovernanceOptimizationRepository
from services.governance_optimization.schemas import (
    CGINOptimizationSnapshot,
    OptimizationAggregateResponse,
    OptimizationDashboardResponse,
    OptimizationDecisionResponse,
    OptimizationSnapshotResponse,
)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _avg(values: list[float]) -> Optional[float]:
    if not values:
        return None
    return round(sum(values) / len(values), 4)


class GovernanceOptimizationEngine:
    """Derives optimization rankings and prioritization from governance authority data."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = GovernanceOptimizationRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Internal: persist a single ranked item as a decision row
    # ------------------------------------------------------------------

    def _persist_decision(
        self, item: RankedItem, optimization_id: str
    ) -> FaGovernanceOptimizationDecision:
        row = FaGovernanceOptimizationDecision(
            id=_new_id(),
            tenant_id=self._tenant_id,
            optimization_id=optimization_id,
            optimization_type=item.optimization_type,
            target_type=item.target_type,
            target_id=item.target_id,
            priority_score=item.priority_score,
            rank=item.rank,
            reason=item.reason,
            evidence_summary=item.evidence_summary,
            source_authorities=json.dumps(item.source_authorities),
            source_record_ids=json.dumps(item.source_record_ids),
            confidence=item.confidence,
            created_at=_now_iso(),
        )
        self._repo.create_decision(row)
        return row

    # ------------------------------------------------------------------
    # Internal: update aggregate for a ranked item
    # ------------------------------------------------------------------

    def _update_aggregate(self, item: RankedItem) -> None:
        now = _now_iso()
        existing = self._repo.get_aggregate(
            item.target_type, item.target_id, item.optimization_type
        )
        if existing is None:
            updates = {
                "times_ranked": 1,
                "average_priority_score": item.priority_score,
                "latest_priority_score": item.priority_score,
                "highest_priority_score": item.priority_score,
                "lowest_priority_score": item.priority_score,
                "average_health_lift": None,
                "average_effectiveness_lift": None,
                "average_confidence": None,
                "last_ranked_at": now,
            }
        else:
            n = existing.times_ranked + 1
            prev_avg = existing.average_priority_score or 0.0
            new_avg = round((prev_avg * existing.times_ranked + item.priority_score) / n, 4)
            highest = max(existing.highest_priority_score or item.priority_score, item.priority_score)
            lowest = min(existing.lowest_priority_score or item.priority_score, item.priority_score)
            updates = {
                "times_ranked": n,
                "average_priority_score": new_avg,
                "latest_priority_score": item.priority_score,
                "highest_priority_score": highest,
                "lowest_priority_score": lowest,
                "last_ranked_at": now,
            }
        self._repo.upsert_aggregate(
            target_type=item.target_type,
            target_id=item.target_id,
            optimization_type=item.optimization_type,
            updates=updates,
        )

    # ------------------------------------------------------------------
    # Internal: create snapshot after a ranking run
    # ------------------------------------------------------------------

    def _create_snapshot(
        self,
        snapshot_type: str,
        ranked_items: list[RankedItem],
    ) -> None:
        now = _now_iso()
        total = len(ranked_items)
        top = ranked_items[0] if ranked_items else None
        avg_score = _avg([i.priority_score for i in ranked_items])

        if total == 0:
            opt_confidence = "INSUFFICIENT"
        else:
            opt_confidence = classify_optimization_confidence(
                avg_score or 0.0, total
            ).value

        row = FaGovernanceOptimizationSnapshot(
            id=_new_id(),
            tenant_id=self._tenant_id,
            snapshot_type=snapshot_type,
            total_items_ranked=total,
            top_priority_target_id=top.target_id if top else None,
            top_priority_score=top.priority_score if top else None,
            average_priority_score=avg_score,
            optimization_confidence=opt_confidence,
            generated_at=now,
        )
        self._repo.create_snapshot(row)

    # ------------------------------------------------------------------
    # Internal: convert RankedItem list → response list, optionally persisting
    # ------------------------------------------------------------------

    def _finalize_ranking(
        self,
        raw_items: list[RankedItem],
        optimization_type: str,
        snapshot_type: str,
        persist: bool,
    ) -> list[OptimizationDecisionResponse]:
        # Filter and sort
        surfaced = [
            item
            for item in raw_items
            if should_surface_as_optimization_target(
                item.target_type, item.priority_score, 1
            )
        ]
        ranked = apply_optimization_context(surfaced, optimization_type)

        if persist and ranked:
            optimization_id = _new_id()
            for item in ranked:
                self._persist_decision(item, optimization_id)
                self._update_aggregate(item)
            self._create_snapshot(snapshot_type, ranked)
            self._db.commit()

        return [_decision_row_to_response_from_item(item, self._tenant_id) for item in ranked]

    # ------------------------------------------------------------------
    # Public: rank recommendations
    # ------------------------------------------------------------------

    def rank_recommendations(
        self, persist: bool = True
    ) -> list[OptimizationDecisionResponse]:
        """Rank recommendation types by calibrated performance from GAI accuracy aggregates."""
        from api.db_models_governance_adaptive_intelligence import (
            FaGovernanceAccuracyAggregate,
        )

        aggs = (
            self._db.query(FaGovernanceAccuracyAggregate)
            .filter(FaGovernanceAccuracyAggregate.tenant_id == self._tenant_id)
            .all()
        )
        raw = ranking_module.rank_recommendations(aggs)
        return self._finalize_ranking(
            raw,
            OptimizationType.RECOMMENDATION_RANKING.value,
            OptimizationType.RECOMMENDATION_RANKING.value,
            persist,
        )

    # ------------------------------------------------------------------
    # Public: rank controls (placeholder)
    # ------------------------------------------------------------------

    def rank_controls(self, persist: bool = True) -> list[OptimizationDecisionResponse]:
        """Rank controls by effectiveness score (graceful degradation if data absent)."""
        controls = []
        try:
            from api.db_models_control_effectiveness import FaControlEffectiveness

            controls = (
                self._db.query(FaControlEffectiveness)
                .filter(FaControlEffectiveness.tenant_id == self._tenant_id)
                .all()
            )
        except Exception:
            controls = []

        if not controls:
            return []

        # Build ranked items from control effectiveness rows (lower score = higher priority)
        from services.governance_optimization.ranking import RankedItem
        from services.governance_optimization.models import (
            classify_optimization_confidence,
            clamp,
        )

        items = []
        for ctrl in controls:
            eff_score = getattr(ctrl, "effectiveness_score", None) or 0.0
            # Lower effectiveness = higher priority (needs more attention)
            priority_score = clamp((1.0 - eff_score) * 60.0, 0.0, 100.0)
            sample_size = 1
            confidence = classify_optimization_confidence(priority_score, sample_size)
            items.append(
                RankedItem(
                    target_id=getattr(ctrl, "control_id", ctrl.id),
                    target_type=TargetType.CONTROL.value,
                    optimization_type=OptimizationType.CONTROL_PRIORITIZATION.value,
                    priority_score=round(priority_score, 4),
                    rank=0,
                    reason=(
                        f"Control has effectiveness score {round(eff_score * 100, 1)}%. "
                        "Lower effectiveness = higher optimization priority."
                    ),
                    evidence_summary=f"effectiveness_score={eff_score}",
                    source_authorities=["control_effectiveness"],
                    source_record_ids=[ctrl.id],
                    confidence=confidence.value,
                )
            )

        return self._finalize_ranking(
            items,
            OptimizationType.CONTROL_PRIORITIZATION.value,
            OptimizationType.CONTROL_PRIORITIZATION.value,
            persist,
        )

    # ------------------------------------------------------------------
    # Public: rank remediations
    # ------------------------------------------------------------------

    def rank_remediations(
        self, persist: bool = True
    ) -> list[OptimizationDecisionResponse]:
        """Rank remediation categories by historical success from learning aggregates."""
        from api.db_models_governance_learning import FaGovernanceLearningAggregate

        aggs = (
            self._db.query(FaGovernanceLearningAggregate)
            .filter(FaGovernanceLearningAggregate.tenant_id == self._tenant_id)
            .all()
        )
        raw = ranking_module.rank_remediations(aggs)
        return self._finalize_ranking(
            raw,
            OptimizationType.REMEDIATION_PRIORITIZATION.value,
            OptimizationType.REMEDIATION_PRIORITIZATION.value,
            persist,
        )

    # ------------------------------------------------------------------
    # Public: rank bridges
    # ------------------------------------------------------------------

    def rank_bridges(self, persist: bool = True) -> list[OptimizationDecisionResponse]:
        """Rank governance chain bridges by execution failure rate."""
        from api.db_models_governance_chain import FaGovernanceChainExecution

        executions = (
            self._db.query(FaGovernanceChainExecution)
            .filter(FaGovernanceChainExecution.tenant_id == self._tenant_id)
            .all()
        )
        raw = ranking_module.rank_bridges(executions)
        return self._finalize_ranking(
            raw,
            OptimizationType.BRIDGE_PRIORITIZATION.value,
            OptimizationType.BRIDGE_PRIORITIZATION.value,
            persist,
        )

    # ------------------------------------------------------------------
    # Public: rank strategies
    # ------------------------------------------------------------------

    def rank_strategies(self, persist: bool = True) -> list[OptimizationDecisionResponse]:
        """Rank strategy profiles by playbook performance."""
        from api.db_models_governance_adaptive_intelligence import FaGovernancePlaybook
        from services.governance_adaptive_intelligence.strategy_profiles import (
            STRATEGY_PROFILES,
        )

        playbooks = (
            self._db.query(FaGovernancePlaybook)
            .filter(FaGovernancePlaybook.tenant_id == self._tenant_id)
            .all()
        )
        raw = ranking_module.rank_strategies(playbooks, STRATEGY_PROFILES)
        return self._finalize_ranking(
            raw,
            OptimizationType.STRATEGY_WEIGHTING.value,
            OptimizationType.STRATEGY_WEIGHTING.value,
            persist,
        )

    # ------------------------------------------------------------------
    # Public: dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> OptimizationDashboardResponse:
        """Aggregate summary dashboard from all optimization types."""
        now = _now_iso()
        all_aggs = self._repo.list_all_aggregates()
        all_decisions_count = len(self._repo.list_all_decisions())

        all_scores = [
            a.average_priority_score
            for a in all_aggs
            if a.average_priority_score is not None
        ]
        avg_score = _avg(all_scores)

        # Top items per type
        rec_aggs = [
            a
            for a in all_aggs
            if a.optimization_type == OptimizationType.RECOMMENDATION_RANKING.value
        ]
        rem_aggs = [
            a
            for a in all_aggs
            if a.optimization_type == OptimizationType.REMEDIATION_PRIORITIZATION.value
        ]
        bridge_aggs = [
            a
            for a in all_aggs
            if a.optimization_type == OptimizationType.BRIDGE_PRIORITIZATION.value
        ]

        top_rec = None
        if rec_aggs:
            best = max(rec_aggs, key=lambda a: a.latest_priority_score or 0.0)
            top_rec = best.target_id

        top_rem = None
        if rem_aggs:
            best = max(rem_aggs, key=lambda a: a.latest_priority_score or 0.0)
            top_rem = best.target_id

        top_bridge = None
        if bridge_aggs:
            best = max(bridge_aggs, key=lambda a: a.latest_priority_score or 0.0)
            top_bridge = best.target_id

        total_aggs = len(all_aggs)
        overall_confidence = classify_optimization_confidence(
            avg_score or 0.0, total_aggs
        ).value

        return OptimizationDashboardResponse(
            tenant_id=self._tenant_id,
            total_decisions=all_decisions_count,
            total_aggregates=total_aggs,
            top_recommendation_type=top_rec,
            top_remediation_category=top_rem,
            top_bridge=top_bridge,
            average_priority_score=avg_score,
            overall_confidence=overall_confidence,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: list decisions
    # ------------------------------------------------------------------

    def list_decisions(
        self,
        optimization_type: Optional[str] = None,
        target_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[OptimizationDecisionResponse]:
        rows, _ = self._repo.list_decisions(
            optimization_type=optimization_type,
            target_type=target_type,
            limit=limit,
            offset=offset,
        )
        return [_decision_row_to_response(row) for row in rows]

    # ------------------------------------------------------------------
    # Public: list aggregates
    # ------------------------------------------------------------------

    def list_aggregates(
        self,
        target_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[OptimizationAggregateResponse]:
        rows, _ = self._repo.list_aggregates(
            target_type=target_type, limit=limit, offset=offset
        )
        return [_aggregate_row_to_response(row) for row in rows]

    # ------------------------------------------------------------------
    # Public: list snapshots
    # ------------------------------------------------------------------

    def list_snapshots(
        self,
        snapshot_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[OptimizationSnapshotResponse]:
        rows, _ = self._repo.list_snapshots(
            snapshot_type=snapshot_type, limit=limit, offset=offset
        )
        return [_snapshot_row_to_response(row) for row in rows]

    # ------------------------------------------------------------------
    # Public: CGIN snapshot
    # ------------------------------------------------------------------

    def get_cgin_snapshot(self) -> CGINOptimizationSnapshot:
        """Return anonymized CGIN benchmark snapshot. Never includes raw tenant_id."""
        now = _now_iso()
        fingerprint = hashlib.sha256(
            f"cgin:v1:{self._tenant_id}".encode()
        ).hexdigest()[:32]

        all_aggs = self._repo.list_all_aggregates()

        # Aggregate stats per optimization type
        def _stats_for_type(opt_type: str) -> dict:
            aggs = [a for a in all_aggs if a.optimization_type == opt_type]
            if not aggs:
                return {"count": 0, "avg_score": None, "top_target": None}
            scores = [a.average_priority_score for a in aggs if a.average_priority_score is not None]
            top = max(aggs, key=lambda a: a.latest_priority_score or 0.0)
            return {
                "count": len(aggs),
                "avg_score": _avg(scores),
                "top_target": top.target_id,
            }

        rec_stats = _stats_for_type(OptimizationType.RECOMMENDATION_RANKING.value)
        ctrl_stats = _stats_for_type(OptimizationType.CONTROL_PRIORITIZATION.value)
        rem_stats = _stats_for_type(OptimizationType.REMEDIATION_PRIORITIZATION.value)
        bridge_stats = _stats_for_type(OptimizationType.BRIDGE_PRIORITIZATION.value)
        strat_stats = _stats_for_type(OptimizationType.STRATEGY_WEIGHTING.value)

        # Confidence distribution across all aggs
        conf_dist: dict[str, int] = {}
        for agg in all_aggs:
            # Derive confidence from latest score
            conf = classify_optimization_confidence(
                agg.latest_priority_score or 0.0,
                agg.times_ranked,
            ).value
            conf_dist[conf] = conf_dist.get(conf, 0) + 1

        all_scores = [
            a.average_priority_score
            for a in all_aggs
            if a.average_priority_score is not None
        ]
        avg_priority = _avg(all_scores)

        top_strategy = strat_stats.get("top_target")

        return CGINOptimizationSnapshot(
            tenant_fingerprint=fingerprint,
            bundle_id=f"cgin-go-{fingerprint[:8]}",
            optimization_version=GOVERNANCE_OPTIMIZATION_VERSION,
            average_priority_score=avg_priority,
            top_strategy_profile=top_strategy,
            recommendation_ranking_stats=rec_stats,
            control_priority_stats=ctrl_stats,
            remediation_priority_stats=rem_stats,
            bridge_priority_stats=bridge_stats,
            confidence_distribution=conf_dist,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: recalculate
    # ------------------------------------------------------------------

    def recalculate(self, optimization_type: Optional[str] = None) -> dict:
        """Run all (or specific) ranking methods with persist=True and return summary."""
        now = _now_iso()
        results: dict[str, int] = {}

        run_all = optimization_type is None

        if run_all or optimization_type == OptimizationType.RECOMMENDATION_RANKING.value:
            items = self.rank_recommendations(persist=True)
            results[OptimizationType.RECOMMENDATION_RANKING.value] = len(items)

        if run_all or optimization_type == OptimizationType.CONTROL_PRIORITIZATION.value:
            items = self.rank_controls(persist=True)
            results[OptimizationType.CONTROL_PRIORITIZATION.value] = len(items)

        if run_all or optimization_type == OptimizationType.REMEDIATION_PRIORITIZATION.value:
            items = self.rank_remediations(persist=True)
            results[OptimizationType.REMEDIATION_PRIORITIZATION.value] = len(items)

        if run_all or optimization_type == OptimizationType.BRIDGE_PRIORITIZATION.value:
            items = self.rank_bridges(persist=True)
            results[OptimizationType.BRIDGE_PRIORITIZATION.value] = len(items)

        if run_all or optimization_type == OptimizationType.STRATEGY_WEIGHTING.value:
            items = self.rank_strategies(persist=True)
            results[OptimizationType.STRATEGY_WEIGHTING.value] = len(items)

        return {
            "tenant_id": self._tenant_id,
            "optimization_type_filter": optimization_type,
            "results": results,
            "recalculated_at": now,
        }


# ---------------------------------------------------------------------------
# Module-level row → response converters
# ---------------------------------------------------------------------------


def _decision_row_to_response(row) -> OptimizationDecisionResponse:
    return OptimizationDecisionResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        optimization_id=row.optimization_id,
        optimization_type=row.optimization_type,
        target_type=row.target_type,
        target_id=row.target_id,
        priority_score=row.priority_score,
        rank=row.rank,
        reason=row.reason,
        evidence_summary=row.evidence_summary,
        source_authorities=row.source_authorities,
        source_record_ids=row.source_record_ids,
        confidence=row.confidence,
        created_at=row.created_at,
    )


def _decision_row_to_response_from_item(
    item: RankedItem, tenant_id: str
) -> OptimizationDecisionResponse:
    return OptimizationDecisionResponse(
        id=_new_id(),
        tenant_id=tenant_id,
        optimization_id="",
        optimization_type=item.optimization_type,
        target_type=item.target_type,
        target_id=item.target_id,
        priority_score=item.priority_score,
        rank=item.rank,
        reason=item.reason,
        evidence_summary=item.evidence_summary,
        source_authorities=item.source_authorities,
        source_record_ids=item.source_record_ids,
        confidence=item.confidence,
        created_at=_now_iso(),
    )


def _aggregate_row_to_response(row) -> OptimizationAggregateResponse:
    return OptimizationAggregateResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        target_type=row.target_type,
        target_id=row.target_id,
        optimization_type=row.optimization_type,
        times_ranked=row.times_ranked,
        average_priority_score=row.average_priority_score,
        latest_priority_score=row.latest_priority_score,
        highest_priority_score=row.highest_priority_score,
        lowest_priority_score=row.lowest_priority_score,
        average_health_lift=row.average_health_lift,
        average_effectiveness_lift=row.average_effectiveness_lift,
        average_confidence=row.average_confidence,
        last_ranked_at=row.last_ranked_at,
    )


def _snapshot_row_to_response(row) -> OptimizationSnapshotResponse:
    return OptimizationSnapshotResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        snapshot_type=row.snapshot_type,
        total_items_ranked=row.total_items_ranked,
        top_priority_target_id=row.top_priority_target_id,
        top_priority_score=row.top_priority_score,
        average_priority_score=row.average_priority_score,
        optimization_confidence=row.optimization_confidence,
        generated_at=row.generated_at,
    )
