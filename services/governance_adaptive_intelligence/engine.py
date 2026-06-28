"""services/governance_adaptive_intelligence/engine.py

Governance Adaptive Intelligence Authority Engine.

Produces:
  - Recommendation tracking (idempotent on recommendation_id per tenant)
  - Accept / reject / execute lifecycle (append-only; new row per status)
  - Outcome recording with accuracy aggregate update
  - Dashboard summary
  - Accuracy breakdown per recommendation type
  - Calibration report
  - Playbook management
  - Strategy profiles (static)
  - CGIN anonymized benchmark snapshot

No AI. No LLMs. All computation is deterministic and auditable.

PR 17.6C — Governance Adaptive Intelligence Authority
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models_governance_adaptive_intelligence import (
    FaGovernanceAccuracyAggregate,
    FaGovernanceRecommendationHistory,
    FaGovernanceRecommendationOutcome,
)
from services.governance_adaptive_intelligence import recommendation_rules
from services.governance_adaptive_intelligence.models import (
    CalibratedConfidence,
    PlaybookType,
    RecommendationType,
    classify_calibrated_confidence,
    compute_accuracy_score,
    compute_avg_delta,
)
from services.governance_adaptive_intelligence.repository import (
    GovernanceAdaptiveIntelligenceRepository,
)
from services.governance_adaptive_intelligence.schemas import (
    AcceptRecommendationRequest,
    AccuracyAggregateResponse,
    AdaptiveAccuracyResponse,
    AdaptiveDashboardResponse,
    AdaptiveRecommendation,
    CGINAdaptiveSnapshot,
    CalibrationResponse,
    ExecuteRecommendationRequest,
    PlaybookResponse,
    RecalculateAdaptiveRequest,
    RecordOutcomeRequest,
    RecommendationHistoryResponse,
    RecommendationOutcomeResponse,
    StrategyProfileResponse,
    TrackRecommendationRequest,
)
from services.governance_adaptive_intelligence.strategy_profiles import (
    STRATEGY_PROFILES,
)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _delta(before: Optional[float], after: Optional[float]) -> Optional[float]:
    if before is None or after is None:
        return None
    return round(after - before, 4)


class GovernanceAdaptiveIntelligenceEngine:
    """Derives adaptive governance intelligence from recommendations and outcomes."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = GovernanceAdaptiveIntelligenceRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _history_to_response(
        self,
        row: FaGovernanceRecommendationHistory,
        outcome: Optional[FaGovernanceRecommendationOutcome] = None,
    ) -> RecommendationHistoryResponse:
        outcome_resp: Optional[RecommendationOutcomeResponse] = None
        if outcome is not None:
            outcome_resp = self._outcome_to_response(outcome)
        return RecommendationHistoryResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            recommendation_id=row.recommendation_id,
            recommendation_type=row.recommendation_type,
            recommendation_category=row.recommendation_category,
            recommendation_reason=row.recommendation_reason,
            recommendation_confidence=row.recommendation_confidence,
            generated_at=row.generated_at,
            accepted_at=row.accepted_at,
            rejected_at=row.rejected_at,
            executed_at=row.executed_at,
            closed_at=row.closed_at,
            status=row.status,
            source_learning_record_id=row.source_learning_record_id,
            source_aggregate_id=row.source_aggregate_id,
            source_authority=row.source_authority,
            outcome=outcome_resp,
        )

    def _outcome_to_response(
        self, row: FaGovernanceRecommendationOutcome
    ) -> RecommendationOutcomeResponse:
        return RecommendationOutcomeResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            recommendation_history_id=row.recommendation_history_id,
            health_before=row.health_before,
            health_after=row.health_after,
            health_delta=row.health_delta,
            effectiveness_before=row.effectiveness_before,
            effectiveness_after=row.effectiveness_after,
            effectiveness_delta=row.effectiveness_delta,
            verification_before=row.verification_before,
            verification_after=row.verification_after,
            verification_delta=row.verification_delta,
            freshness_before=row.freshness_before,
            freshness_after=row.freshness_after,
            freshness_delta=row.freshness_delta,
            forecast_before=row.forecast_before,
            forecast_after=row.forecast_after,
            forecast_delta=row.forecast_delta,
            success=row.success,
            confidence_adjustment=row.confidence_adjustment,
            recorded_at=row.recorded_at,
        )

    def _accuracy_to_response(
        self, row: FaGovernanceAccuracyAggregate
    ) -> AccuracyAggregateResponse:
        accuracy_score = compute_accuracy_score(
            row.recommendations_successful, row.recommendations_executed
        )
        return AccuracyAggregateResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            recommendation_type=row.recommendation_type,
            recommendations_generated=row.recommendations_generated,
            recommendations_accepted=row.recommendations_accepted,
            recommendations_executed=row.recommendations_executed,
            recommendations_successful=row.recommendations_successful,
            recommendations_failed=row.recommendations_failed,
            avg_health_delta=row.avg_health_delta,
            avg_effectiveness_delta=row.avg_effectiveness_delta,
            avg_verification_delta=row.avg_verification_delta,
            avg_freshness_delta=row.avg_freshness_delta,
            avg_forecast_delta=row.avg_forecast_delta,
            calibrated_confidence=row.calibrated_confidence,
            last_updated_at=row.last_updated_at,
            accuracy_score=accuracy_score,
        )

    def _update_accuracy_aggregate(self, recommendation_type: str) -> None:
        """Rebuild accuracy aggregate for a recommendation_type from all outcomes."""
        outcomes = self._repo.list_outcomes_for_type(recommendation_type)
        executed = len(outcomes)
        successful = sum(1 for o in outcomes if o.success)
        failed = sum(1 for o in outcomes if not o.success)

        # Count generated and accepted from history rows — outcomes only cover the
        # executed phase; generated/accepted counts require the history table.
        _ACCEPTED_OR_LATER = {"ACCEPTED", "EXECUTED", "CLOSED"}
        history_rows = self._repo.list_history_for_type(recommendation_type)
        generated = len({r.recommendation_id for r in history_rows})
        accepted = len(
            {r.recommendation_id for r in history_rows if r.status in _ACCEPTED_OR_LATER}
        )

        acc_score = compute_accuracy_score(successful, executed)
        cal_conf = classify_calibrated_confidence(acc_score, executed)

        # Averages from successful outcomes
        suc_outcomes = [o for o in outcomes if o.success]
        avg_h = compute_avg_delta([o.health_delta for o in suc_outcomes])
        avg_e = compute_avg_delta([o.effectiveness_delta for o in suc_outcomes])
        avg_v = compute_avg_delta([o.verification_delta for o in suc_outcomes])
        avg_f = compute_avg_delta([o.freshness_delta for o in suc_outcomes])
        avg_fc = compute_avg_delta([o.forecast_delta for o in suc_outcomes])

        now = _now_iso()
        self._repo.upsert_accuracy_aggregate(
            recommendation_type=recommendation_type,
            updates={
                "recommendations_generated": generated,
                "recommendations_accepted": accepted,
                "recommendations_executed": executed,
                "recommendations_successful": successful,
                "recommendations_failed": failed,
                "avg_health_delta": avg_h,
                "avg_effectiveness_delta": avg_e,
                "avg_verification_delta": avg_v,
                "avg_freshness_delta": avg_f,
                "avg_forecast_delta": avg_fc,
                "calibrated_confidence": cal_conf.value,
                "last_updated_at": now,
            },
        )

    def _rebuild_playbooks(self) -> None:
        """Rebuild all playbooks from outcome history."""
        # Mapping of playbook type → recommendation types that feed it
        playbook_to_rec_types: dict[str, list[str]] = {
            PlaybookType.REMEDIATION.value: [
                RecommendationType.PRIORITIZE_BEST_CATEGORY.value,
                RecommendationType.ESCALATE_WORST_CATEGORY.value,
            ],
            PlaybookType.VERIFICATION.value: [
                RecommendationType.IMPROVE_VERIFICATION.value,
            ],
            PlaybookType.FRESHNESS_RECOVERY.value: [
                RecommendationType.IMPROVE_FRESHNESS.value,
            ],
            PlaybookType.CONTROL_IMPROVEMENT.value: [
                RecommendationType.IMPROVE_EFFECTIVENESS.value,
                RecommendationType.GOVERNANCE_REVIEW.value,
            ],
        }

        now = _now_iso()
        for playbook_type, rec_types in playbook_to_rec_types.items():
            all_outcomes = []
            for rt in rec_types:
                all_outcomes.extend(self._repo.list_outcomes_for_type(rt))

            sample_size = len(all_outcomes)
            if sample_size == 0:
                success_rate = 0.0
                avg_health = None
                conf = CalibratedConfidence.CALIBRATED_UNKNOWN.value
            else:
                successful = sum(1 for o in all_outcomes if o.success)
                success_rate = round(successful / sample_size, 4)
                avg_health = compute_avg_delta(
                    [o.health_delta for o in all_outcomes if o.success]
                )
                acc_score = compute_accuracy_score(successful, sample_size)
                conf = classify_calibrated_confidence(acc_score, sample_size).value

            # Build recommended_path from strategy profile steps for this type
            steps = _playbook_steps_for_type(playbook_type)

            self._repo.upsert_playbook(
                playbook_type=playbook_type,
                updates={
                    "recommended_path": json.dumps(steps),
                    "success_rate": success_rate,
                    "avg_health_improvement": avg_health,
                    "confidence": conf,
                    "sample_size": sample_size,
                    "last_updated_at": now,
                },
            )

    def _get_adaptive_recommendations(
        self,
    ) -> list[AdaptiveRecommendation]:
        """Load aggregates + accuracy aggregates and call recommendation_rules."""
        from services.governance_learning.repository import GovernanceLearningRepository

        gl_repo = GovernanceLearningRepository(self._db, self._tenant_id)
        all_aggs = gl_repo.get_all_aggregates()
        all_records = gl_repo.list_all_records()
        total_records = len(all_records)

        # 30-day health delta window
        cutoff_30d = (
            datetime.now(tz=timezone.utc) - timedelta(days=30)
        ).isoformat()
        recent_30d = [r for r in all_records if r.created_at >= cutoff_30d]
        avg_health_30d_vals = [
            r.health_delta for r in recent_30d if r.health_delta is not None
        ]
        avg_health_30d: Optional[float] = (
            round(sum(avg_health_30d_vals) / len(avg_health_30d_vals), 4)
            if avg_health_30d_vals
            else None
        )

        accuracy_aggs = self._repo.list_all_accuracy_aggregates()

        return recommendation_rules.generate_adaptive_recommendations(
            aggregates=all_aggs,
            accuracy_aggregates=accuracy_aggs,
            total_records=total_records,
            avg_health_delta_30d=avg_health_30d,
        )

    # ------------------------------------------------------------------
    # Public: POST /governance-adaptive-intelligence/track
    # ------------------------------------------------------------------

    def track_recommendation(
        self, request: TrackRecommendationRequest
    ) -> RecommendationHistoryResponse:
        """Create a PENDING history row. Idempotent on recommendation_id per tenant."""
        existing = self._repo.get_latest_history_for_recommendation(
            request.recommendation_id
        )
        if existing is not None and existing.status == "PENDING":
            return self._history_to_response(existing)

        now = _now_iso()
        row = FaGovernanceRecommendationHistory(
            id=_new_id(),
            tenant_id=self._tenant_id,
            recommendation_id=request.recommendation_id,
            recommendation_type=request.recommendation_type,
            recommendation_category=request.recommendation_category,
            recommendation_reason=request.recommendation_reason,
            recommendation_confidence=request.recommendation_confidence,
            generated_at=now,
            accepted_at=None,
            rejected_at=None,
            executed_at=None,
            closed_at=None,
            status="PENDING",
            source_learning_record_id=request.source_learning_record_id,
            source_aggregate_id=request.source_aggregate_id,
            source_authority=request.source_authority,
        )
        self._repo.create_history(row)
        self._db.commit()
        return self._history_to_response(row)

    # ------------------------------------------------------------------
    # Public: POST /governance-adaptive-intelligence/accept
    # ------------------------------------------------------------------

    def accept_recommendation(
        self, request: AcceptRecommendationRequest
    ) -> RecommendationHistoryResponse:
        """Accept or reject a recommendation. Creates a new history row.

        The append-only table cannot be updated, so each status transition
        creates a NEW row with the same recommendation_id.
        """
        # Find the source history row
        source = self._repo.get_history_by_id(request.recommendation_history_id)
        if source is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=404, detail="recommendation_history not found"
            )

        now = _now_iso()
        new_status = "ACCEPTED" if request.accepted else "REJECTED"
        row = FaGovernanceRecommendationHistory(
            id=_new_id(),
            tenant_id=self._tenant_id,
            recommendation_id=source.recommendation_id,
            recommendation_type=source.recommendation_type,
            recommendation_category=source.recommendation_category,
            recommendation_reason=source.recommendation_reason,
            recommendation_confidence=source.recommendation_confidence,
            generated_at=now,
            accepted_at=now if request.accepted else None,
            rejected_at=now if not request.accepted else None,
            executed_at=None,
            closed_at=now if not request.accepted else None,
            status=new_status,
            source_learning_record_id=source.source_learning_record_id,
            source_aggregate_id=source.source_aggregate_id,
            source_authority=source.source_authority,
        )
        self._repo.create_history(row)
        self._db.commit()
        return self._history_to_response(row)

    # ------------------------------------------------------------------
    # Public: POST /governance-adaptive-intelligence/execute
    # ------------------------------------------------------------------

    def execute_recommendation(
        self, request: ExecuteRecommendationRequest
    ) -> RecommendationHistoryResponse:
        """Mark a recommendation as EXECUTED. Creates a new history row."""
        source = self._repo.get_history_by_id(request.recommendation_history_id)
        if source is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=404, detail="recommendation_history not found"
            )

        now = _now_iso()
        row = FaGovernanceRecommendationHistory(
            id=_new_id(),
            tenant_id=self._tenant_id,
            recommendation_id=source.recommendation_id,
            recommendation_type=source.recommendation_type,
            recommendation_category=source.recommendation_category,
            recommendation_reason=source.recommendation_reason,
            recommendation_confidence=source.recommendation_confidence,
            generated_at=now,
            accepted_at=source.accepted_at,
            rejected_at=source.rejected_at,
            executed_at=now,
            closed_at=None,
            status="EXECUTED",
            source_learning_record_id=source.source_learning_record_id,
            source_aggregate_id=source.source_aggregate_id,
            source_authority=source.source_authority,
        )
        self._repo.create_history(row)
        self._db.commit()
        return self._history_to_response(row)

    # ------------------------------------------------------------------
    # Public: POST /governance-adaptive-intelligence/record-outcome
    # ------------------------------------------------------------------

    def record_outcome(
        self, request: RecordOutcomeRequest
    ) -> RecommendationOutcomeResponse:
        """Create an outcome row. Idempotent on (tenant_id, recommendation_history_id)."""
        existing = self._repo.get_outcome_by_history_id(
            request.recommendation_history_id
        )
        if existing is not None:
            return self._outcome_to_response(existing)

        # Validate that the history row exists and belongs to this tenant
        hist = self._repo.get_history_by_id(request.recommendation_history_id)
        if hist is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=404, detail="recommendation_history not found"
            )

        h_delta = _delta(request.health_before, request.health_after)
        e_delta = _delta(request.effectiveness_before, request.effectiveness_after)
        v_delta = _delta(request.verification_before, request.verification_after)
        f_delta = _delta(request.freshness_before, request.freshness_after)
        fc_delta = _delta(request.forecast_before, request.forecast_after)

        row = FaGovernanceRecommendationOutcome(
            id=_new_id(),
            tenant_id=self._tenant_id,
            recommendation_history_id=request.recommendation_history_id,
            health_before=request.health_before,
            health_after=request.health_after,
            health_delta=h_delta,
            effectiveness_before=request.effectiveness_before,
            effectiveness_after=request.effectiveness_after,
            effectiveness_delta=e_delta,
            verification_before=request.verification_before,
            verification_after=request.verification_after,
            verification_delta=v_delta,
            freshness_before=request.freshness_before,
            freshness_after=request.freshness_after,
            freshness_delta=f_delta,
            forecast_before=request.forecast_before,
            forecast_after=request.forecast_after,
            forecast_delta=fc_delta,
            success=request.success,
            confidence_adjustment=None,
            recorded_at=_now_iso(),
        )
        try:
            self._repo.create_outcome(row)
            # Update accuracy aggregate for this recommendation type
            self._update_accuracy_aggregate(hist.recommendation_type)
            self._db.commit()
        except IntegrityError:
            self._db.rollback()
            existing = self._repo.get_outcome_by_history_id(
                request.recommendation_history_id
            )
            if existing is not None:
                return self._outcome_to_response(existing)
            raise
        return self._outcome_to_response(row)

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> AdaptiveDashboardResponse:
        """Compute adaptive dashboard from history and accuracy aggregates."""
        now = _now_iso()
        all_history = self._repo.list_all_history()
        acc_aggs = self._repo.list_all_accuracy_aggregates()

        # Deduplicate history to get latest row per recommendation_id
        seen: set[str] = set()
        latest_per_rec: list[FaGovernanceRecommendationHistory] = []
        for row in sorted(all_history, key=lambda r: r.generated_at, reverse=True):
            if row.recommendation_id not in seen:
                seen.add(row.recommendation_id)
                latest_per_rec.append(row)

        total_recommendations = len(latest_per_rec)
        active_count = sum(
            1 for r in latest_per_rec if r.status in ("PENDING", "ACCEPTED")
        )

        total_executed = sum(
            row.recommendations_executed for row in acc_aggs
        )
        total_successful = sum(
            row.recommendations_successful for row in acc_aggs
        )

        overall_acc = compute_accuracy_score(total_successful, total_executed)
        overall_conf = classify_calibrated_confidence(overall_acc, total_executed)

        # Averages from accuracy aggregates
        avg_h = compute_avg_delta([a.avg_health_delta for a in acc_aggs])
        avg_e = compute_avg_delta([a.avg_effectiveness_delta for a in acc_aggs])

        return AdaptiveDashboardResponse(
            tenant_id=self._tenant_id,
            total_recommendations=total_recommendations,
            total_executed=total_executed,
            total_successful=total_successful,
            overall_accuracy_score=overall_acc,
            calibrated_confidence=overall_conf.value,
            avg_health_delta=avg_h,
            avg_effectiveness_delta=avg_e,
            active_recommendation_count=active_count,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/recommendations
    # ------------------------------------------------------------------

    def list_recommendations(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RecommendationHistoryResponse]:
        """List latest history rows per recommendation_id, optionally filtered by status."""
        rows, _ = self._repo.list_history(status=status, limit=limit, offset=offset)
        result = []
        for row in rows:
            outcome = self._repo.get_outcome_by_history_id(row.id)
            result.append(self._history_to_response(row, outcome))
        return result

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/recommendations/{recommendation_id}
    # ------------------------------------------------------------------

    def get_recommendation_detail(
        self, recommendation_id: str
    ) -> RecommendationHistoryResponse:
        """Return the latest status row for a recommendation_id with outcome attached."""
        row = self._repo.get_latest_history_for_recommendation(recommendation_id)
        if row is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="recommendation not found")
        outcome = self._repo.get_outcome_by_history_id(row.id)
        return self._history_to_response(row, outcome)

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/outcomes
    # ------------------------------------------------------------------

    def list_outcomes(
        self, limit: int = 50, offset: int = 0
    ) -> list[RecommendationOutcomeResponse]:
        """List outcomes for this tenant with pagination."""
        rows, _ = self._repo.list_outcomes(limit=limit, offset=offset)
        return [self._outcome_to_response(r) for r in rows]

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/accuracy
    # ------------------------------------------------------------------

    def get_accuracy(self) -> AdaptiveAccuracyResponse:
        """Return per-type accuracy breakdown."""
        now = _now_iso()
        aggs = self._repo.list_all_accuracy_aggregates()
        per_type = [self._accuracy_to_response(a) for a in aggs]

        total_executed = sum(a.recommendations_executed for a in aggs)
        total_successful = sum(a.recommendations_successful for a in aggs)
        overall_acc = compute_accuracy_score(total_successful, total_executed)
        overall_conf = classify_calibrated_confidence(overall_acc, total_executed)

        return AdaptiveAccuracyResponse(
            tenant_id=self._tenant_id,
            per_type=per_type,
            overall_accuracy_score=overall_acc,
            overall_calibrated_confidence=overall_conf.value,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/calibration
    # ------------------------------------------------------------------

    def get_calibration(self) -> CalibrationResponse:
        """Return confidence distribution per recommendation type."""
        now = _now_iso()
        aggs = self._repo.list_all_accuracy_aggregates()

        dist: dict[str, str] = {}
        for agg in aggs:
            dist[agg.recommendation_type] = agg.calibrated_confidence

        if not aggs:
            overall = CalibratedConfidence.CALIBRATED_UNKNOWN.value
        else:
            # Overall: most common confidence value
            counts: dict[str, int] = {}
            for conf in dist.values():
                counts[conf] = counts.get(conf, 0) + 1
            overall = max(counts, key=lambda k: counts[k])

        return CalibrationResponse(
            tenant_id=self._tenant_id,
            confidence_distribution=dist,
            overall_calibration=overall,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/playbooks
    # ------------------------------------------------------------------

    def list_playbooks(self) -> list[PlaybookResponse]:
        """List all playbooks for this tenant."""
        rows = self._repo.list_all_playbooks()
        return [_playbook_row_to_response(r) for r in rows]

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/strategy-profiles
    # ------------------------------------------------------------------

    def list_strategy_profiles(self) -> list[StrategyProfileResponse]:
        """Return static strategy profiles for all industry verticals."""
        result = []
        for profile_name, data in STRATEGY_PROFILES.items():
            result.append(
                StrategyProfileResponse(
                    profile=profile_name,
                    recommended_controls=data["recommended_controls"],
                    recommended_remediation_types=data["recommended_remediation_types"],
                    historical_success_patterns=data["historical_success_patterns"],
                    historical_failure_patterns=data["historical_failure_patterns"],
                    confidence=data["confidence"],
                )
            )
        return result

    # ------------------------------------------------------------------
    # Public: GET /governance-adaptive-intelligence/cgin/snapshot
    # ------------------------------------------------------------------

    def get_cgin_snapshot(self) -> CGINAdaptiveSnapshot:
        """Return anonymized CGIN benchmark snapshot. Never includes raw tenant_id."""
        now = _now_iso()
        fingerprint = hashlib.sha256(
            f"cgin:v1:{self._tenant_id}".encode()
        ).hexdigest()[:32]

        acc_aggs = self._repo.list_all_accuracy_aggregates()
        playbooks = self._repo.list_all_playbooks()
        all_history = self._repo.list_all_history()

        # Deduplicate total_recommendations
        seen: set[str] = set()
        for row in all_history:
            seen.add(row.recommendation_id)
        total_recommendations = len(seen)

        # Overall accuracy
        total_executed = sum(a.recommendations_executed for a in acc_aggs)
        total_successful = sum(a.recommendations_successful for a in acc_aggs)
        overall_acc: Optional[float] = (
            compute_accuracy_score(total_successful, total_executed)
            if total_executed > 0
            else None
        )

        # Avg health improvement from successful outcomes
        avg_h_vals = [
            a.avg_health_delta for a in acc_aggs if a.avg_health_delta is not None
        ]
        avg_h_improvement: Optional[float] = (
            round(sum(avg_h_vals) / len(avg_h_vals), 4) if avg_h_vals else None
        )

        # Confidence distribution
        dist: dict[str, str] = {
            a.recommendation_type: a.calibrated_confidence for a in acc_aggs
        }

        # Playbook statistics (anonymized)
        pb_stats = [
            {
                "playbook_type": pb.playbook_type,
                "success_rate": pb.success_rate,
                "sample_size": pb.sample_size,
                "confidence": pb.confidence,
            }
            for pb in playbooks
        ]

        return CGINAdaptiveSnapshot(
            tenant_fingerprint=fingerprint,
            bundle_id=f"cgin-gai-{fingerprint[:8]}",
            overall_accuracy=overall_acc,
            avg_health_improvement=avg_h_improvement,
            confidence_distribution=dist,
            playbook_statistics=pb_stats,
            total_recommendations=total_recommendations,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: POST /governance-adaptive-intelligence/recalculate
    # ------------------------------------------------------------------

    def recalculate(self, request: RecalculateAdaptiveRequest) -> dict:
        """Rebuild accuracy aggregates and playbooks from outcome history."""
        now = _now_iso()

        if request.recommendation_type is not None:
            types_to_rebuild = [request.recommendation_type]
        else:
            # Rebuild all types seen in outcomes
            all_outcomes = self._repo.list_all_outcomes()
            all_history = self._repo.list_all_history()
            # Map history_id → recommendation_type
            hist_map: dict[str, str] = {row.id: row.recommendation_type for row in all_history}
            types_to_rebuild = list(
                {
                    hist_map[o.recommendation_history_id]
                    for o in all_outcomes
                    if o.recommendation_history_id in hist_map
                }
            )

        for rec_type in types_to_rebuild:
            self._update_accuracy_aggregate(rec_type)

        # Rebuild playbooks
        self._rebuild_playbooks()
        self._db.commit()

        return {
            "tenant_id": self._tenant_id,
            "types_recalculated": len(types_to_rebuild),
            "recommendation_type_filter": request.recommendation_type,
            "recalculated_at": now,
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_PLAYBOOK_STEPS: dict[str, list[str]] = {
    PlaybookType.REMEDIATION.value: [
        "identify_failing_controls",
        "classify_remediation_category",
        "apply_best_practice_remediation",
        "verify_remediation_outcome",
        "close_or_escalate",
    ],
    PlaybookType.VERIFICATION.value: [
        "assess_verification_gaps",
        "collect_missing_evidence",
        "run_verification_workflow",
        "record_verification_outcome",
        "update_freshness_score",
    ],
    PlaybookType.FRESHNESS_RECOVERY.value: [
        "identify_stale_evidence",
        "trigger_evidence_refresh",
        "re_run_freshness_scoring",
        "verify_freshness_threshold_met",
        "archive_or_escalate",
    ],
    PlaybookType.CONTROL_IMPROVEMENT.value: [
        "assess_control_effectiveness",
        "identify_improvement_actions",
        "implement_control_changes",
        "validate_effectiveness_delta",
        "update_governance_record",
    ],
}


def _playbook_steps_for_type(playbook_type: str) -> list[str]:
    return _PLAYBOOK_STEPS.get(playbook_type, [])


def _playbook_row_to_response(row) -> PlaybookResponse:
    try:
        steps: list[str] = json.loads(row.recommended_path)
        if not isinstance(steps, list):
            steps = []
    except Exception:
        steps = []
    return PlaybookResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        playbook_type=row.playbook_type,
        recommended_path=row.recommended_path,
        recommended_steps=steps,
        success_rate=row.success_rate,
        avg_health_improvement=row.avg_health_improvement,
        confidence=row.confidence,
        sample_size=row.sample_size,
        last_updated_at=row.last_updated_at,
    )
