"""services/governance_learning/engine.py

Governance Learning Loop Authority Engine.

Produces:
  - Learning records from remediation outcomes (idempotent ingestion)
  - Per-category aggregate statistics
  - Deterministic governance recommendations
  - Momentum and stability classification
  - Dashboard summary
  - CGIN anonymized benchmark snapshot

No AI. No LLMs. All computation is deterministic and auditable.

PR 17.6B — Governance Learning Loop Authority
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models_governance_learning import (
    FaGovernanceLearningAggregate,
    FaGovernanceLearningRecord,
)
from services.governance_learning import learning_rules
from services.governance_learning.models import (
    GOVERNANCE_LEARNING_VERSION,
    LearningCategory,
    classify_confidence,
    classify_momentum,
    classify_stability,
    compute_confidence_score,
    compute_success_score,
    detect_signals,
)
from services.governance_learning.repository import GovernanceLearningRepository
from services.governance_learning.schemas import (
    GovernanceMomentumResponse,
    IngestOutcomeRequest,
    LearningAggregateListResponse,
    LearningAggregateResponse,
    LearningCGINSnapshot,
    LearningDashboardResponse,
    LearningRecordListResponse,
    LearningRecordResponse,
    RecalculateRequest,
    RecommendationListResponse,
)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _avg(values: list[Optional[float]]) -> Optional[float]:
    """Compute the average of non-None values, returning None if all are None."""
    valid = [v for v in values if v is not None]
    if not valid:
        return None
    return round(sum(valid) / len(valid), 4)


def _delta(before: Optional[float], after: Optional[float]) -> Optional[float]:
    if before is None or after is None:
        return None
    return round(after - before, 4)


class GovernanceLearningEngine:
    """Derives governance learning analytics from ingested remediation outcomes."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = GovernanceLearningRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_to_response(
        self, row: FaGovernanceLearningRecord
    ) -> LearningRecordResponse:
        return LearningRecordResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            learning_category=row.learning_category,
            control_id=row.control_id,
            remediation_category=row.remediation_category,
            outcome_type=row.outcome_type,
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
            health_before=row.health_before,
            health_after=row.health_after,
            health_delta=row.health_delta,
            success_score=row.success_score,
            confidence_score=row.confidence_score,
            source_outcome_id=row.source_outcome_id,
            created_at=row.created_at,
        )

    def _aggregate_to_response(
        self, row: FaGovernanceLearningAggregate
    ) -> LearningAggregateResponse:
        total = (
            row.success_count
            + row.failure_count
            + row.partial_success_count
            + row.no_change_count
        )
        success_rate = (
            round((row.success_count + row.partial_success_count * 0.5) / total, 4)
            if total > 0
            else 0.0
        )
        failure_rate = round(row.failure_count / total, 4) if total > 0 else 0.0
        signals = detect_signals(
            avg_effectiveness_delta=row.average_effectiveness_delta,
            avg_health_delta=row.average_health_delta,
            avg_freshness_delta=row.average_freshness_delta,
            avg_verification_delta=row.average_verification_delta,
            avg_forecast_delta=row.average_forecast_delta,
            success_rate=success_rate,
            failure_rate=failure_rate,
            total_count=total,
        )
        return LearningAggregateResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            remediation_category=row.remediation_category,
            success_count=row.success_count,
            failure_count=row.failure_count,
            partial_success_count=row.partial_success_count,
            total_count=total,
            success_rate=success_rate,
            failure_rate=failure_rate,
            average_effectiveness_delta=row.average_effectiveness_delta,
            average_verification_delta=row.average_verification_delta,
            average_freshness_delta=row.average_freshness_delta,
            average_forecast_delta=row.average_forecast_delta,
            average_health_delta=row.average_health_delta,
            confidence=row.confidence,
            last_updated_at=row.last_updated_at,
            signals=signals,
        )

    def _update_aggregate(self, remediation_category: str) -> None:
        """Recompute aggregate for a remediation_category from all records."""
        records = self._repo.list_records_for_category(remediation_category)
        total = len(records)

        success_count = sum(1 for r in records if r.outcome_type == "SUCCESS")
        partial_count = sum(1 for r in records if r.outcome_type == "PARTIAL_SUCCESS")
        # failure: FAILURE, REGRESSION, and NO_CHANGE with delta <= -1
        failure_count = sum(
            1
            for r in records
            if r.outcome_type in ("FAILURE", "REGRESSION")
            or (
                r.outcome_type == "NO_CHANGE" and (r.effectiveness_delta or 0.0) <= -1.0
            )
        )
        # neutral NO_CHANGE (delta > -1.0) — tracked separately so totals are complete
        no_change_count = sum(
            1
            for r in records
            if r.outcome_type == "NO_CHANGE" and (r.effectiveness_delta or 0.0) > -1.0
        )

        avg_eff = _avg([r.effectiveness_delta for r in records])
        avg_ver = _avg([r.verification_delta for r in records])
        avg_fre = _avg([r.freshness_delta for r in records])
        avg_for = _avg([r.forecast_delta for r in records])
        avg_hlt = _avg([r.health_delta for r in records])

        confidence = classify_confidence(total).value
        now = _now_iso()

        self._repo.upsert_aggregate(
            tenant_id=self._tenant_id,
            remediation_category=remediation_category,
            updates={
                "success_count": success_count,
                "failure_count": failure_count,
                "partial_success_count": partial_count,
                "no_change_count": no_change_count,
                "average_effectiveness_delta": avg_eff,
                "average_verification_delta": avg_ver,
                "average_freshness_delta": avg_fre,
                "average_forecast_delta": avg_for,
                "average_health_delta": avg_hlt,
                "confidence": confidence,
                "last_updated_at": now,
            },
        )

    # ------------------------------------------------------------------
    # Public: POST /governance-learning/ingest-outcome
    # ------------------------------------------------------------------

    def ingest_outcome(self, request: IngestOutcomeRequest) -> LearningRecordResponse:
        """Create a learning record from a remediation outcome. Idempotent on source_outcome_id."""
        existing = self._repo.get_record_by_outcome(request.source_outcome_id)
        if existing is not None:
            return self._record_to_response(existing)

        eff_delta = _delta(request.effectiveness_before, request.effectiveness_after)
        ver_delta = _delta(request.verification_before, request.verification_after)
        fre_delta = _delta(request.freshness_before, request.freshness_after)
        for_delta = _delta(request.forecast_before, request.forecast_after)
        hlt_delta = _delta(request.health_before, request.health_after)

        success_score = compute_success_score(
            request.outcome_classification, request.score_delta
        )
        # Confidence for a single record = based on 1 sample
        confidence_score = compute_confidence_score(1)

        row = FaGovernanceLearningRecord(
            id=_new_id(),
            tenant_id=self._tenant_id,
            learning_category=LearningCategory.REMEDIATION.value,
            control_id=request.control_id,
            remediation_category=request.remediation_category,
            outcome_type=request.outcome_classification,
            effectiveness_before=request.effectiveness_before,
            effectiveness_after=request.effectiveness_after,
            effectiveness_delta=eff_delta,
            verification_before=request.verification_before,
            verification_after=request.verification_after,
            verification_delta=ver_delta,
            freshness_before=request.freshness_before,
            freshness_after=request.freshness_after,
            freshness_delta=fre_delta,
            forecast_before=request.forecast_before,
            forecast_after=request.forecast_after,
            forecast_delta=for_delta,
            health_before=request.health_before,
            health_after=request.health_after,
            health_delta=hlt_delta,
            success_score=success_score,
            confidence_score=confidence_score,
            source_outcome_id=request.source_outcome_id,
            created_at=_now_iso(),
        )
        try:
            self._repo.create_record(row)
            self._update_aggregate(request.remediation_category)
            self._db.commit()
        except IntegrityError:
            self._db.rollback()
            existing = self._repo.get_record_by_outcome(request.source_outcome_id)
            if existing is not None:
                return self._record_to_response(existing)
            raise
        return self._record_to_response(row)

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/learning-records
    # ------------------------------------------------------------------

    def list_records(
        self,
        learning_category: Optional[str] = None,
        remediation_category: Optional[str] = None,
        control_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> LearningRecordListResponse:
        rows, total = self._repo.list_records(
            learning_category=learning_category,
            remediation_category=remediation_category,
            control_id=control_id,
            limit=limit,
            offset=offset,
        )
        return LearningRecordListResponse(
            records=[self._record_to_response(r) for r in rows],
            total=total,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/aggregates
    # ------------------------------------------------------------------

    def list_aggregates(
        self, limit: int = 50, offset: int = 0
    ) -> LearningAggregateListResponse:
        rows, total = self._repo.list_aggregates(limit=limit, offset=offset)
        return LearningAggregateListResponse(
            aggregates=[self._aggregate_to_response(r) for r in rows],
            total=total,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> LearningDashboardResponse:
        """Compute dashboard from aggregates and records."""
        now = _now_iso()
        all_records = self._repo.list_all_records()
        total_records = len(all_records)

        all_aggs = self._repo.get_all_aggregates()
        total_aggs = len(all_aggs)

        # Overall success/failure counts
        total_successful = sum(
            1 for r in all_records if r.outcome_type in ("SUCCESS", "PARTIAL_SUCCESS")
        )

        # Overall success rate
        if total_records > 0:
            overall_success_rate = round(total_successful / total_records, 4)
        else:
            overall_success_rate = 0.0

        # Overall avg health delta
        overall_avg_health = _avg([r.health_delta for r in all_records])

        # Top/worst by aggregate success rate
        top_cat: Optional[str] = None
        worst_cat: Optional[str] = None
        if all_aggs:

            def _sr(a: FaGovernanceLearningAggregate) -> float:
                t = (
                    a.success_count
                    + a.failure_count
                    + a.partial_success_count
                    + a.no_change_count
                )
                return (
                    (a.success_count + a.partial_success_count * 0.5) / t
                    if t > 0
                    else 0.0
                )

            best = max(all_aggs, key=_sr)
            worst = min(all_aggs, key=_sr)
            top_cat = best.remediation_category
            worst_cat = worst.remediation_category

        # Momentum from records in the last 30 calendar days
        cutoff_30d = (datetime.now(tz=timezone.utc) - timedelta(days=30)).isoformat()
        recent_30d = [r for r in all_records if r.created_at >= cutoff_30d]
        avg_health_30d = _avg([r.health_delta for r in recent_30d])
        avg_eff_30d = _avg([r.effectiveness_delta for r in recent_30d])
        momentum = classify_momentum(avg_health_30d, avg_eff_30d)

        health_deltas = [
            r.health_delta for r in all_records if r.health_delta is not None
        ]
        stability = classify_stability(health_deltas)

        # Confidence from total records
        confidence = classify_confidence(total_records)

        # Active signals across all aggregates
        active_signals: list[str] = []
        for agg in all_aggs:
            t = (
                agg.success_count
                + agg.failure_count
                + agg.partial_success_count
                + agg.no_change_count
            )
            sr = (
                (agg.success_count + agg.partial_success_count * 0.5) / t
                if t > 0
                else 0.0
            )
            fr = agg.failure_count / t if t > 0 else 0.0
            sigs = detect_signals(
                avg_effectiveness_delta=agg.average_effectiveness_delta,
                avg_health_delta=agg.average_health_delta,
                avg_freshness_delta=agg.average_freshness_delta,
                avg_verification_delta=agg.average_verification_delta,
                avg_forecast_delta=agg.average_forecast_delta,
                success_rate=sr,
                failure_rate=fr,
                total_count=t,
            )
            for s in sigs:
                if s not in active_signals:
                    active_signals.append(s)

        return LearningDashboardResponse(
            tenant_id=self._tenant_id,
            total_learning_records=total_records,
            total_aggregates=total_aggs,
            top_performing_category=top_cat,
            worst_performing_category=worst_cat,
            overall_success_rate=overall_success_rate,
            overall_average_health_delta=overall_avg_health,
            momentum=momentum.value,
            stability=stability.value,
            confidence=confidence.value,
            active_signals=active_signals,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/recommendations
    # ------------------------------------------------------------------

    def get_recommendations(self) -> RecommendationListResponse:
        """Generate deterministic recommendations from aggregates."""
        now = _now_iso()
        all_aggs = self._repo.get_all_aggregates()
        all_records = self._repo.list_all_records()
        total_records = len(all_records)

        # Avg health delta from records in the last 30 calendar days
        cutoff_30d = (datetime.now(tz=timezone.utc) - timedelta(days=30)).isoformat()
        recent_30d = [r for r in all_records if r.created_at >= cutoff_30d]
        avg_health_30d = _avg([r.health_delta for r in recent_30d])

        recs = learning_rules.generate_recommendations(
            aggregates=all_aggs,
            total_records=total_records,
            avg_health_delta_30d=avg_health_30d,
        )
        return RecommendationListResponse(
            recommendations=recs,
            total=len(recs),
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/top-performers
    # ------------------------------------------------------------------

    def get_top_performers(self, limit: int = 5) -> LearningAggregateListResponse:
        """Return aggregates sorted by success rate descending."""
        all_aggs = self._repo.get_all_aggregates()

        def _sr(a: FaGovernanceLearningAggregate) -> float:
            t = (
                a.success_count
                + a.failure_count
                + a.partial_success_count
                + a.no_change_count
            )
            return (
                (a.success_count + a.partial_success_count * 0.5) / t if t > 0 else 0.0
            )

        sorted_aggs = sorted(all_aggs, key=_sr, reverse=True)[:limit]
        return LearningAggregateListResponse(
            aggregates=[self._aggregate_to_response(r) for r in sorted_aggs],
            total=len(sorted_aggs),
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/top-failures
    # ------------------------------------------------------------------

    def get_failures(self, limit: int = 5) -> LearningAggregateListResponse:
        """Return aggregates sorted by failure rate descending."""
        all_aggs = self._repo.get_all_aggregates()

        def _fr(a: FaGovernanceLearningAggregate) -> float:
            t = (
                a.success_count
                + a.failure_count
                + a.partial_success_count
                + a.no_change_count
            )
            return a.failure_count / t if t > 0 else 0.0

        sorted_aggs = sorted(all_aggs, key=_fr, reverse=True)[:limit]
        return LearningAggregateListResponse(
            aggregates=[self._aggregate_to_response(r) for r in sorted_aggs],
            total=len(sorted_aggs),
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/momentum
    # ------------------------------------------------------------------

    def get_momentum(self) -> GovernanceMomentumResponse:
        """Classify momentum and stability from recent records."""
        now = _now_iso()
        all_records = self._repo.list_all_records()
        total_records = len(all_records)

        total_successful = sum(
            1 for r in all_records if r.outcome_type in ("SUCCESS", "PARTIAL_SUCCESS")
        )
        total_failed = sum(
            1 for r in all_records if r.outcome_type in ("FAILURE", "REGRESSION")
        )

        cutoff_30d = (datetime.now(tz=timezone.utc) - timedelta(days=30)).isoformat()
        recent_30d = [r for r in all_records if r.created_at >= cutoff_30d]
        avg_health_30d = _avg([r.health_delta for r in recent_30d])
        avg_eff_30d = _avg([r.effectiveness_delta for r in recent_30d])

        momentum = classify_momentum(avg_health_30d, avg_eff_30d)

        health_deltas = [
            r.health_delta for r in all_records if r.health_delta is not None
        ]
        stability = classify_stability(health_deltas)

        confidence = classify_confidence(total_records)

        return GovernanceMomentumResponse(
            tenant_id=self._tenant_id,
            momentum_class=momentum.value,
            stability_class=stability.value,
            avg_health_delta_30d=avg_health_30d,
            avg_effectiveness_delta_30d=avg_eff_30d,
            total_learning_records=total_records,
            total_successful=total_successful,
            total_failed=total_failed,
            confidence=confidence.value,
            computed_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /governance-learning/cgin/snapshot
    # ------------------------------------------------------------------

    def get_cgin_snapshot(self) -> LearningCGINSnapshot:
        """Return anonymized benchmark snapshot. Never includes raw tenant_id."""
        now = _now_iso()

        # Anonymize the tenant_id
        fingerprint = hashlib.sha256(f"cgin:v1:{self._tenant_id}".encode()).hexdigest()[
            :32
        ]

        all_records = self._repo.list_all_records()
        total_records = len(all_records)
        all_aggs = self._repo.get_all_aggregates()

        # Overall success rate
        total_successful = sum(
            1 for r in all_records if r.outcome_type in ("SUCCESS", "PARTIAL_SUCCESS")
        )
        overall_success_rate = (
            round(total_successful / total_records, 4) if total_records > 0 else None
        )
        overall_avg_health = _avg([r.health_delta for r in all_records])

        # Per-category snapshots
        category_snapshots = []
        for agg in all_aggs:
            t = (
                agg.success_count
                + agg.failure_count
                + agg.partial_success_count
                + agg.no_change_count
            )
            sr = (
                (agg.success_count + agg.partial_success_count * 0.5) / t
                if t > 0
                else 0.0
            )
            category_snapshots.append(
                {
                    "remediation_category": agg.remediation_category,
                    "success_rate": round(sr, 4),
                    "avg_health_delta": agg.average_health_delta,
                    "confidence": agg.confidence,
                    "total_outcomes": t,
                }
            )

        return LearningCGINSnapshot(
            tenant_fingerprint=fingerprint,
            bundle_id=f"cgin-gl-{fingerprint[:8]}",
            bundle_version=GOVERNANCE_LEARNING_VERSION,
            category_snapshots=category_snapshots,
            overall_success_rate=overall_success_rate,
            overall_avg_health_delta=overall_avg_health,
            total_records=total_records,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: POST /governance-learning/recalculate
    # ------------------------------------------------------------------

    def recalculate(self, request: RecalculateRequest) -> dict:
        """Rebuild all aggregates from scratch (or for one control_id)."""
        now = _now_iso()

        if request.control_id is not None:
            # Rebuild only for categories that include records for this control
            all_records = self._repo.list_all_records()
            categories = list(
                {
                    r.remediation_category
                    for r in all_records
                    if r.control_id == request.control_id
                }
            )
        else:
            # Rebuild all categories
            all_records = self._repo.list_all_records()
            categories = list({r.remediation_category for r in all_records})

        for category in categories:
            self._update_aggregate(category)

        self._db.commit()

        return {
            "tenant_id": self._tenant_id,
            "categories_recalculated": len(categories),
            "control_id_filter": request.control_id,
            "recalculated_at": now,
        }
