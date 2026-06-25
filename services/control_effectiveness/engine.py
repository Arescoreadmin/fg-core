"""services/control_effectiveness/engine.py — Control Effectiveness Engine.

Deterministic scoring. No AI. No heuristics without documentation.
All scores 0-100. Same inputs always produce the same outputs.

SCORING MODEL v1 (see models.py for weights):
  Coverage          20%
  Verification      20%
  Freshness         15%
  Trend             15%
  Forecast          10%
  Evidence Density  10%
  Exception         10%

PR 16.5 — Control Effectiveness Engine
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_control_effectiveness import (
    FaControlEffectiveness,
    FaControlEffectivenessHistory,
)
from api.db_models_evidence_authority import (
    FaEvidence,
    FaEvidenceControlLink,
    FaVerification,
)
from api.db_models_evidence_freshness_authority import (
    FaEvidenceFreshnessRecord,
    FaFreshnessException,
)
from api.db_models_freshness_score_history import FaFreshnessScoreSnapshot
from services.control_effectiveness.models import (
    SCORING_MODEL_VERSION,
    EffectivenessLevel,
    classify_effectiveness,
    classify_risk,
    classify_trend,
    compute_effectiveness_score,
)
from services.control_effectiveness.repository import ControlEffectivenessRepository
from services.control_effectiveness.schemas import (
    CGINEffectivenessSnapshot,
    ControlEffectivenessDashboardResponse,
    ControlEffectivenessHistoryItem,
    ControlEffectivenessHistoryResponse,
    ControlEffectivenessListResponse,
    ControlEffectivenessResponse,
    ControlNotFound,
    RecalculateResponse,
)

# Lifecycle states that mean evidence is no longer active
_INACTIVE_STATES = {"REVOKED", "EXPIRED", "ARCHIVED"}
# Trust states indicating verification-grade confidence
_VERIFIED_STATES = {"VERIFIED", "HIGH_CONFIDENCE"}
# Verification result values that count as success
_PASSING_RESULTS = {"PASS", "APPROVED", "VERIFIED"}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _date_n_days_ago(n: int) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d")


def _days_between(date_a: str, date_b: str) -> int:
    """Return date_b - date_a in days. Positive means date_b is later."""
    try:
        a = date.fromisoformat(date_a[:10])
        b = date.fromisoformat(date_b[:10])
        return (b - a).days
    except Exception:
        return 0


class ControlEffectivenessEngine:
    """Deterministic control effectiveness scoring engine."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = ControlEffectivenessRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Internal: linked evidence
    # ------------------------------------------------------------------

    def _get_linked_evidence_ids(self, control_id: str) -> list[str]:
        rows = (
            self._db.query(FaEvidenceControlLink.evidence_id)
            .filter(
                FaEvidenceControlLink.tenant_id == self._tenant_id,
                FaEvidenceControlLink.control_id == control_id,
            )
            .all()
        )
        return [r[0] for r in rows]

    # ------------------------------------------------------------------
    # Component: Coverage (20%)
    # Coverage measures how well a control is supported by evidence.
    # Base: 10 points per piece of evidence, capped at 100 (10+ = full base).
    # Blend: 60% evidence existence, 40% trust-state verification ratio.
    # ------------------------------------------------------------------

    def _compute_coverage_score(self, control_id: str) -> float:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 0.0
        evidence = (
            self._db.query(FaEvidence)
            .filter(
                FaEvidence.tenant_id == self._tenant_id,
                FaEvidence.id.in_(evidence_ids),
            )
            .all()
        )
        if not evidence:
            return 0.0
        active = [e for e in evidence if e.lifecycle_state not in _INACTIVE_STATES]
        verified = [e for e in active if e.trust_state in _VERIFIED_STATES]
        base = min(100.0, len(evidence_ids) * 10.0)
        verified_ratio = len(verified) / max(1, len(active)) * 100.0
        return round(base * 0.6 + verified_ratio * 0.4, 2)

    # ------------------------------------------------------------------
    # Component: Verification (20%)
    # Measures verification success rate and recency.
    # Age penalty: >90d since last verification = -20; >180d = -40.
    # Failure penalty: 5 points per failure, capped at 30.
    # ------------------------------------------------------------------

    def _compute_verification_score(self, control_id: str) -> float:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 0.0
        verifications = (
            self._db.query(FaVerification)
            .filter(
                FaVerification.tenant_id == self._tenant_id,
                FaVerification.evidence_id.in_(evidence_ids),
            )
            .all()
        )
        if not verifications:
            return 0.0
        total = len(verifications)
        passing = sum(
            1 for v in verifications
            if v.verification_result in _PASSING_RESULTS
        )
        success_rate = passing / total * 100.0

        # Age penalty based on most recent verification
        now_iso = _now_iso()
        created_dates = [v.created_at for v in verifications if v.created_at]
        age_penalty = 0.0
        if created_dates:
            latest = max(created_dates)
            days_old = _days_between(latest[:10], now_iso[:10])
            if days_old > 180:
                age_penalty = 40.0
            elif days_old > 90:
                age_penalty = 20.0

        failure_count = total - passing
        failure_penalty = min(30.0, failure_count * 5.0)
        return round(max(0.0, min(100.0, success_rate - age_penalty - failure_penalty)), 2)

    # ------------------------------------------------------------------
    # Component: Freshness (15%)
    # Average freshness score across linked evidence freshness records.
    # Active exceptions add a small bonus (compensating controls).
    # Returns 50 (neutral) when no freshness data exists.
    # ------------------------------------------------------------------

    def _compute_freshness_score(self, control_id: str) -> float:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 50.0
        records = (
            self._db.query(FaEvidenceFreshnessRecord)
            .filter(
                FaEvidenceFreshnessRecord.tenant_id == self._tenant_id,
                FaEvidenceFreshnessRecord.evidence_id.in_(evidence_ids),
            )
            .all()
        )
        if not records:
            return 50.0
        avg_freshness = sum(r.freshness_score for r in records) / len(records)

        # Count active, non-expired exceptions (compensating controls)
        now_iso = _now_iso()
        exceptions = (
            self._db.query(FaFreshnessException)
            .filter(
                FaFreshnessException.tenant_id == self._tenant_id,
                FaFreshnessException.evidence_id.in_(evidence_ids),
                FaFreshnessException.status == "ACTIVE",
                FaFreshnessException.expires_at > now_iso,
            )
            .all()
        )
        bonus = min(10.0, len(exceptions) * 2.0)
        return round(min(100.0, avg_freshness + bonus), 2)

    # ------------------------------------------------------------------
    # Component: Trend (15%) — returns full tuple for all callers
    # Trend measures how control effectiveness is changing over time,
    # proxied by freshness score trajectory across linked evidence snapshots.
    # Baseline must be near the period cutoff (2× window constraint).
    # IMPROVING→80, STABLE→60, DEGRADING→35, CRITICAL→10
    # ------------------------------------------------------------------

    def _compute_trend_data(
        self, control_id: str
    ) -> tuple[float, str, Optional[float], Optional[float], Optional[float]]:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 50.0, "STABLE", None, None, None

        snapshots = (
            self._db.query(FaFreshnessScoreSnapshot)
            .filter(
                FaFreshnessScoreSnapshot.tenant_id == self._tenant_id,
                FaFreshnessScoreSnapshot.evidence_id.in_(evidence_ids),
            )
            .order_by(FaFreshnessScoreSnapshot.capture_date.asc())
            .all()
        )
        if not snapshots:
            return 50.0, "STABLE", None, None, None

        # Group by capture_date and compute per-date average
        date_scores: dict[str, list[float]] = {}
        for s in snapshots:
            date_scores.setdefault(s.capture_date, []).append(float(s.freshness_score))
        date_avgs = {d: sum(v) / len(v) for d, v in date_scores.items()}

        sorted_dates = sorted(date_avgs.keys())
        if len(sorted_dates) < 2:
            return 50.0, "STABLE", None, None, None

        latest_date = sorted_dates[-1]
        latest_avg = date_avgs[latest_date]

        def _delta_for_period(period_days: int) -> Optional[float]:
            cutoff = _date_n_days_ago(period_days)
            lower = _date_n_days_ago(period_days * 2)
            candidates = [d for d in sorted_dates if lower <= d <= cutoff]
            if not candidates:
                return None
            baseline_date = candidates[-1]
            if baseline_date == latest_date:
                return None
            return round(latest_avg - date_avgs[baseline_date], 2)

        delta_7d = _delta_for_period(7)
        delta_30d = _delta_for_period(30)
        delta_90d = _delta_for_period(90)

        primary_delta = delta_30d if delta_30d is not None else delta_7d
        if primary_delta is None:
            return 50.0, "STABLE", delta_7d, delta_30d, delta_90d

        direction = classify_trend(primary_delta)
        trend_score_map = {
            "IMPROVING": 80.0,
            "STABLE": 60.0,
            "DEGRADING": 35.0,
            "CRITICAL": 10.0,
        }
        trend_score = trend_score_map[direction.value]

        # Fine-tune within band based on magnitude
        if direction.value == "IMPROVING":
            trend_score = min(95.0, 80.0 + primary_delta * 0.5)
        elif direction.value == "CRITICAL":
            trend_score = max(5.0, 10.0 + primary_delta * 0.3)

        return round(trend_score, 2), direction.value, delta_7d, delta_30d, delta_90d

    # ------------------------------------------------------------------
    # Component: Forecast (10%)
    # Derives velocity from 30d freshness snapshot history for linked evidence.
    # Improving velocity → above 65; declining → below 65; clamped [10, 90].
    # ------------------------------------------------------------------

    def _compute_forecast_score(self, control_id: str) -> float:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 65.0

        cutoff_30d = _date_n_days_ago(30)
        lower_30d = _date_n_days_ago(60)
        snapshots = (
            self._db.query(FaFreshnessScoreSnapshot)
            .filter(
                FaFreshnessScoreSnapshot.tenant_id == self._tenant_id,
                FaFreshnessScoreSnapshot.evidence_id.in_(evidence_ids),
                FaFreshnessScoreSnapshot.capture_date >= lower_30d,
            )
            .order_by(FaFreshnessScoreSnapshot.capture_date.asc())
            .all()
        )
        if not snapshots:
            return 65.0

        # Group by date
        date_scores: dict[str, list[float]] = {}
        for s in snapshots:
            date_scores.setdefault(s.capture_date, []).append(float(s.freshness_score))
        date_avgs = {d: sum(v) / len(v) for d, v in date_scores.items()}
        sorted_dates = sorted(date_avgs.keys())
        if len(sorted_dates) < 2:
            return 65.0

        # Find baseline near 30d cutoff
        candidates = [d for d in sorted_dates if d <= cutoff_30d]
        if not candidates:
            return 65.0
        baseline_date = candidates[-1]
        latest_date = sorted_dates[-1]
        if baseline_date == latest_date:
            return 65.0

        actual_days = _days_between(baseline_date, latest_date)
        if actual_days <= 0:
            return 65.0

        velocity = (date_avgs[latest_date] - date_avgs[baseline_date]) / actual_days
        if velocity >= 0:
            score = 65.0 + min(25.0, velocity * 30.0)
        else:
            score = 65.0 + max(-55.0, velocity * 100.0)

        return round(min(90.0, max(10.0, score)), 2)

    # ------------------------------------------------------------------
    # Component: Evidence Density (10%)
    # Blends evidence count (40%), quality scores (40%), source diversity (20%).
    # 10+ pieces of evidence = full count score.
    # ------------------------------------------------------------------

    def _compute_evidence_density_score(self, control_id: str) -> float:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 0.0
        evidence = (
            self._db.query(FaEvidence)
            .filter(
                FaEvidence.tenant_id == self._tenant_id,
                FaEvidence.id.in_(evidence_ids),
            )
            .all()
        )
        if not evidence:
            return 0.0

        count_score = min(100.0, len(evidence) * 10.0)

        # Quality: average of freshness_score, verification_score, completeness_score
        quality_values = []
        for e in evidence:
            scores = [
                s for s in [e.freshness_score, e.verification_score, e.completeness_score]
                if s is not None
            ]
            if scores:
                quality_values.append(sum(scores) / len(scores))
        quality_score = sum(quality_values) / len(quality_values) if quality_values else 0.0

        # Diversity: distinct source systems / 3 × 100, capped at 100
        distinct_sources = len({e.source_system for e in evidence if e.source_system})
        diversity_score = min(100.0, distinct_sources / 3.0 * 100.0)

        return round(count_score * 0.4 + quality_score * 0.4 + diversity_score * 0.2, 2)

    # ------------------------------------------------------------------
    # Component: Exception (10%)
    # Open active exceptions reduce score. Active non-expired ones = open.
    # Expired exceptions apply a smaller penalty (they were compensating but lapsed).
    # Starts at 100; penalized by 8 per open exception, 3 per expired.
    # ------------------------------------------------------------------

    def _compute_exception_score(self, control_id: str) -> float:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 100.0
        now_iso = _now_iso()
        exceptions = (
            self._db.query(FaFreshnessException)
            .filter(
                FaFreshnessException.tenant_id == self._tenant_id,
                FaFreshnessException.evidence_id.in_(evidence_ids),
            )
            .all()
        )
        if not exceptions:
            return 100.0

        open_count = sum(
            1 for ex in exceptions
            if ex.status == "ACTIVE" and ex.expires_at > now_iso
        )
        expired_count = sum(
            1 for ex in exceptions
            if ex.expires_at <= now_iso
        )
        penalty = open_count * 8.0 + expired_count * 3.0
        return round(max(0.0, min(100.0, 100.0 - penalty)), 2)

    # ------------------------------------------------------------------
    # Governance health score — informational, not weighted
    # Composite signal of overdue freshness and open exceptions.
    # ------------------------------------------------------------------

    def _compute_governance_health_score(self, control_id: str) -> float:
        evidence_ids = self._get_linked_evidence_ids(control_id)
        if not evidence_ids:
            return 50.0
        overdue_states = {"REVIEW_REQUIRED", "VERIFICATION_REQUIRED", "EXPIRED"}
        overdue_freshness = (
            self._db.query(FaEvidenceFreshnessRecord)
            .filter(
                FaEvidenceFreshnessRecord.tenant_id == self._tenant_id,
                FaEvidenceFreshnessRecord.evidence_id.in_(evidence_ids),
                FaEvidenceFreshnessRecord.freshness_state.in_(overdue_states),
            )
            .count()
        )
        now_iso = _now_iso()
        open_exceptions = (
            self._db.query(FaFreshnessException)
            .filter(
                FaFreshnessException.tenant_id == self._tenant_id,
                FaFreshnessException.evidence_id.in_(evidence_ids),
                FaFreshnessException.status == "ACTIVE",
                FaFreshnessException.expires_at > now_iso,
            )
            .count()
        )
        penalty = overdue_freshness * 10.0 + open_exceptions * 5.0
        return round(max(0.0, 100.0 - min(100.0, penalty)), 2)

    # ------------------------------------------------------------------
    # ORM → schema conversion
    # ------------------------------------------------------------------

    def _to_response(self, row: FaControlEffectiveness) -> ControlEffectivenessResponse:
        return ControlEffectivenessResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            control_id=row.control_id,
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            effectiveness_risk=row.effectiveness_risk,
            coverage_score=row.coverage_score,
            verification_score=row.verification_score,
            freshness_score=row.freshness_score,
            trend_score=row.trend_score,
            forecast_score=row.forecast_score,
            evidence_density_score=row.evidence_density_score,
            exception_score=row.exception_score,
            governance_health_score=row.governance_health_score,
            trend_direction=row.trend_direction,
            score_delta_7d=row.score_delta_7d,
            score_delta_30d=row.score_delta_30d,
            score_delta_90d=row.score_delta_90d,
            last_calculated_at=row.last_calculated_at,
            calculation_version=row.calculation_version,
        )

    def _to_history_item(
        self, row: FaControlEffectivenessHistory
    ) -> ControlEffectivenessHistoryItem:
        return ControlEffectivenessHistoryItem(
            id=row.id,
            tenant_id=row.tenant_id,
            control_id=row.control_id,
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            effectiveness_risk=row.effectiveness_risk,
            coverage_score=row.coverage_score,
            verification_score=row.verification_score,
            freshness_score=row.freshness_score,
            trend_score=row.trend_score,
            captured_at=row.captured_at,
        )

    # ------------------------------------------------------------------
    # Public: recalculate (single control)
    # ------------------------------------------------------------------

    def recalculate(self, control_id: str) -> ControlEffectivenessResponse:
        if not self._get_linked_evidence_ids(control_id):
            raise ControlNotFound(control_id)

        now = _now_iso()

        coverage_score = self._compute_coverage_score(control_id)
        verification_score = self._compute_verification_score(control_id)
        freshness_score = self._compute_freshness_score(control_id)
        trend_score, trend_direction, delta_7d, delta_30d, delta_90d = (
            self._compute_trend_data(control_id)
        )
        forecast_score = self._compute_forecast_score(control_id)
        density_score = self._compute_evidence_density_score(control_id)
        exception_score = self._compute_exception_score(control_id)
        health_score = self._compute_governance_health_score(control_id)

        effectiveness_score = compute_effectiveness_score(
            coverage_score,
            verification_score,
            freshness_score,
            trend_score,
            forecast_score,
            density_score,
            exception_score,
        )
        level = classify_effectiveness(effectiveness_score)
        risk = classify_risk(level)

        # Upsert current record
        existing = self._repo.get_effectiveness(control_id)
        if existing is None:
            row = FaControlEffectiveness(
                id=_new_id(),
                tenant_id=self._tenant_id,
                control_id=control_id,
            )
        else:
            row = existing
        row.effectiveness_score = effectiveness_score
        row.effectiveness_level = level.value
        row.effectiveness_risk = risk.value
        row.coverage_score = coverage_score
        row.verification_score = verification_score
        row.freshness_score = freshness_score
        row.trend_score = trend_score
        row.forecast_score = forecast_score
        row.evidence_density_score = density_score
        row.exception_score = exception_score
        row.governance_health_score = health_score
        row.trend_direction = trend_direction
        row.score_delta_7d = delta_7d
        row.score_delta_30d = delta_30d
        row.score_delta_90d = delta_90d
        row.last_calculated_at = now
        row.calculation_version = SCORING_MODEL_VERSION
        self._repo.upsert_effectiveness(row)

        # Append history
        hist = FaControlEffectivenessHistory(
            id=_new_id(),
            tenant_id=self._tenant_id,
            control_id=control_id,
            effectiveness_score=effectiveness_score,
            effectiveness_level=level.value,
            effectiveness_risk=risk.value,
            coverage_score=coverage_score,
            verification_score=verification_score,
            freshness_score=freshness_score,
            trend_score=trend_score,
            captured_at=now,
        )
        self._repo.create_history(hist)
        self._db.commit()

        # Prometheus — try/except protected, never blocks governance
        try:
            from api.observability.metrics import (
                CONTROL_EFFECTIVENESS_CALCULATIONS_TOTAL,
                CONTROL_EFFECTIVENESS_HISTORY_RECORDS_TOTAL,
            )
            CONTROL_EFFECTIVENESS_CALCULATIONS_TOTAL.inc()
            CONTROL_EFFECTIVENESS_HISTORY_RECORDS_TOTAL.inc()
        except Exception:
            pass

        if delta_30d is not None:
            if delta_30d > 5:
                try:
                    from api.observability.metrics import (
                        CONTROL_EFFECTIVENESS_IMPROVEMENT_TOTAL,
                    )
                    CONTROL_EFFECTIVENESS_IMPROVEMENT_TOTAL.inc()
                except Exception:
                    pass
            elif delta_30d < -5:
                try:
                    from api.observability.metrics import (
                        CONTROL_EFFECTIVENESS_DEGRADATION_TOTAL,
                    )
                    CONTROL_EFFECTIVENESS_DEGRADATION_TOTAL.inc()
                except Exception:
                    pass

        # Timeline event
        self._emit_timeline_event(
            row.id,
            "control_effectiveness.calculated",
            {
                "control_id": control_id,
                "effectiveness_score": effectiveness_score,
                "effectiveness_level": level.value,
                "effectiveness_risk": risk.value,
            },
        )

        return self._to_response(row)

    def _emit_timeline_event(
        self, source_id: str, event_type: str, payload: dict
    ) -> None:
        try:
            from services.governance.timeline.adapters import (
                control_effectiveness_to_timeline_event,
            )
            from services.governance.timeline.store import TimelineStore

            event = control_effectiveness_to_timeline_event(
                tenant_id=self._tenant_id,
                source_id=source_id,
                event_type=event_type,
                occurred_at=_now_iso(),
                payload=payload,
                replay_eligible=False,
            )
            store = TimelineStore()
            store.record(self._db, event)
            self._db.commit()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public: recalculate_all
    # ------------------------------------------------------------------

    def recalculate_all(self) -> RecalculateResponse:
        now = _now_iso()
        control_ids = self._repo.get_all_control_ids()
        count = 0
        for cid in control_ids:
            try:
                self.recalculate(cid)
                count += 1
            except Exception:
                pass
        try:
            from api.observability.metrics import (
                CONTROL_EFFECTIVENESS_RECALCULATIONS_TOTAL,
            )
            CONTROL_EFFECTIVENESS_RECALCULATIONS_TOTAL.inc()
        except Exception:
            pass
        return RecalculateResponse(
            tenant_id=self._tenant_id,
            controls_recalculated=count,
            control_id=None,
            calculated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: read methods
    # ------------------------------------------------------------------

    def get_effectiveness(self, control_id: str) -> ControlEffectivenessResponse:
        row = self._repo.get_effectiveness(control_id)
        if row is None:
            raise ControlNotFound(control_id)
        return self._to_response(row)

    def list_effectiveness(
        self, limit: int, offset: int
    ) -> ControlEffectivenessListResponse:
        items, total = self._repo.list_effectiveness(limit, offset)
        return ControlEffectivenessListResponse(
            tenant_id=self._tenant_id,
            items=[self._to_response(r) for r in items],
            total=total,
        )

    def get_history(
        self, control_id: str, limit: int, offset: int
    ) -> ControlEffectivenessHistoryResponse:
        items, total = self._repo.list_history(control_id, limit, offset)
        return ControlEffectivenessHistoryResponse(
            tenant_id=self._tenant_id,
            control_id=control_id,
            items=[self._to_history_item(r) for r in items],
            total=total,
        )

    def get_dashboard(self) -> ControlEffectivenessDashboardResponse:
        now = _now_iso()
        all_items = self._repo.list_all_effectiveness()
        total = len(all_items)

        if total == 0:
            return ControlEffectivenessDashboardResponse(
                tenant_id=self._tenant_id,
                total_controls=0,
                average_effectiveness_score=0.0,
                highly_effective_count=0,
                effective_count=0,
                adequate_count=0,
                weak_count=0,
                ineffective_count=0,
                critical_risk_count=0,
                high_risk_count=0,
                top_controls=[],
                weak_controls=[],
                high_risk_controls=[],
                fastest_improving=[],
                fastest_decaying=[],
                generated_at=now,
            )

        avg_score = round(
            sum(r.effectiveness_score for r in all_items) / total, 2
        )

        level_counts: dict[str, int] = {
            "HIGHLY_EFFECTIVE": 0, "EFFECTIVE": 0,
            "ADEQUATE": 0, "WEAK": 0, "INEFFECTIVE": 0,
        }
        for r in all_items:
            level_counts[r.effectiveness_level] = (
                level_counts.get(r.effectiveness_level, 0) + 1
            )

        critical_risk = sum(1 for r in all_items if r.effectiveness_risk == "CRITICAL")
        high_risk = sum(1 for r in all_items if r.effectiveness_risk == "HIGH")

        responses = [self._to_response(r) for r in all_items]
        top = sorted(responses, key=lambda x: x.effectiveness_score, reverse=True)[:5]
        weak = sorted(responses, key=lambda x: x.effectiveness_score)[:5]
        high_risk_list = [
            r for r in responses if r.effectiveness_risk in ("HIGH", "CRITICAL")
        ][:5]
        fastest_improving = sorted(
            [r for r in responses if r.score_delta_30d is not None],
            key=lambda x: x.score_delta_30d,  # type: ignore[arg-type]
            reverse=True,
        )[:5]
        fastest_decaying = sorted(
            [r for r in responses if r.score_delta_30d is not None],
            key=lambda x: x.score_delta_30d,  # type: ignore[arg-type]
        )[:5]

        return ControlEffectivenessDashboardResponse(
            tenant_id=self._tenant_id,
            total_controls=total,
            average_effectiveness_score=avg_score,
            highly_effective_count=level_counts["HIGHLY_EFFECTIVE"],
            effective_count=level_counts["EFFECTIVE"],
            adequate_count=level_counts["ADEQUATE"],
            weak_count=level_counts["WEAK"],
            ineffective_count=level_counts["INEFFECTIVE"],
            critical_risk_count=critical_risk,
            high_risk_count=high_risk,
            top_controls=top,
            weak_controls=weak,
            high_risk_controls=high_risk_list,
            fastest_improving=fastest_improving,
            fastest_decaying=fastest_decaying,
            generated_at=now,
        )

    def get_cgin_snapshot(self) -> CGINEffectivenessSnapshot:
        now = _now_iso()
        all_items = self._repo.list_all_effectiveness()
        total = len(all_items)

        if total == 0:
            return CGINEffectivenessSnapshot(
                tenant_id=self._tenant_id,
                average_effectiveness=0.0,
                effectiveness_distribution={
                    "HIGHLY_EFFECTIVE": 0, "EFFECTIVE": 0,
                    "ADEQUATE": 0, "WEAK": 0, "INEFFECTIVE": 0,
                },
                total_controls=0,
                high_risk_controls=0,
                critical_risk_controls=0,
                top_controls=[],
                weak_controls=[],
                generated_at=now,
            )

        avg = round(sum(r.effectiveness_score for r in all_items) / total, 2)
        distribution: dict[str, int] = {
            "HIGHLY_EFFECTIVE": 0, "EFFECTIVE": 0,
            "ADEQUATE": 0, "WEAK": 0, "INEFFECTIVE": 0,
        }
        for r in all_items:
            distribution[r.effectiveness_level] = (
                distribution.get(r.effectiveness_level, 0) + 1
            )
        high_risk = sum(
            1 for r in all_items if r.effectiveness_risk in ("HIGH", "CRITICAL")
        )
        critical_risk = sum(
            1 for r in all_items if r.effectiveness_risk == "CRITICAL"
        )
        top = [r.control_id for r in all_items if r.effectiveness_score >= 75]
        weak = [r.control_id for r in all_items if r.effectiveness_score < 60]

        return CGINEffectivenessSnapshot(
            tenant_id=self._tenant_id,
            average_effectiveness=avg,
            effectiveness_distribution=distribution,
            total_controls=total,
            high_risk_controls=high_risk,
            critical_risk_controls=critical_risk,
            top_controls=top,
            weak_controls=weak,
            generated_at=now,
        )
