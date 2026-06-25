"""services/freshness_score_history/engine.py — Business logic for Freshness Score History.

Idempotent snapshot creation with trend analytics.
All trend calculations are pure arithmetic.

PR 14.6.8 — Freshness Score History & Governance Trend Intelligence
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_evidence_freshness_authority import FaEvidenceFreshnessRecord
from api.db_models_freshness_score_history import (
    FaFreshnessDailySnapshot,
    FaFreshnessScoreSnapshot,
    FaFreshnessTrendSnapshot,
)
from services.freshness_score_history.models import (
    TrendDirection,
    compute_score_delta,
    compute_trend_direction,
)
from services.freshness_score_history.repository import FreshnessScoreHistoryRepository
from services.freshness_score_history.schemas import (
    FreshnessCGINTrendSnapshot,
    FreshnessGovernanceForecast,
    FreshnessHistoryResponse,
    FreshnessScoreSnapshotResponse,
    FreshnessTrendDashboardResponse,
    FreshnessTrendHistoryResponse,
    FreshnessTrendResponse,
    FreshnessTrendSnapshotResponse,
    RunSnapshotRequest,
    RunSnapshotResponse,
)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _today_str() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _date_n_days_ago(n: int) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d")


class FreshnessScoreHistoryEngine:
    """Business logic engine for Freshness Score History."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = FreshnessScoreHistoryRepository(db, tenant_id)

    def _emit_timeline_event(
        self, source_id: str, event_type: str, payload: dict
    ) -> None:
        try:
            from services.governance.timeline.adapters import (
                freshness_score_history_to_timeline_event,
            )
            from services.governance.timeline.store import TimelineStore

            event = freshness_score_history_to_timeline_event(
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

    def _to_snapshot_response(
        self, row: FaFreshnessScoreSnapshot
    ) -> FreshnessScoreSnapshotResponse:
        return FreshnessScoreSnapshotResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            evidence_id=row.evidence_id,
            freshness_record_id=row.freshness_record_id,
            freshness_score=row.freshness_score,
            freshness_state=row.freshness_state,
            review_due_at=row.review_due_at,
            verification_due_at=row.verification_due_at,
            expiration_due_at=row.expiration_due_at,
            captured_at=row.captured_at,
            capture_date=row.capture_date,
        )

    def run_snapshot(
        self,
        req: RunSnapshotRequest,
        actor_id: str,
        actor_type: str,
    ) -> RunSnapshotResponse:
        now = _now_iso()
        capture_date = req.capture_date if req.capture_date else _today_str()

        existing_daily = self._repo.get_daily_snapshot_for_date(capture_date)
        if existing_daily is not None:
            return RunSnapshotResponse(
                capture_date=capture_date,
                evidence_snapshots_created=0,
                daily_snapshot_created=False,
                already_exists=True,
                captured_at=now,
            )

        records = (
            self._db.query(FaEvidenceFreshnessRecord)
            .filter(FaEvidenceFreshnessRecord.tenant_id == self._tenant_id)
            .all()
        )

        evidence_snapshots_created = 0
        fresh_count = 0
        due_soon_count = 0
        review_required_count = 0
        verification_required_count = 0
        expired_count = 0
        coverage_at_risk_count = 0
        total_score = 0

        for record in records:
            existing_snap = self._repo.get_score_snapshot_by_evidence_date(
                record.evidence_id, capture_date
            )
            if existing_snap is not None:
                continue

            snap = FaFreshnessScoreSnapshot(
                id=_new_id(),
                tenant_id=self._tenant_id,
                evidence_id=record.evidence_id,
                freshness_record_id=record.id,
                freshness_score=record.freshness_score,
                freshness_state=record.freshness_state,
                review_due_at=record.review_due_at,
                verification_due_at=record.verification_due_at,
                expiration_due_at=record.expiration_due_at,
                captured_at=now,
                capture_date=capture_date,
            )
            self._repo.create_score_snapshot(snap)
            evidence_snapshots_created += 1

            state = record.freshness_state
            total_score += record.freshness_score
            if state == "CURRENT":
                fresh_count += 1
            elif state == "DUE_SOON":
                due_soon_count += 1
            elif state == "REVIEW_REQUIRED":
                review_required_count += 1
                coverage_at_risk_count += 1
            elif state == "VERIFICATION_REQUIRED":
                verification_required_count += 1
                coverage_at_risk_count += 1
            elif state == "EXPIRED":
                expired_count += 1
                coverage_at_risk_count += 1

        total_evidence = len(records)
        avg_score = (
            round(total_score / total_evidence, 2) if total_evidence > 0 else 0.0
        )

        daily_snap = FaFreshnessDailySnapshot(
            id=_new_id(),
            tenant_id=self._tenant_id,
            average_freshness_score=avg_score,
            fresh_evidence_count=fresh_count,
            due_soon_count=due_soon_count,
            review_required_count=review_required_count,
            verification_required_count=verification_required_count,
            expired_count=expired_count,
            coverage_at_risk_count=coverage_at_risk_count,
            total_evidence_count=total_evidence,
            captured_at=now,
            capture_date=capture_date,
        )
        self._repo.create_daily_snapshot(daily_snap)
        self._db.commit()

        # Persist trend snapshots for 7d / 30d / 90d windows
        for period_days, period_label in ((7, "7d"), (30, "30d"), (90, "90d")):
            try:
                since = _date_n_days_ago(period_days)
                hist = self._repo.list_daily_snapshots_since(
                    since, limit=period_days + 1
                )
                baseline = hist[0] if hist else None
                t_delta: Optional[float] = None
                t_fresh: Optional[int] = None
                t_expired: Optional[int] = None
                t_cov: Optional[int] = None
                if baseline is not None and baseline.capture_date != capture_date:
                    t_delta = compute_score_delta(
                        avg_score, baseline.average_freshness_score
                    )
                    t_fresh = (
                        fresh_count - baseline.fresh_evidence_count
                    )
                    t_expired = (
                        expired_count - baseline.expired_count
                    )
                    t_cov = (
                        coverage_at_risk_count - baseline.coverage_at_risk_count
                    )
                trend_row = FaFreshnessTrendSnapshot(
                    id=_new_id(),
                    tenant_id=self._tenant_id,
                    period=period_label,
                    average_score=avg_score,
                    score_delta=t_delta,
                    fresh_delta=t_fresh,
                    expired_delta=t_expired,
                    coverage_risk_delta=t_cov,
                    generated_at=now,
                )
                self._repo.create_trend_snapshot(trend_row)
            except Exception:
                pass

        self._db.commit()

        try:
            from api.observability.metrics import FRESHNESS_SNAPSHOTS_CREATED_TOTAL

            FRESHNESS_SNAPSHOTS_CREATED_TOTAL.inc()
        except Exception:
            pass

        self._emit_timeline_event(
            daily_snap.id,
            "freshness.snapshot.created",
            {
                "capture_date": capture_date,
                "evidence_snapshots_created": evidence_snapshots_created,
                "avg_score": avg_score,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        prior_daily = (
            self._db.query(FaFreshnessDailySnapshot)
            .filter(
                FaFreshnessDailySnapshot.tenant_id == self._tenant_id,
                FaFreshnessDailySnapshot.capture_date < capture_date,
            )
            .order_by(FaFreshnessDailySnapshot.capture_date.desc())
            .first()
        )
        if prior_daily is not None:
            delta = compute_score_delta(avg_score, prior_daily.average_freshness_score)
            direction = compute_trend_direction(delta)
            if direction == TrendDirection.IMPROVING:
                try:
                    from api.observability.metrics import (
                        FRESHNESS_IMPROVEMENT_DETECTED_TOTAL,
                    )

                    FRESHNESS_IMPROVEMENT_DETECTED_TOTAL.inc()
                except Exception:
                    pass
                self._emit_timeline_event(
                    daily_snap.id,
                    "freshness.improvement.detected",
                    {"score_delta": delta, "capture_date": capture_date},
                )
            elif direction in (TrendDirection.DEGRADING, TrendDirection.CRITICAL):
                try:
                    from api.observability.metrics import FRESHNESS_DECAY_DETECTED_TOTAL

                    FRESHNESS_DECAY_DETECTED_TOTAL.inc()
                except Exception:
                    pass
                self._emit_timeline_event(
                    daily_snap.id,
                    "freshness.decay.detected",
                    {
                        "score_delta": delta,
                        "trend_direction": direction.value,
                        "capture_date": capture_date,
                    },
                )

        return RunSnapshotResponse(
            capture_date=capture_date,
            evidence_snapshots_created=evidence_snapshots_created,
            daily_snapshot_created=True,
            already_exists=False,
            captured_at=now,
        )

    def get_evidence_history(
        self,
        evidence_id: str,
        days: int,
        limit: int,
        offset: int,
    ) -> FreshnessHistoryResponse:
        since_date = _date_n_days_ago(days)
        snapshots_since = self._repo.get_score_snapshots_since(evidence_id, since_date)

        if not snapshots_since:
            # No data within the requested window — check if evidence has any history
            check_items, _ = self._repo.list_score_snapshots_for_evidence(
                evidence_id, limit=1, offset=0
            )
            if not check_items:
                from services.freshness_score_history.schemas import (
                    FreshnessSnapshotNotFound,
                )

                raise FreshnessSnapshotNotFound(evidence_id)
            # Evidence has history but none within the days window
            return FreshnessHistoryResponse(
                evidence_id=evidence_id,
                tenant_id=self._tenant_id,
                snapshots=[],
                total=0,
                trend_direction=TrendDirection.STABLE.value,
                score_delta_7d=None,
                score_delta_30d=None,
            )

        items, total = self._repo.list_score_snapshots_for_evidence(
            evidence_id, limit, offset, since_date=since_date
        )

        score_delta_7d: Optional[float] = None
        score_delta_30d: Optional[float] = None

        if len(snapshots_since) >= 2:
            latest_score = float(snapshots_since[-1].freshness_score)

            date_7d_ago = _date_n_days_ago(7)
            snapshots_7d = [s for s in snapshots_since if s.capture_date >= date_7d_ago]
            if len(snapshots_7d) >= 2:
                score_delta_7d = compute_score_delta(
                    latest_score, float(snapshots_7d[0].freshness_score)
                )

            date_30d_ago = _date_n_days_ago(30)
            snapshots_30d = [
                s for s in snapshots_since if s.capture_date >= date_30d_ago
            ]
            if len(snapshots_30d) >= 2:
                score_delta_30d = compute_score_delta(
                    latest_score, float(snapshots_30d[0].freshness_score)
                )

        trend_direction: Optional[str] = None
        if score_delta_30d is not None:
            trend_direction = compute_trend_direction(score_delta_30d).value
        elif score_delta_7d is not None:
            trend_direction = compute_trend_direction(score_delta_7d).value
        else:
            trend_direction = TrendDirection.STABLE.value

        try:
            from api.observability.metrics import FRESHNESS_HISTORY_RECORDS_TOTAL

            FRESHNESS_HISTORY_RECORDS_TOTAL.inc()
        except Exception:
            pass

        return FreshnessHistoryResponse(
            evidence_id=evidence_id,
            tenant_id=self._tenant_id,
            snapshots=[self._to_snapshot_response(r) for r in items],
            total=total,
            trend_direction=trend_direction,
            score_delta_7d=score_delta_7d,
            score_delta_30d=score_delta_30d,
        )

    def get_trends(self, period_days: int) -> FreshnessTrendResponse:
        now = _now_iso()
        current = self._repo.get_latest_daily_snapshot()

        if current is None:
            return FreshnessTrendResponse(
                tenant_id=self._tenant_id,
                period_days=period_days,
                current_avg_score=0.0,
                baseline_avg_score=None,
                score_delta=None,
                trend_direction=TrendDirection.STABLE.value,
                fresh_delta=None,
                expired_delta=None,
                coverage_risk_delta=None,
                generated_at=now,
            )

        since_date = _date_n_days_ago(period_days)
        snapshots = self._repo.list_daily_snapshots_since(
            since_date, limit=period_days + 1
        )

        baseline = snapshots[0] if snapshots else None
        current_avg = current.average_freshness_score

        score_delta: Optional[float] = None
        baseline_avg: Optional[float] = None
        fresh_delta: Optional[int] = None
        expired_delta: Optional[int] = None
        coverage_risk_delta: Optional[int] = None

        if baseline is not None and baseline.capture_date != current.capture_date:
            baseline_avg = baseline.average_freshness_score
            score_delta = compute_score_delta(current_avg, baseline_avg)
            fresh_delta = current.fresh_evidence_count - baseline.fresh_evidence_count
            expired_delta = current.expired_count - baseline.expired_count
            coverage_risk_delta = (
                current.coverage_at_risk_count - baseline.coverage_at_risk_count
            )

        trend_direction = (
            compute_trend_direction(score_delta).value
            if score_delta is not None
            else TrendDirection.STABLE.value
        )

        try:
            from api.observability.metrics import FRESHNESS_TRENDS_GENERATED_TOTAL

            FRESHNESS_TRENDS_GENERATED_TOTAL.inc()
        except Exception:
            pass

        return FreshnessTrendResponse(
            tenant_id=self._tenant_id,
            period_days=period_days,
            current_avg_score=current_avg,
            baseline_avg_score=baseline_avg,
            score_delta=score_delta,
            trend_direction=trend_direction,
            fresh_delta=fresh_delta,
            expired_delta=expired_delta,
            coverage_risk_delta=coverage_risk_delta,
            generated_at=now,
        )

    def get_trends_dashboard(self) -> FreshnessTrendDashboardResponse:
        now = _now_iso()
        current = self._repo.get_latest_daily_snapshot()

        if current is None:
            return FreshnessTrendDashboardResponse(
                tenant_id=self._tenant_id,
                current_avg_score=0.0,
                score_delta_7d=None,
                score_delta_30d=None,
                score_delta_90d=None,
                trend_direction=TrendDirection.STABLE.value,
                freshness_velocity=None,
                coverage_velocity=None,
                risk_velocity=None,
                generated_at=now,
            )

        current_avg = current.average_freshness_score
        since_90d = _date_n_days_ago(90)
        snapshots = self._repo.list_daily_snapshots_since(since_90d, limit=91)

        def _delta_for_period(days: int) -> Optional[float]:
            cutoff = _date_n_days_ago(days)
            lower_bound = _date_n_days_ago(days * 2)
            candidates = [
                s for s in snapshots
                if lower_bound <= s.capture_date <= cutoff
            ]
            if not candidates:
                return None
            baseline = candidates[-1]
            if baseline.capture_date == current.capture_date:
                return None
            return compute_score_delta(current_avg, baseline.average_freshness_score)

        score_delta_7d = _delta_for_period(7)
        score_delta_30d = _delta_for_period(30)
        score_delta_90d = _delta_for_period(90)

        primary_delta = (
            score_delta_30d if score_delta_30d is not None else score_delta_7d
        )
        trend_direction = (
            compute_trend_direction(primary_delta).value
            if primary_delta is not None
            else TrendDirection.STABLE.value
        )

        freshness_velocity: Optional[float] = None
        coverage_velocity: Optional[float] = None
        risk_velocity: Optional[float] = None

        if score_delta_30d is not None:
            freshness_velocity = round(score_delta_30d / 30.0, 4)
        elif score_delta_7d is not None:
            freshness_velocity = round(score_delta_7d / 7.0, 4)

        if len(snapshots) >= 2:
            oldest = snapshots[0]
            period = len(snapshots)
            if period > 0:
                cov_delta = (
                    current.coverage_at_risk_count - oldest.coverage_at_risk_count
                )
                coverage_velocity = round(cov_delta / period, 4)
                risk_vel_raw = current.expired_count - oldest.expired_count
                risk_velocity = round(risk_vel_raw / period, 4)

        return FreshnessTrendDashboardResponse(
            tenant_id=self._tenant_id,
            current_avg_score=current_avg,
            score_delta_7d=score_delta_7d,
            score_delta_30d=score_delta_30d,
            score_delta_90d=score_delta_90d,
            trend_direction=trend_direction,
            freshness_velocity=freshness_velocity,
            coverage_velocity=coverage_velocity,
            risk_velocity=risk_velocity,
            generated_at=now,
        )

    def get_cgin_trends(self) -> FreshnessCGINTrendSnapshot:
        now = _now_iso()
        current = self._repo.get_latest_daily_snapshot()

        if current is None:
            return FreshnessCGINTrendSnapshot(
                tenant_id=self._tenant_id,
                average_score=0.0,
                score_delta_30d=None,
                score_delta_90d=None,
                coverage_risk_delta=None,
                improvement_velocity=None,
                generated_at=now,
            )

        current_avg = current.average_freshness_score
        since_90d = _date_n_days_ago(90)
        snapshots = self._repo.list_daily_snapshots_since(since_90d, limit=91)

        def _delta_for_period(days: int) -> Optional[float]:
            cutoff = _date_n_days_ago(days)
            lower_bound = _date_n_days_ago(days * 2)
            candidates = [
                s for s in snapshots
                if lower_bound <= s.capture_date <= cutoff
            ]
            if not candidates:
                return None
            baseline = candidates[-1]
            if baseline.capture_date == current.capture_date:
                return None
            return compute_score_delta(current_avg, baseline.average_freshness_score)

        score_delta_30d = _delta_for_period(30)
        score_delta_90d = _delta_for_period(90)

        coverage_risk_delta: Optional[int] = None
        cutoff_30d = _date_n_days_ago(30)
        lower_bound_30d = _date_n_days_ago(60)
        candidates_30d = [
            s for s in snapshots
            if lower_bound_30d <= s.capture_date <= cutoff_30d
        ]
        if candidates_30d:
            baseline_30d = candidates_30d[-1]
            if baseline_30d.capture_date != current.capture_date:
                coverage_risk_delta = (
                    current.coverage_at_risk_count - baseline_30d.coverage_at_risk_count
                )

        improvement_velocity: Optional[float] = None
        if score_delta_30d is not None and score_delta_30d > 0:
            improvement_velocity = round(score_delta_30d / 30.0, 4)

        return FreshnessCGINTrendSnapshot(
            tenant_id=self._tenant_id,
            average_score=current_avg,
            score_delta_30d=score_delta_30d,
            score_delta_90d=score_delta_90d,
            coverage_risk_delta=coverage_risk_delta,
            improvement_velocity=improvement_velocity,
            generated_at=now,
        )

    def get_trend_history(
        self,
        period: str,
        limit: int,
        offset: int,
    ) -> FreshnessTrendHistoryResponse:
        items, total = self._repo.list_trend_snapshots(
            period=period, limit=limit, offset=offset
        )
        return FreshnessTrendHistoryResponse(
            tenant_id=self._tenant_id,
            period=period,
            items=[
                FreshnessTrendSnapshotResponse(
                    id=r.id,
                    tenant_id=r.tenant_id,
                    period=r.period,
                    average_score=r.average_score,
                    score_delta=r.score_delta,
                    fresh_delta=r.fresh_delta,
                    expired_delta=r.expired_delta,
                    coverage_risk_delta=r.coverage_risk_delta,
                    generated_at=r.generated_at,
                )
                for r in items
            ],
            total=total,
        )

    def get_forecast(
        self,
        early_warning_threshold: int = 50,
        early_warning_horizon_days: int = 90,
    ) -> FreshnessGovernanceForecast:
        now = _now_iso()
        current = self._repo.get_latest_daily_snapshot()

        if current is None:
            return FreshnessGovernanceForecast(
                tenant_id=self._tenant_id,
                current_avg_score=0.0,
                velocity_per_day=None,
                forecast_30d=None,
                forecast_60d=None,
                forecast_90d=None,
                early_warning=False,
                early_warning_threshold=early_warning_threshold,
                early_warning_horizon_days=early_warning_horizon_days,
                days_until_threshold=None,
                trend_direction=TrendDirection.STABLE.value,
                generated_at=now,
            )

        current_avg = current.average_freshness_score

        # Derive velocity from 30d delta (preferred) or 7d
        velocity_per_day: Optional[float] = None
        trend_direction = TrendDirection.STABLE.value
        since_30d = _date_n_days_ago(30)
        snapshots_30d = self._repo.list_daily_snapshots_since(since_30d, limit=31)
        if len(snapshots_30d) >= 2:
            baseline_30d = snapshots_30d[0]
            if baseline_30d.capture_date != current.capture_date:
                delta_30d = compute_score_delta(
                    current_avg, baseline_30d.average_freshness_score
                )
                velocity_per_day = round(delta_30d / 30.0, 4)
                trend_direction = compute_trend_direction(delta_30d).value
        if velocity_per_day is None:
            since_7d = _date_n_days_ago(7)
            snapshots_7d = self._repo.list_daily_snapshots_since(since_7d, limit=8)
            if len(snapshots_7d) >= 2:
                baseline_7d = snapshots_7d[0]
                if baseline_7d.capture_date != current.capture_date:
                    delta_7d = compute_score_delta(
                        current_avg, baseline_7d.average_freshness_score
                    )
                    velocity_per_day = round(delta_7d / 7.0, 4)
                    trend_direction = compute_trend_direction(delta_7d).value

        def _project(horizon: int) -> Optional[float]:
            if velocity_per_day is None:
                return None
            return round(max(0.0, min(100.0, current_avg + velocity_per_day * horizon)), 2)

        forecast_30d = _project(30)
        forecast_60d = _project(60)
        forecast_90d = _project(90)

        # Early warning: will score breach threshold within horizon?
        early_warning = False
        days_until_threshold: Optional[int] = None
        if velocity_per_day is not None and velocity_per_day < 0:
            # days until score hits threshold: (current - threshold) / abs(velocity)
            days_raw = (current_avg - early_warning_threshold) / abs(velocity_per_day)
            if 0 < days_raw <= early_warning_horizon_days:
                early_warning = True
                days_until_threshold = max(0, int(days_raw))

        return FreshnessGovernanceForecast(
            tenant_id=self._tenant_id,
            current_avg_score=current_avg,
            velocity_per_day=velocity_per_day,
            forecast_30d=forecast_30d,
            forecast_60d=forecast_60d,
            forecast_90d=forecast_90d,
            early_warning=early_warning,
            early_warning_threshold=early_warning_threshold,
            early_warning_horizon_days=early_warning_horizon_days,
            days_until_threshold=days_until_threshold,
            trend_direction=trend_direction,
            generated_at=now,
        )
