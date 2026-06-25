"""services/freshness_score_history/repository.py — Data access for Freshness Score History.

All queries are tenant-scoped. No query path bypasses tenant_id.

PR 14.6.8 — Freshness Score History & Governance Trend Intelligence
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_freshness_score_history import (
    FaFreshnessDailySnapshot,
    FaFreshnessScoreSnapshot,
)


class FreshnessScoreHistoryRepository:
    """Tenant-scoped data access for fa_freshness_score_snapshots and fa_freshness_daily_snapshots."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # FaFreshnessScoreSnapshot
    # ------------------------------------------------------------------

    def create_score_snapshot(self, row: FaFreshnessScoreSnapshot) -> None:
        self._db.add(row)
        self._db.flush()

    def get_score_snapshot_by_evidence_date(
        self, evidence_id: str, capture_date: str
    ) -> Optional[FaFreshnessScoreSnapshot]:
        return (
            self._db.query(FaFreshnessScoreSnapshot)
            .filter(
                FaFreshnessScoreSnapshot.tenant_id == self._tenant_id,
                FaFreshnessScoreSnapshot.evidence_id == evidence_id,
                FaFreshnessScoreSnapshot.capture_date == capture_date,
            )
            .first()
        )

    def list_score_snapshots_for_evidence(
        self, evidence_id: str, limit: int, offset: int
    ) -> tuple[list[FaFreshnessScoreSnapshot], int]:
        q = self._db.query(FaFreshnessScoreSnapshot).filter(
            FaFreshnessScoreSnapshot.tenant_id == self._tenant_id,
            FaFreshnessScoreSnapshot.evidence_id == evidence_id,
        )
        total = q.count()
        items = (
            q.order_by(FaFreshnessScoreSnapshot.capture_date.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def get_score_snapshots_since(
        self, evidence_id: str, since_date: str
    ) -> list[FaFreshnessScoreSnapshot]:
        return (
            self._db.query(FaFreshnessScoreSnapshot)
            .filter(
                FaFreshnessScoreSnapshot.tenant_id == self._tenant_id,
                FaFreshnessScoreSnapshot.evidence_id == evidence_id,
                FaFreshnessScoreSnapshot.capture_date >= since_date,
            )
            .order_by(FaFreshnessScoreSnapshot.capture_date.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # FaFreshnessDailySnapshot
    # ------------------------------------------------------------------

    def create_daily_snapshot(self, row: FaFreshnessDailySnapshot) -> None:
        self._db.add(row)
        self._db.flush()

    def get_daily_snapshot_for_date(
        self, capture_date: str
    ) -> Optional[FaFreshnessDailySnapshot]:
        return (
            self._db.query(FaFreshnessDailySnapshot)
            .filter(
                FaFreshnessDailySnapshot.tenant_id == self._tenant_id,
                FaFreshnessDailySnapshot.capture_date == capture_date,
            )
            .first()
        )

    def list_daily_snapshots_since(
        self, since_date: str, limit: int
    ) -> list[FaFreshnessDailySnapshot]:
        return (
            self._db.query(FaFreshnessDailySnapshot)
            .filter(
                FaFreshnessDailySnapshot.tenant_id == self._tenant_id,
                FaFreshnessDailySnapshot.capture_date >= since_date,
            )
            .order_by(FaFreshnessDailySnapshot.capture_date.asc())
            .limit(limit)
            .all()
        )

    def get_latest_daily_snapshot(self) -> Optional[FaFreshnessDailySnapshot]:
        return (
            self._db.query(FaFreshnessDailySnapshot)
            .filter(FaFreshnessDailySnapshot.tenant_id == self._tenant_id)
            .order_by(FaFreshnessDailySnapshot.capture_date.desc())
            .first()
        )
