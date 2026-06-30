"""services/report_authority/repository.py — Tenant-scoped data access for Report Authority.

Every query ALWAYS includes a tenant_id predicate.
This is the only code that touches fa_report_* tables directly.

SQLAlchemy Session (sync) — consistent with the rest of fg-core.

ORM models are imported from api.db_models_report_authority. Adjust once that
module is created; the TYPE_CHECKING guard prevents circular imports during
the bootstrap phase.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from api.db_models_report_authority import (
    FaReport,
    FaReportAuditEvent,
    FaReportBundle,
)


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class ReportRepository:
    """Tenant-scoped data access for fa_report* tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # fa_reports
    # ------------------------------------------------------------------

    def get_report(self, report_id: str) -> Optional[FaReport]:
        """Return the report row for this tenant, or None if not found."""
        return (
            self._db.query(FaReport)
            .filter(
                FaReport.id == report_id,
                FaReport.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_reports(
        self,
        *,
        report_type: Optional[str] = None,
        lifecycle_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[FaReport], int]:
        """Return (items, total) — always tenant-scoped."""
        q = self._db.query(FaReport).filter(FaReport.tenant_id == self._tenant_id)
        if report_type is not None:
            q = q.filter(FaReport.report_type == report_type)
        if lifecycle_state is not None:
            q = q.filter(FaReport.lifecycle_state == lifecycle_state)
        total: int = q.count()
        items: list[FaReport] = (
            q.order_by(FaReport.created_at.desc()).offset(offset).limit(limit).all()
        )
        return items, total

    def create_report(self, row: FaReport) -> FaReport:
        """Persist a new report row and flush to obtain the DB-assigned state."""
        self._db.add(row)
        self._db.flush()
        return row

    def save_report(self, row: FaReport) -> FaReport:
        """Flush pending changes for an already-tracked report row."""
        self._db.flush()
        return row

    def lock_report_for_update(self, report_id: str) -> Optional[FaReport]:
        """Acquire a SELECT … FOR UPDATE lock on the report row.

        Serializes concurrent state transitions. SQLite ignores the hint,
        making this safe in the test environment without branching.
        """
        return (
            self._db.query(FaReport)
            .filter(
                FaReport.id == report_id,
                FaReport.tenant_id == self._tenant_id,
            )
            .with_for_update()
            .first()
        )

    # ------------------------------------------------------------------
    # fa_report_audit_events
    # ------------------------------------------------------------------

    def create_audit_event(
        self,
        *,
        report_id: str,
        event_type: str,
        actor_id: str,
        actor_type: str,
        from_state: Optional[str],
        to_state: Optional[str],
        reason: Optional[str],
        event_metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Append an immutable audit event — never raises on metadata shape."""
        import uuid
        import json as _json

        row = FaReportAuditEvent(
            id=str(uuid.uuid4()),
            tenant_id=self._tenant_id,
            report_id=report_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            event_metadata=_json.dumps(event_metadata or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()

    def list_audit_events(self, report_id: str) -> list[FaReportAuditEvent]:
        """Return all audit events for a report in ascending chronological order."""
        return (
            self._db.query(FaReportAuditEvent)
            .filter(
                FaReportAuditEvent.tenant_id == self._tenant_id,
                FaReportAuditEvent.report_id == report_id,
            )
            .order_by(FaReportAuditEvent.created_at.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # fa_report_bundles
    # ------------------------------------------------------------------

    def get_bundle(self, bundle_id: str) -> Optional[FaReportBundle]:
        """Return the bundle row for this tenant, or None."""
        return (
            self._db.query(FaReportBundle)
            .filter(
                FaReportBundle.id == bundle_id,
                FaReportBundle.tenant_id == self._tenant_id,
            )
            .first()
        )

    def get_bundle_for_report(self, report_id: str) -> Optional[FaReportBundle]:
        """Return the most recent bundle for a report, or None."""
        return (
            self._db.query(FaReportBundle)
            .filter(
                FaReportBundle.report_id == report_id,
                FaReportBundle.tenant_id == self._tenant_id,
            )
            .order_by(FaReportBundle.created_at.desc())
            .first()
        )

    def create_bundle(self, row: FaReportBundle) -> FaReportBundle:
        """Persist a new bundle row and flush."""
        self._db.add(row)
        self._db.flush()
        return row

    def save_bundle(self, row: FaReportBundle) -> FaReportBundle:
        """Flush pending changes for an already-tracked bundle row."""
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Statistics aggregation
    # ------------------------------------------------------------------

    def get_statistics(self) -> dict[str, Any]:
        """Return raw aggregation data for this tenant's reports.

        The engine converts this into a ReportStatisticsResponse schema object.
        """
        from sqlalchemy import func as sa_func
        from datetime import date

        total: int = (
            self._db.query(FaReport)
            .filter(FaReport.tenant_id == self._tenant_id)
            .count()
        )

        by_type_rows = (
            self._db.query(
                FaReport.report_type,
                sa_func.count(FaReport.id).label("cnt"),
            )
            .filter(FaReport.tenant_id == self._tenant_id)
            .group_by(FaReport.report_type)
            .all()
        )

        by_state_rows = (
            self._db.query(
                FaReport.lifecycle_state,
                sa_func.count(FaReport.id).label("cnt"),
            )
            .filter(FaReport.tenant_id == self._tenant_id)
            .group_by(FaReport.lifecycle_state)
            .all()
        )

        by_grade_rows = (
            self._db.query(
                FaReport.quality_grade,
                sa_func.count(FaReport.id).label("cnt"),
            )
            .filter(FaReport.tenant_id == self._tenant_id)
            .group_by(FaReport.quality_grade)
            .all()
        )

        # Reports created in the current calendar month
        today = date.today()
        month_prefix = f"{today.year}-{today.month:02d}"
        generated_this_month: int = (
            self._db.query(FaReport)
            .filter(
                FaReport.tenant_id == self._tenant_id,
                FaReport.created_at.like(f"{month_prefix}%"),
            )
            .count()
        )

        return {
            "total": total,
            "by_type": {row.report_type: row.cnt for row in by_type_rows},
            "by_lifecycle_state": {
                row.lifecycle_state: row.cnt for row in by_state_rows
            },
            "by_quality_grade": {
                (row.quality_grade or "__unknown__"): row.cnt for row in by_grade_rows
            },
            "generated_this_month": generated_this_month,
        }
