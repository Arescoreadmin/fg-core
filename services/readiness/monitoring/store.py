"""Monitoring run persistence store.

All methods take a SQLAlchemy Session. No module-level state. No side effects beyond DB.

Tenant isolation contract:
  - get_run() and list_runs() always filter by tenant_id.
  - Cross-tenant access returns None / empty list (no disclosure).
  - create_run() always records tenant_id from the monitoring context.

Immutability contract:
  - Monitoring runs are write-once; no update methods exist.
  - Stored snapshot_json is frozen at creation time.
  - Historical runs remain reconstructable.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .models import MonitoringRunRecord

logger = logging.getLogger("frostgate.readiness.monitoring.store")


class MonitoringRunNotFound(Exception):
    pass


class MonitoringRunTenantIsolationError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MonitoringRunStore:
    """Write-once persistence for immutable monitoring run records."""

    def create_run(
        self,
        db: Session,
        *,
        run_id: str,
        tenant_id: str,
        assessment_id: Optional[str],
        framework_ids: tuple[str, ...],
        eval_window_start_iso: str,
        eval_window_end_iso: str,
        monitoring_contract_version: str,
        evaluation_engine_version: str,
        snapshot_id: str,
        snapshot_json: str,
        domains_evaluated: tuple[str, ...],
        total_drift_events: int,
        critical_or_blocking_count: int,
        completed_at_iso: str,
        evaluation_success: bool,
        error_summary: Optional[str],
    ) -> MonitoringRunRecord:
        from api.db_models_monitoring import MonitoringRunModel

        now = _now()
        row = MonitoringRunModel(
            run_id=run_id,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            framework_ids_json=json.dumps(sorted(framework_ids)),
            eval_window_start_iso=eval_window_start_iso,
            eval_window_end_iso=eval_window_end_iso,
            monitoring_contract_version=monitoring_contract_version,
            evaluation_engine_version=evaluation_engine_version,
            snapshot_id=snapshot_id,
            snapshot_json=snapshot_json,
            domains_evaluated_json=json.dumps(list(domains_evaluated)),
            total_drift_events=total_drift_events,
            critical_or_blocking_count=critical_or_blocking_count,
            completed_at_iso=completed_at_iso,
            evaluation_success=evaluation_success,
            error_summary=error_summary,
            created_at=now,
        )
        db.add(row)
        db.flush()
        return self._to_domain(row)

    def get_run(
        self, db: Session, *, run_id: str, tenant_id: str
    ) -> MonitoringRunRecord:
        from api.db_models_monitoring import MonitoringRunModel

        row = db.query(MonitoringRunModel).filter_by(run_id=run_id).first()
        if row is None:
            raise MonitoringRunNotFound(run_id)
        if row.tenant_id != tenant_id:
            raise MonitoringRunTenantIsolationError(run_id)
        return self._to_domain(row)

    def list_runs(
        self,
        db: Session,
        *,
        tenant_id: str,
        assessment_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MonitoringRunRecord]:
        from api.db_models_monitoring import MonitoringRunModel

        q = db.query(MonitoringRunModel).filter_by(tenant_id=tenant_id)
        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)
        rows = (
            q.order_by(MonitoringRunModel.created_at.desc())
            .limit(min(limit, 200))
            .offset(offset)
            .all()
        )
        return [self._to_domain(r) for r in rows]

    def _to_domain(self, row) -> MonitoringRunRecord:  # type: ignore[no-untyped-def]
        return MonitoringRunRecord(
            run_id=row.run_id,
            tenant_id=row.tenant_id,
            assessment_id=row.assessment_id,
            framework_ids=tuple(json.loads(row.framework_ids_json or "[]")),
            eval_window_start_iso=row.eval_window_start_iso,
            eval_window_end_iso=row.eval_window_end_iso,
            monitoring_contract_version=row.monitoring_contract_version,
            evaluation_engine_version=row.evaluation_engine_version,
            snapshot_id=row.snapshot_id,
            snapshot_json=row.snapshot_json,
            domains_evaluated=tuple(json.loads(row.domains_evaluated_json or "[]")),
            total_drift_events=row.total_drift_events,
            critical_or_blocking_count=row.critical_or_blocking_count,
            completed_at_iso=row.completed_at_iso,
            evaluation_success=row.evaluation_success,
            error_summary=row.error_summary,
            created_at_iso=row.created_at.isoformat() if row.created_at else "",
        )
