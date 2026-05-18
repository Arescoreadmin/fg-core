"""Simulation run persistence store.

All methods take a SQLAlchemy Session. No module-level state. No side effects beyond DB.

Tenant isolation contract:
  - get_run() and list_runs() always filter by tenant_id.
  - Cross-tenant access returns None / empty list (no disclosure).
  - create_run() always records tenant_id from the simulation input.

Immutability contract:
  - Simulation runs are write-once; no update methods exist.
  - Stored projection_json is frozen at creation time.
  - Historical runs remain reconstructable.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .models import SimulationRunRecord

logger = logging.getLogger("frostgate.readiness.simulation.store")


class SimulationRunNotFound(Exception):
    pass


class SimulationRunTenantIsolationError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SimulationRunStore:
    """Write-once persistence for immutable simulation run records."""

    def create_run(
        self,
        db: Session,
        *,
        run_id: str,
        tenant_id: str,
        assessment_id: Optional[str],
        framework_id: Optional[str],
        scenario_type: str,
        simulation_contract_version: str,
        simulation_engine_version: str,
        snapshot_id: str,
        projection_json: str,
        uncertainty: str,
        total_warnings: int,
        total_impacts: int,
        total_critical_warnings: int,
        simulated_at_iso: str,
        completed: bool,
        error_summary: Optional[str],
    ) -> SimulationRunRecord:
        from api.db_models_simulation import SimulationRunModel

        now = _now()
        row = SimulationRunModel(
            run_id=run_id,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            framework_id=framework_id,
            scenario_type=scenario_type,
            simulation_contract_version=simulation_contract_version,
            simulation_engine_version=simulation_engine_version,
            snapshot_id=snapshot_id,
            projection_json=projection_json,
            uncertainty=uncertainty,
            total_warnings=total_warnings,
            total_impacts=total_impacts,
            total_critical_warnings=total_critical_warnings,
            simulated_at_iso=simulated_at_iso,
            completed=completed,
            error_summary=error_summary,
            created_at=now,
        )
        db.add(row)
        db.flush()
        # longitudinal_simulation_seam: multi-run governance trend analysis, drift
        # recurrence scoring, and readiness volatility prediction plug in here after
        # flush. At this point the simulation run is persisted; a longitudinal analyzer
        # can query prior runs by (tenant_id, assessment_id) to produce trajectory
        # annotations before the transaction commits.
        return self._to_domain(row)

    def get_run(
        self, db: Session, *, run_id: str, tenant_id: str
    ) -> SimulationRunRecord:
        from api.db_models_simulation import SimulationRunModel

        row = db.query(SimulationRunModel).filter_by(run_id=run_id).first()
        if row is None:
            raise SimulationRunNotFound(run_id)
        if row.tenant_id != tenant_id:
            raise SimulationRunTenantIsolationError(run_id)
        return self._to_domain(row)

    def list_runs(
        self,
        db: Session,
        *,
        tenant_id: str,
        assessment_id: Optional[str] = None,
        scenario_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[SimulationRunRecord]:
        from api.db_models_simulation import SimulationRunModel

        q = db.query(SimulationRunModel).filter_by(tenant_id=tenant_id)
        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)
        if scenario_type:
            q = q.filter_by(scenario_type=scenario_type)
        rows = (
            q.order_by(SimulationRunModel.created_at.desc())
            .limit(min(limit, 200))
            .offset(offset)
            .all()
        )
        return [self._to_domain(r) for r in rows]

    def _to_domain(self, row) -> SimulationRunRecord:  # type: ignore[no-untyped-def]
        return SimulationRunRecord(
            run_id=row.run_id,
            tenant_id=row.tenant_id,
            assessment_id=row.assessment_id,
            framework_id=row.framework_id,
            scenario_type=row.scenario_type,
            simulation_contract_version=row.simulation_contract_version,
            simulation_engine_version=row.simulation_engine_version,
            snapshot_id=row.snapshot_id,
            projection_json=row.projection_json,
            uncertainty=row.uncertainty,
            total_warnings=row.total_warnings,
            total_impacts=row.total_impacts,
            total_critical_warnings=row.total_critical_warnings,
            simulated_at_iso=row.simulated_at_iso,
            completed=row.completed,
            error_summary=row.error_summary,
            created_at_iso=row.created_at.isoformat() if row.created_at else "",
        )
