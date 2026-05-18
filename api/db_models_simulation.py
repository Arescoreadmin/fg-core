# api/db_models_simulation.py
"""SQLAlchemy ORM model for immutable simulation run records.

Infrastructure note (PR 95):
  This file extends Base.metadata with a new table: readiness_simulation_runs.
  Imported by api.db._ensure_models_imported() so init_db() creates the table.
  The table is write-once — no UPDATE paths exist in SimulationRunStore.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base, utcnow


class SimulationRunModel(Base):
    """Immutable simulation run record — write-once, never updated.

    run_id is a deterministic SHA-256 digest derived from governance inputs;
    identical governance scope + scenario parameters → identical run_id (idempotent).

    projection_json stores the export-safe serialized SimulationProjection.
    It is NEVER exposed directly in API responses — the deserialized dict is returned.
    """

    __tablename__ = "readiness_simulation_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    assessment_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    framework_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scenario_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    simulation_contract_version: Mapped[str] = mapped_column(String(32), nullable=False)
    simulation_engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    projection_json: Mapped[str] = mapped_column(Text, nullable=False)
    uncertainty: Mapped[str] = mapped_column(String(64), nullable=False)
    total_warnings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_impacts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_critical_warnings: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    simulated_at_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error_summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Actor attribution: who submitted this simulation (for audit/replay lineage)
    created_by_actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    auth_scope_snapshot: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Replay/hash integrity: input, output, and contract hashes for regulator-grade evidence
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    projection_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    contract_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # Classification — audience scope for this simulation output
    classification: Mapped[str] = mapped_column(
        String(64), nullable=False, default="internal"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_simulation_runs_tenant_created", "tenant_id", "created_at"),
        Index("ix_simulation_runs_tenant_assessment", "tenant_id", "assessment_id"),
    )


class SimulationEventModel(Base):
    """Append-only governance event record for simulation lifecycle telemetry.

    Events feed the SIEM forwarding surface, replay backbone, analytics pipeline,
    and governance timeline integration.
    Table: readiness_simulation_events
    """

    __tablename__ = "readiness_simulation_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    simulation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(
        String(64), nullable=False, default="internal"
    )
    scenario_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index(
            "ix_simulation_events_tenant_simulation",
            "tenant_id",
            "simulation_id",
        ),
        Index(
            "ix_simulation_events_tenant_event_type",
            "tenant_id",
            "event_type",
        ),
    )
