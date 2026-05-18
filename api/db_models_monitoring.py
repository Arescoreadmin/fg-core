# api/db_models_monitoring.py
"""SQLAlchemy ORM model for immutable monitoring run records.

Infrastructure note (PR 93):
  This file extends Base.metadata with a new table: readiness_monitoring_runs.
  Imported by api.db._ensure_models_imported() so init_db() creates the table.
  The table is write-once — no UPDATE paths exist in MonitoringRunStore.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base, utcnow


class MonitoringRunModel(Base):
    """Immutable monitoring run record — write-once, never updated.

    run_id is a deterministic SHA-256 digest derived from governance inputs;
    identical governance scope + evaluation window → identical run_id (idempotent).

    snapshot_json stores the export-safe serialized DriftSnapshot.
    framework_ids_json and domains_evaluated_json store JSON arrays.
    """

    __tablename__ = "readiness_monitoring_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    assessment_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    framework_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    eval_window_start_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    eval_window_end_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    monitoring_contract_version: Mapped[str] = mapped_column(String(32), nullable=False)
    evaluation_engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)
    domains_evaluated_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )
    total_drift_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_or_blocking_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    completed_at_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluation_success: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    error_summary: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_monitoring_runs_tenant_created", "tenant_id", "created_at"),
        Index("ix_monitoring_runs_tenant_assessment", "tenant_id", "assessment_id"),
    )
