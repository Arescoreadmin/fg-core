# api/db_models_governance_learning.py
"""SQLAlchemy ORM models for PR 17.6B — Governance Learning Loop Authority.

Tables:
  fa_governance_learning_records   — per-outcome learning record (append-only)
  fa_governance_learning_aggregates — mutable per-category learning aggregates

Design:
  - fa_governance_learning_records: fully append-only (UPDATE and DELETE blocked
    via sa_event guards).
  - fa_governance_learning_aggregates: fully mutable (upserted on ingest/recalculate).

PR 17.6B — Governance Learning Loop Authority
"""

from __future__ import annotations

from sqlalchemy import (
    Float,
    Index,
    Integer,
    String,
    UniqueConstraint,
    event as sa_event,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_governance_learning_records — append-only per-outcome learning record
# ---------------------------------------------------------------------------


class FaGovernanceLearningRecord(Base):
    """Append-only learning record derived from a single remediation outcome."""

    __tablename__ = "fa_governance_learning_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    learning_category: Mapped[str] = mapped_column(String(32), nullable=False)
    control_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation_category: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome_type: Mapped[str] = mapped_column(String(32), nullable=False)

    effectiveness_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    effectiveness_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    effectiveness_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    verification_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    freshness_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    forecast_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    forecast_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    forecast_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    health_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    health_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    health_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    success_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    source_outcome_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_gl_record_tenant", "tenant_id"),
        Index("idx_gl_record_tenant_category", "tenant_id", "learning_category"),
        Index("idx_gl_record_tenant_control", "tenant_id", "control_id"),
        Index("idx_gl_record_tenant_rem_category", "tenant_id", "remediation_category"),
        Index("idx_gl_record_tenant_source_outcome", "tenant_id", "source_outcome_id"),
    )


@sa_event.listens_for(FaGovernanceLearningRecord, "before_update")
def _block_gl_record_update(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_learning_records is append-only (update not allowed)"
    )


@sa_event.listens_for(FaGovernanceLearningRecord, "before_delete")
def _block_gl_record_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_learning_records is append-only (delete not allowed)"
    )


# ---------------------------------------------------------------------------
# fa_governance_learning_aggregates — mutable per-category aggregate
# ---------------------------------------------------------------------------


class FaGovernanceLearningAggregate(Base):
    """Mutable aggregate for a remediation category — upserted on each ingest."""

    __tablename__ = "fa_governance_learning_aggregates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    remediation_category: Mapped[str] = mapped_column(String(32), nullable=False)

    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    partial_success_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    no_change_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    average_effectiveness_delta: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    average_verification_delta: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    average_freshness_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    average_forecast_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    average_health_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default="UNKNOWN"
    )
    last_updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "remediation_category",
            name="uidx_fa_gl_aggregate_tenant_category",
        ),
        Index("idx_gl_aggregate_tenant", "tenant_id"),
        Index("idx_gl_aggregate_tenant_category", "tenant_id", "remediation_category"),
    )
