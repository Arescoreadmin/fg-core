# api/db_models_remediation_effectiveness.py
"""SQLAlchemy ORM models for PR 17.5 — Remediation Effectiveness Analytics Authority.

Tables:
  fa_remediation_outcome      — per-remediation outcome record (delete-protected)
  fa_remediation_persistence  — append-only persistence windows per remediation
  fa_remediation_learning     — mutable per-category learning aggregates
  fa_remediation_pattern      — mutable per-control pattern records

Design:
  - fa_remediation_outcome: mutable status field, but delete is blocked via sa_event.
  - fa_remediation_persistence: fully append-only (UPDATE and DELETE both blocked).
  - fa_remediation_learning: fully mutable (upserted on recalculate).
  - fa_remediation_pattern: fully mutable (upserted on recalculate).

PR 17.5 — Remediation Effectiveness Analytics Authority
"""

from __future__ import annotations

from sqlalchemy import (
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event as sa_event,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_remediation_outcome — per-remediation outcome (delete-protected)
# ---------------------------------------------------------------------------


class FaRemediationOutcome(Base):
    """Recorded outcome for a single remediation action."""

    __tablename__ = "fa_remediation_outcome"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    remediation_task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)

    before_score: Mapped[float] = mapped_column(Float, nullable=False)
    after_score: Mapped[float] = mapped_column(Float, nullable=False)
    score_delta: Mapped[float] = mapped_column(Float, nullable=False)

    before_effectiveness_level: Mapped[str] = mapped_column(String(32), nullable=False)
    after_effectiveness_level: Mapped[str] = mapped_column(String(32), nullable=False)

    outcome_classification: Mapped[str] = mapped_column(String(32), nullable=False)
    remediation_effectiveness_score: Mapped[float] = mapped_column(
        Float, nullable=False
    )
    effectiveness_level: Mapped[str] = mapped_column(String(32), nullable=False)
    roi_score: Mapped[float] = mapped_column(Float, nullable=False)
    roi_classification: Mapped[str] = mapped_column(String(32), nullable=False)
    remediation_category: Mapped[str] = mapped_column(String(32), nullable=False)

    verification_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    forecast_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    forecast_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    forecast_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    governance_health_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    governance_health_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    governance_health_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="COMPLETE")
    measured_at: Mapped[str] = mapped_column(String(64), nullable=False)
    calculation_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "remediation_task_id",
            "control_id",
            name="uidx_fa_remediation_outcome_tenant_task_control",
        ),
        Index("idx_fa_remediation_outcome_tenant", "tenant_id"),
        Index(
            "idx_fa_remediation_outcome_tenant_control",
            "tenant_id",
            "control_id",
        ),
        Index(
            "idx_fa_remediation_outcome_tenant_classification",
            "tenant_id",
            "outcome_classification",
        ),
    )


@sa_event.listens_for(FaRemediationOutcome, "before_delete")
def _block_outcome_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_remediation_outcome rows cannot be deleted"
    )


# ---------------------------------------------------------------------------
# fa_remediation_persistence — append-only persistence windows
# ---------------------------------------------------------------------------


class FaRemediationPersistence(Base):
    """Append-only persistence window measurement for a remediation."""

    __tablename__ = "fa_remediation_persistence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    remediation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False)
    score_at_window: Mapped[float] = mapped_column(Float, nullable=False)
    delta_from_close: Mapped[float] = mapped_column(Float, nullable=False)
    persistence_classification: Mapped[str] = mapped_column(String(32), nullable=False)
    measured_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "remediation_id",
            "window_days",
            name="uidx_fa_remediation_persistence_tenant_rem_window",
        ),
        Index("idx_fa_remediation_persistence_tenant", "tenant_id"),
        Index(
            "idx_fa_remediation_persistence_tenant_remediation",
            "tenant_id",
            "remediation_id",
        ),
    )


@sa_event.listens_for(FaRemediationPersistence, "before_update")
def _block_persistence_update(mapper, connection, target):
    raise RuntimeError(
        "fa_remediation_persistence is append-only (update not allowed)"
    )


@sa_event.listens_for(FaRemediationPersistence, "before_delete")
def _block_persistence_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_remediation_persistence is append-only (delete not allowed)"
    )


# ---------------------------------------------------------------------------
# fa_remediation_learning — mutable per-category learning aggregates
# ---------------------------------------------------------------------------


class FaRemediationLearning(Base):
    """Mutable aggregate learning data per remediation category."""

    __tablename__ = "fa_remediation_learning"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    remediation_category: Mapped[str] = mapped_column(String(32), nullable=False)

    total_remediations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    partial_success_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    no_change_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    regression_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    success_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    average_score_delta: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    average_roi_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "remediation_category",
            name="uidx_fa_remediation_learning_tenant_category",
        ),
        Index("idx_fa_remediation_learning_tenant", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# fa_remediation_pattern — mutable per-control pattern records
# ---------------------------------------------------------------------------


class FaRemediationPattern(Base):
    """Mutable remediation pattern record per control."""

    __tablename__ = "fa_remediation_pattern"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    pattern_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "control_id",
            "pattern_type",
            name="uidx_fa_remediation_pattern_tenant_control_type",
        ),
        Index("idx_fa_remediation_pattern_tenant", "tenant_id"),
        Index(
            "idx_fa_remediation_pattern_tenant_control",
            "tenant_id",
            "control_id",
        ),
    )
