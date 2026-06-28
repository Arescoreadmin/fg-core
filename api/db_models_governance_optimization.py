# api/db_models_governance_optimization.py
"""SQLAlchemy ORM models for PR 17.6D — Governance Optimization Engine.

Tables:
  fa_governance_optimization_decisions  — per-decision row (append-only)
  fa_governance_optimization_aggregates — mutable per-target aggregate
  fa_governance_optimization_snapshots  — per-type snapshot (append-only)

Design:
  - fa_governance_optimization_decisions: fully append-only (UPDATE and DELETE
    blocked via sa_event guards + PG trigger).
  - fa_governance_optimization_aggregates: mutable — upserted on each ranking run.
  - fa_governance_optimization_snapshots: fully append-only (UPDATE and DELETE
    blocked via sa_event guards + PG trigger).

PR 17.6D — Governance Optimization Engine
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
# fa_governance_optimization_decisions — append-only decision row
# ---------------------------------------------------------------------------


class FaGovernanceOptimizationDecision(Base):
    """Append-only optimization decision. Each ranking run creates new rows."""

    __tablename__ = "fa_governance_optimization_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    optimization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    optimization_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_authorities: Mapped[str] = mapped_column(Text, nullable=False)
    source_record_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_god_tenant", "tenant_id"),
        Index("idx_god_tenant_opt_type", "tenant_id", "optimization_type"),
        Index("idx_god_tenant_target_type", "tenant_id", "target_type"),
        Index("idx_god_tenant_target_id", "tenant_id", "target_id"),
        Index("idx_god_tenant_created_at", "tenant_id", "created_at"),
    )


@sa_event.listens_for(FaGovernanceOptimizationDecision, "before_update")
def _block_god_update(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_optimization_decisions is append-only (update not allowed)"
    )


@sa_event.listens_for(FaGovernanceOptimizationDecision, "before_delete")
def _block_god_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_optimization_decisions is append-only (delete not allowed)"
    )


# ---------------------------------------------------------------------------
# fa_governance_optimization_aggregates — mutable per-target aggregate
# ---------------------------------------------------------------------------


class FaGovernanceOptimizationAggregate(Base):
    """Mutable aggregate for a (target_type, target_id, optimization_type) tuple."""

    __tablename__ = "fa_governance_optimization_aggregates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    optimization_type: Mapped[str] = mapped_column(String(64), nullable=False)
    times_ranked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    average_priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    latest_priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    highest_priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    lowest_priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    average_health_lift: Mapped[float | None] = mapped_column(Float, nullable=True)
    average_effectiveness_lift: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    average_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_ranked_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "target_type",
            "target_id",
            "optimization_type",
            name="uidx_goa_tenant_target_opt",
        ),
        Index("idx_goa_tenant", "tenant_id"),
        Index("idx_goa_tenant_target_type", "tenant_id", "target_type"),
        Index("idx_goa_tenant_opt_type", "tenant_id", "optimization_type"),
    )


# ---------------------------------------------------------------------------
# fa_governance_optimization_snapshots — append-only per-type snapshot
# ---------------------------------------------------------------------------


class FaGovernanceOptimizationSnapshot(Base):
    """Append-only optimization snapshot — created after each ranking run."""

    __tablename__ = "fa_governance_optimization_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    snapshot_type: Mapped[str] = mapped_column(String(64), nullable=False)
    total_items_ranked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    top_priority_target_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    top_priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    average_priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    optimization_confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_gos_tenant", "tenant_id"),
        Index("idx_gos_tenant_snapshot_type", "tenant_id", "snapshot_type"),
        Index("idx_gos_tenant_generated_at", "tenant_id", "generated_at"),
    )


@sa_event.listens_for(FaGovernanceOptimizationSnapshot, "before_update")
def _block_gos_update(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_optimization_snapshots is append-only (update not allowed)"
    )


@sa_event.listens_for(FaGovernanceOptimizationSnapshot, "before_delete")
def _block_gos_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_optimization_snapshots is append-only (delete not allowed)"
    )
