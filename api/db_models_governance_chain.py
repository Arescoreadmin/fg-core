# api/db_models_governance_chain.py
"""SQLAlchemy ORM models for PR 17.6 — Canonical Governance Chain Authority.

Tables:
  fa_governance_chain_events      — canonical governance event log (append-only)
  fa_governance_chain_executions  — per-bridge execution audit (append-only)
  fa_governance_health_snapshots  — governance health point-in-time (append-only)
  fa_governance_chain_snapshots   — CGIN anonymized benchmark snapshots (mutable)

Design:
  - fa_governance_chain_events: append-only (UPDATE+DELETE blocked via sa_event).
  - fa_governance_chain_executions: append-only (UPDATE+DELETE blocked via sa_event).
  - fa_governance_health_snapshots: append-only (UPDATE+DELETE blocked via sa_event).
  - fa_governance_chain_snapshots: mutable — CGIN benchmark data, upserted on snapshot.

PR 17.6 — Canonical Governance Chain Authority
"""

from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy import event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_governance_chain_events — append-only governance event log
# ---------------------------------------------------------------------------


class FaGovernanceChainEvent(Base):
    """Canonical governance chain event — immutable after creation."""

    __tablename__ = "fa_governance_chain_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    authority: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_gc_events_tenant", "tenant_id"),
        Index("idx_gc_events_tenant_type", "tenant_id", "event_type"),
        Index("idx_gc_events_tenant_authority", "tenant_id", "authority"),
        Index("idx_gc_events_correlation", "correlation_id"),
        Index("idx_gc_events_tenant_object", "tenant_id", "object_id"),
    )


@sa_event.listens_for(FaGovernanceChainEvent, "before_update")
def _block_event_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_governance_chain_events is append-only. Updates are not permitted."
    )


@sa_event.listens_for(FaGovernanceChainEvent, "before_delete")
def _block_event_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_governance_chain_events is append-only. Deletes are not permitted."
    )


# ---------------------------------------------------------------------------
# fa_governance_chain_executions — append-only bridge execution audit
# ---------------------------------------------------------------------------


class FaGovernanceChainExecution(Base):
    """Per-bridge execution record — immutable after creation."""

    __tablename__ = "fa_governance_chain_executions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    chain_execution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_authority: Mapped[str] = mapped_column(String(64), nullable=False)
    target_authority: Mapped[str] = mapped_column(String(64), nullable=False)
    bridge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    trigger_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    trigger_object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger_object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_result: Mapped[str] = mapped_column(String(32), nullable=False)
    success: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    executed_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_gc_exec_tenant", "tenant_id"),
        Index("idx_gc_exec_tenant_bridge", "tenant_id", "bridge_type"),
        Index("idx_gc_exec_tenant_success", "tenant_id", "success"),
        Index("idx_gc_exec_chain_id", "chain_execution_id"),
    )


@sa_event.listens_for(FaGovernanceChainExecution, "before_update")
def _block_execution_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_governance_chain_executions is append-only. Updates are not permitted."
    )


@sa_event.listens_for(FaGovernanceChainExecution, "before_delete")
def _block_execution_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_governance_chain_executions is append-only. Deletes are not permitted."
    )


# ---------------------------------------------------------------------------
# fa_governance_health_snapshots — append-only health point-in-time
# ---------------------------------------------------------------------------


class FaGovernanceHealthSnapshot(Base):
    """Point-in-time governance health snapshot — immutable after creation."""

    __tablename__ = "fa_governance_health_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    verification_health: Mapped[float] = mapped_column(Float, nullable=False)
    freshness_health: Mapped[float] = mapped_column(Float, nullable=False)
    effectiveness_health: Mapped[float] = mapped_column(Float, nullable=False)
    remediation_health: Mapped[float] = mapped_column(Float, nullable=False)
    forecast_health: Mapped[float] = mapped_column(Float, nullable=False)
    governance_health_score: Mapped[float] = mapped_column(Float, nullable=False)
    governance_health_rating: Mapped[str] = mapped_column(String(32), nullable=False)
    missing_inputs_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_at: Mapped[str] = mapped_column(String(64), nullable=False)
    calculation_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    governance_momentum: Mapped[float | None] = mapped_column(Float, nullable=True)
    governance_stability: Mapped[float | None] = mapped_column(Float, nullable=True)
    governance_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("idx_gc_health_tenant", "tenant_id"),
        Index("idx_gc_health_tenant_at", "tenant_id", "snapshot_at"),
    )


@sa_event.listens_for(FaGovernanceHealthSnapshot, "before_update")
def _block_health_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_governance_health_snapshots is append-only. Updates are not permitted."
    )


@sa_event.listens_for(FaGovernanceHealthSnapshot, "before_delete")
def _block_health_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_governance_health_snapshots is append-only. Deletes are not permitted."
    )


# ---------------------------------------------------------------------------
# fa_governance_chain_snapshots — mutable CGIN benchmark snapshots
# ---------------------------------------------------------------------------


class FaGovernanceChainSnapshot(Base):
    """CGIN anonymized governance chain benchmark snapshot."""

    __tablename__ = "fa_governance_chain_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    authority: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    average_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_gc_snap_fingerprint", "tenant_fingerprint"),
        Index("idx_gc_snap_authority", "authority"),
    )
