# api/db_models_control_effectiveness.py
"""SQLAlchemy ORM models for PR 16.5 — Control Effectiveness Engine.

Tables:
  fa_control_effectiveness         — current effectiveness state per control (mutable)
  fa_control_effectiveness_history — append-only effectiveness history

Design:
  - fa_control_effectiveness is updated on every recalculation (not append-only).
    Only deletion is blocked at ORM + PG layer.
  - fa_control_effectiveness_history is fully append-only (both update and delete
    blocked at ORM + PG layer).
  - UniqueConstraint on (tenant_id, control_id) enforces one current record per control.

PR 16.5 — Control Effectiveness Engine
"""

from __future__ import annotations

from sqlalchemy import (
    Float,
    Index,
    String,
    UniqueConstraint,
    event as sa_event,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_control_effectiveness — current state (mutable, delete-protected)
# ---------------------------------------------------------------------------


class FaControlEffectiveness(Base):
    """Current control effectiveness record. Updated on every recalculation."""

    __tablename__ = "fa_control_effectiveness"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)

    effectiveness_score: Mapped[float] = mapped_column(Float, nullable=False)
    effectiveness_level: Mapped[str] = mapped_column(String(32), nullable=False)
    effectiveness_risk: Mapped[str] = mapped_column(String(16), nullable=False)

    coverage_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    trend_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    forecast_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_density_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    exception_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    governance_health_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    trend_direction: Mapped[str | None] = mapped_column(String(16), nullable=True)
    score_delta_7d: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_delta_30d: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_delta_90d: Mapped[float | None] = mapped_column(Float, nullable=True)

    last_calculated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    calculation_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "control_id",
            name="uidx_fa_control_effectiveness_tenant_control",
        ),
        Index(
            "idx_fa_control_effectiveness_tenant_control",
            "tenant_id",
            "control_id",
        ),
        Index(
            "idx_fa_control_effectiveness_score",
            "tenant_id",
            "effectiveness_score",
        ),
    )


@sa_event.listens_for(FaControlEffectiveness, "before_delete")
def _block_effectiveness_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_control_effectiveness rows cannot be deleted (use recalculate to update)"
    )


# ---------------------------------------------------------------------------
# fa_control_effectiveness_history — append-only history
# ---------------------------------------------------------------------------


class FaControlEffectivenessHistory(Base):
    """Immutable control effectiveness history record."""

    __tablename__ = "fa_control_effectiveness_history"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)

    effectiveness_score: Mapped[float] = mapped_column(Float, nullable=False)
    effectiveness_level: Mapped[str] = mapped_column(String(32), nullable=False)
    effectiveness_risk: Mapped[str] = mapped_column(String(16), nullable=False)

    coverage_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    trend_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    captured_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "idx_fa_ce_history_tenant_control",
            "tenant_id",
            "control_id",
        ),
        Index(
            "idx_fa_ce_history_captured",
            "tenant_id",
            "captured_at",
        ),
    )


@sa_event.listens_for(FaControlEffectivenessHistory, "before_update")
def _block_history_update(mapper, connection, target):
    raise RuntimeError(
        "fa_control_effectiveness_history is append-only (update not allowed)"
    )


@sa_event.listens_for(FaControlEffectivenessHistory, "before_delete")
def _block_history_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_control_effectiveness_history is append-only (deletion not allowed)"
    )
