# api/db_models_governance_adaptive_intelligence.py
"""SQLAlchemy ORM models for PR 17.6C — Governance Adaptive Intelligence Authority.

Tables:
  fa_governance_recommendation_history  — per-recommendation status rows (append-only)
  fa_governance_recommendation_outcomes — mutable outcome record per recommendation
  fa_governance_accuracy_aggregates     — mutable per-type accuracy aggregate
  fa_governance_playbooks               — mutable per-type playbook

Design:
  - fa_governance_recommendation_history: fully append-only (UPDATE and DELETE blocked
    via sa_event guards + PG trigger). Each status transition creates a NEW row with
    the same recommendation_id.
  - All other tables: fully mutable (upserted on record-outcome / recalculate).

PR 17.6C — Governance Adaptive Intelligence Authority
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
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
# fa_governance_recommendation_history — append-only per-recommendation row
# ---------------------------------------------------------------------------


class FaGovernanceRecommendationHistory(Base):
    """Append-only recommendation history. Each status transition is a new row."""

    __tablename__ = "fa_governance_recommendation_history"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    recommendation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recommendation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    recommendation_category: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    recommendation_reason: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation_confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    accepted_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rejected_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    closed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    source_learning_record_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    source_aggregate_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_authority: Mapped[str] = mapped_column(
        String(64), nullable=False, default="governance_learning"
    )

    __table_args__ = (
        Index("idx_gai_rh_tenant", "tenant_id"),
        Index("idx_gai_rh_tenant_status", "tenant_id", "status"),
        Index("idx_gai_rh_tenant_type", "tenant_id", "recommendation_type"),
        Index("idx_gai_rh_tenant_rec_id", "tenant_id", "recommendation_id"),
    )


@sa_event.listens_for(FaGovernanceRecommendationHistory, "before_update")
def _block_gai_rh_update(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_recommendation_history is append-only (update not allowed)"
    )


@sa_event.listens_for(FaGovernanceRecommendationHistory, "before_delete")
def _block_gai_rh_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_governance_recommendation_history is append-only (delete not allowed)"
    )


# ---------------------------------------------------------------------------
# fa_governance_recommendation_outcomes — mutable outcome per recommendation
# ---------------------------------------------------------------------------


class FaGovernanceRecommendationOutcome(Base):
    """Mutable outcome record tied to a recommendation_history row."""

    __tablename__ = "fa_governance_recommendation_outcomes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    recommendation_history_id: Mapped[str] = mapped_column(String(64), nullable=False)

    health_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    health_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    health_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

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

    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    confidence_adjustment: Mapped[float | None] = mapped_column(Float, nullable=True)
    recorded_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "recommendation_history_id",
            name="uidx_gai_ro_tenant_history",
        ),
        Index("idx_gai_ro_tenant", "tenant_id"),
        Index("idx_gai_ro_tenant_history_id", "tenant_id", "recommendation_history_id"),
        Index("idx_gai_ro_tenant_success", "tenant_id", "success"),
    )


# ---------------------------------------------------------------------------
# fa_governance_accuracy_aggregates — mutable per-type accuracy aggregate
# ---------------------------------------------------------------------------


class FaGovernanceAccuracyAggregate(Base):
    """Mutable accuracy aggregate for a recommendation type."""

    __tablename__ = "fa_governance_accuracy_aggregates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    recommendation_type: Mapped[str] = mapped_column(String(64), nullable=False)

    recommendations_generated: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    recommendations_accepted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    recommendations_executed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    recommendations_successful: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    recommendations_failed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    avg_health_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_effectiveness_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_verification_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_freshness_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_forecast_delta: Mapped[float | None] = mapped_column(Float, nullable=True)

    calibrated_confidence: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CALIBRATED_UNKNOWN"
    )
    last_updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "recommendation_type",
            name="uidx_gai_aa_tenant_type",
        ),
        Index("idx_gai_aa_tenant", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# fa_governance_playbooks — mutable per-type playbook
# ---------------------------------------------------------------------------


class FaGovernancePlaybook(Base):
    """Mutable playbook for a playbook type — upserted on recalculate."""

    __tablename__ = "fa_governance_playbooks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    playbook_type: Mapped[str] = mapped_column(String(64), nullable=False)
    recommended_path: Mapped[str] = mapped_column(Text, nullable=False)
    success_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    avg_health_improvement: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CALIBRATED_UNKNOWN"
    )
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "playbook_type",
            name="uidx_gai_pb_tenant_type",
        ),
        Index("idx_gai_pb_tenant", "tenant_id"),
    )
