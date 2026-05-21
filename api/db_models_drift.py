"""ORM models for drift detection and continuous connector intelligence.

Tables:
  fa_drift_baselines      — pinned canonical baseline scan per engagement (T&V audit)
  fa_drift_alerts         — deduplicated alert records keyed by fingerprint
  fa_connector_schedules  — cron expression registry per engagement/source type
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaDriftBaseline(Base):
    """Pinned baseline scan for an engagement.

    Only one active baseline per (tenant_id, engagement_id) at a time.
    Pinning a new baseline sets is_active=False on the prior row before insert.
    Drift reports always compute against the active baseline, never auto-select.
    """

    __tablename__ = "fa_drift_baselines"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    pinned_scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_email: Mapped[str] = mapped_column(String(255), nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    pinned_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_drift_baselines_engagement", "engagement_id", "tenant_id"),
        Index(
            "ix_fa_drift_baselines_active",
            "tenant_id",
            "engagement_id",
            "is_active",
        ),
    )


class FaDriftAlert(Base):
    """Deduplicated drift alert record.

    alert_fingerprint = SHA-256(tenant_id:engagement_id:pattern:finding_id:severity)
    Only one active row per fingerprint — no duplicate alerts for ongoing conditions.
    When condition resolves: set is_active=False and stamp resolved_at.
    """

    __tablename__ = "fa_drift_alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    pattern: Mapped[str] = mapped_column(String(128), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    alert_family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_seen_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen_at: Mapped[str] = mapped_column(String(64), nullable=False)
    resolved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "engagement_id",
            "alert_fingerprint",
            name="uq_fa_drift_alert_fingerprint",
        ),
        Index("ix_fa_drift_alerts_engagement", "engagement_id", "tenant_id"),
        Index("ix_fa_drift_alerts_active", "tenant_id", "is_active"),
    )


class FaConnectorSchedule(Base):
    """Cron expression registry entry for a connector/engagement pair.

    One active schedule per (tenant_id, engagement_id, source_type).
    source_type: e.g. 'microsoft_graph', 'okta', 'aws'
    cron_expression: standard 5-field cron (min hour dom mon dow)
    """

    __tablename__ = "fa_connector_schedules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "engagement_id",
            "source_type",
            name="uq_fa_connector_schedule",
        ),
        Index("ix_fa_connector_schedules_engagement", "engagement_id", "tenant_id"),
    )
