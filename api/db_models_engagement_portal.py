"""ORM models for the Engagement Portal (PR 18.2).

Tables:
  portal_engagement_preferences  — per-tenant preference record (unique on tenant_id)
  portal_engagement_activity     — append-only activity log
  portal_engagement_notifications — notification queue (PENDING -> DELIVERED)

Tenant isolation:
  Every query must include a tenant_id predicate. RLS policies are added in
  migration 0143 for defense-in-depth.

Append-only contract:
  portal_engagement_activity rejects ORM UPDATE and DELETE via SQLAlchemy
  events.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Index, Integer, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class PortalEngagementPreferences(Base):
    """Per-tenant portal preferences (single row per tenant)."""

    __tablename__ = "portal_engagement_preferences"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    theme: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notification_email: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = ({"extend_existing": True},)


class PortalEngagementActivity(Base):
    """Append-only portal activity log."""

    __tablename__ = "portal_engagement_activity"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    workspace: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_portal_engagement_activity_tenant_event",
            "tenant_id",
            "event_type",
            "created_at",
        ),
        Index(
            "ix_portal_engagement_activity_tenant_workspace",
            "tenant_id",
            "workspace",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(PortalEngagementActivity, "before_update")
def _block_activity_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "portal_engagement_activity is append-only — updates are forbidden"
    )


@sa_event.listens_for(PortalEngagementActivity, "before_delete")
def _block_activity_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "portal_engagement_activity is append-only — deletes are forbidden"
    )


class PortalEngagementNotification(Base):
    """Engagement-channel notification record."""

    __tablename__ = "portal_engagement_notifications"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    notification_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    delivered_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index(
            "ix_portal_engagement_notif_tenant_status",
            "tenant_id",
            "status",
            "created_at",
        ),
        {"extend_existing": True},
    )
