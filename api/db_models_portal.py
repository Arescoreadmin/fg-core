# api/db_models_portal.py
"""SQLAlchemy ORM models for the Portal Grant system (C7).

Tables:
  portal_grants              — one hashed grant per (tenant, client, engagement)
  portal_grant_audit_events  — append-only audit trail; SELECT + INSERT RLS only
  portal_grant_sessions      — server-side session tracking; 8-hour TTL
"""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class PortalGrant(Base):
    """One portal grant per (tenant, client, engagement). Hashed secret stored; never plaintext."""

    __tablename__ = "portal_grants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    grant_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="client_portal"
    )
    grant_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_used_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    rotation_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_portal_grants_tenant_client", "tenant_id", "client_id"),
        Index("ix_portal_grants_tenant_engagement", "tenant_id", "engagement_id"),
    )


class PortalGrantAuditEvent(Base):
    """Append-only audit trail for portal grant lifecycle events."""

    __tablename__ = "portal_grant_audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    grant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_portal_grant_audit_tenant_created", "tenant_id", "created_at"),
    )


class PortalGrantSession(Base):
    """Server-side portal session record — created when a grant secret is verified."""

    __tablename__ = "portal_grant_sessions"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_grant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    __table_args__ = (
        Index("ix_portal_grant_sessions_tenant_expires", "tenant_id", "expires_at"),
    )
