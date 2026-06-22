# api/db_models_governance_portal.py
"""SQLAlchemy ORM models for PR 14.4 — Governance Portal Integration & Client Trust Layer.

Tables:
  portal_acknowledgements  — client acknowledgements of governance decisions (append-only)
  governance_portal_audits — portal activity audit trail (append-only)

Tenant isolation:
  All queries must include a tenant_id predicate.

Append-only contract:
  Both tables are append-only. No UPDATE or DELETE path exists.

Entity types for acknowledgements:
  ACCEPTED_RISK, REVIEW_OUTCOME, GOVERNANCE_DECISION, CONTROL_EXCEPTION, EVIDENCE_REQUEST

Audit event types:
  RISK_VIEWED, RISK_ACKNOWLEDGED, CONTROL_VIEWED, EVIDENCE_VIEWED,
  ACK_CREATED, DASHBOARD_VIEWED, AUDIT_ACCESSED
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class PortalAcknowledgement(Base):
    """Client acknowledgement of a governance entity.

    Append-only: acknowledged_at and acknowledged_by are immutable after creation.
    entity_type + entity_id identifies the thing being acknowledged.
    """

    __tablename__ = "portal_acknowledgements"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    entity_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # AcknowledgementEntityType value
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    acknowledged_by: Mapped[str] = mapped_column(String(255), nullable=False)
    acknowledged_at: Mapped[str] = mapped_column(String(64), nullable=False)
    comments: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_portal_ack_tenant_entity", "tenant_id", "entity_type", "entity_id"),
        Index("ix_portal_ack_tenant_actor", "tenant_id", "acknowledged_by"),
        {"extend_existing": True},
    )


class GovernancePortalAudit(Base):
    """Append-only audit trail for portal activity.

    event_type identifies what the actor did.
    entity_type + entity_id identifies the object acted upon (nullable for dashboard/audit events).
    """

    __tablename__ = "governance_portal_audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # PortalAuditEventType value
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_at: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_gov_portal_audit_tenant_event", "tenant_id", "event_type", "event_at"
        ),
        Index("ix_gov_portal_audit_tenant_actor", "tenant_id", "actor"),
        {"extend_existing": True},
    )
