# api/db_models_portal_remediation.py
"""ORM models for Portal Remediation Integration (PR 13.4).

Three tables:
  portal_remediation_comments     — append-write (edits allowed but audited)
  portal_evidence_submissions     — immutable after insert
  portal_remediation_audit_events — append-only (no UPDATE/DELETE)
"""

from __future__ import annotations
from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:
    from sqlalchemy import JSON
from api.db_models import Base


class PortalRemediationComment(Base):
    __tablename__ = "portal_remediation_comments"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_edited: Mapped[bool] = mapped_column(nullable=False, default=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    __table_args__ = (Index("ix_portal_comments_tenant_task", "tenant_id", "task_id"),)


class PortalEvidenceSubmission(Base):
    __tablename__ = "portal_evidence_submissions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    submitted_by: Mapped[str] = mapped_column(String(255), nullable=False)
    submitted_at: Mapped[str] = mapped_column(String(64), nullable=False)
    classification: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending"
    )
    evidence_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    __table_args__ = (
        Index("ix_portal_evidence_tenant_task", "tenant_id", "task_id"),
        Index("ix_portal_evidence_sha256", "tenant_id", "sha256"),
        Index("ix_portal_evidence_verification", "tenant_id", "verification_state"),
    )


class PortalRemediationAuditEvent(Base):
    __tablename__ = "portal_remediation_audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    event_at: Mapped[str] = mapped_column(String(64), nullable=False)
    event_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    __table_args__ = (
        Index("ix_portal_audit_tenant_task", "tenant_id", "task_id"),
        Index("ix_portal_audit_event_type", "tenant_id", "event_type"),
        Index("ix_portal_audit_event_at", "event_at"),
    )
