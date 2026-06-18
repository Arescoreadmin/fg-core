# api/db_models_remediation.py
"""SQLAlchemy ORM models for the Remediation Management subsystem.

PR 13.1 — Remediation Management Foundation.
PR 13.2 — Remediation Status Workflow Engine.

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — store layer always provides an explicit value.

Append-only contract:
  remediation_task_audits is append-only. No UPDATE or DELETE.

Tables:
  remediation_tasks         — corrective action tasks linked to findings
  remediation_task_audits   — append-only audit trail for every task mutation
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class RemediationTask(Base):
    """Corrective action task linked to a normalized finding."""

    __tablename__ = "remediation_tasks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    closed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Extension point: risk_acceptance_id, compensating_control_id, sla_config, etc.
    task_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index("ix_remediation_tasks_tenant_finding", "tenant_id", "finding_id"),
        Index("ix_remediation_tasks_tenant_assessment", "tenant_id", "assessment_id"),
        Index("ix_remediation_tasks_tenant_status", "tenant_id", "status"),
        Index("ix_remediation_tasks_tenant_priority", "tenant_id", "priority"),
    )


class RemediationTaskAudit(Base):
    """Append-only audit event for every remediation task mutation.

    No UPDATE or DELETE. Every task state change produces one row.
    Supports full lifecycle reconstruction from audit trail (REM-20).
    """

    __tablename__ = "remediation_task_audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    old_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # PR 13.2: transition reason — required for ACCEPTED_RISK, optional otherwise
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_remediation_audits_tenant_task", "tenant_id", "task_id"),
        Index("ix_remediation_audits_task_id", "task_id"),
        Index("ix_remediation_audits_tenant_event_type", "tenant_id", "event_type"),
        Index("ix_remediation_audits_event_at", "event_at"),
    )
