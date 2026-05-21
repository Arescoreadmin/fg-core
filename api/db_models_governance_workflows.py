# api/db_models_governance_workflows.py
"""SQLAlchemy ORM model for the Autonomous Governance Workflow Engine.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Infrastructure note (PR 6):
  Extends Base.metadata with one governance workflow table.
  Imported by api.db._ensure_models_imported() so init_db() creates the table.

Tenant isolation:
  All queries must include a tenant_id predicate.

Tables:
  governance_workflows — deterministic workflow lifecycle records

Audit trail:
  Workflow transitions are recorded as FaEngagementAuditEvent rows
  (event_type="workflow.transition") — no separate transition table.

Evidence:
  Completion evidence is stored as FaEvidenceLink rows
  (source_entity_type="workflow", source_entity_id=workflow.id) — no separate
  evidence table.  Evidence attached to closed workflows is queryable by the
  drift engine through the same FaEvidenceLink table it already traverses.
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class GovernanceWorkflow(Base):
    """Deterministic governance workflow record.

    id = SHA-256(tenant_id:engagement_id:template_name:context_ref_id:created_at)[:32]
    state machine: draft → active → escalated → resolved → archived
    Evidence is fail-closed: resolved requires at least one FaEvidenceLink per
    required_evidence_type defined in the workflow template.
    """

    __tablename__ = "governance_workflows"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    template_name: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    priority: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    assigned_to_role: Mapped[str] = mapped_column(String(64), nullable=False)
    context_ref_type: Mapped[str] = mapped_column(String(64), nullable=False)
    context_ref_id: Mapped[str] = mapped_column(String(512), nullable=False)
    due_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    resolved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    archived_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSON, nullable=False, default=dict
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index(
            "ix_gw_workflows_engagement_state",
            "tenant_id",
            "engagement_id",
            "state",
        ),
        Index("ix_gw_workflows_tenant_context", "tenant_id", "context_ref_id"),
        Index("ix_gw_workflows_tenant_due", "tenant_id", "due_at"),
    )
