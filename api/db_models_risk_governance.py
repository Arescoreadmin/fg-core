# api/db_models_risk_governance.py
"""SQLAlchemy ORM models for PR 14.2 — Risk Governance Engine.

Tables:
  risk_acceptance_approvals       — first-class formal approval records
  risk_approval_policies          — governance policy configuration
  risk_acceptance_approval_audits — append-only approval audit trail
  risk_reviews                    — periodic review records
  risk_governance_escalations     — escalation records for governance debt

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — store layer always provides an explicit value.

Append-only contract:
  risk_acceptance_approval_audits is append-only. No UPDATE or DELETE path.
  Must survive parent deletion — no CASCADE DELETE.

Approval lifecycle:
  PENDING → APPROVED | REJECTED
  PENDING → EXPIRED (automatic)
  APPROVED → REVOKED

Review lifecycle:
  PENDING → COMPLETED | WAIVED | OVERDUE

Escalation lifecycle:
  Append-only records; not a state machine.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class RiskAcceptanceApproval(Base):
    """First-class formal approval record for a risk acceptance.

    One risk acceptance may have multiple approvals (multi-approver, committee, etc.).
    Approvals are never stored as JSON arrays inside RiskAcceptance.
    """

    __tablename__ = "risk_acceptance_approvals"

    # Identity
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Linkage
    risk_acceptance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # Approver identity
    approver_name: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approver_role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approval_authority: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Classification
    approval_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")

    # Decision
    comments: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Expiration
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Quorum support
    quorum_required: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quorum_position: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_risk_approval_tenant_ra", "tenant_id", "risk_acceptance_id"),
        Index("ix_risk_approval_status", "tenant_id", "status"),
    )


class RiskApprovalPolicy(Base):
    """Governance policy governing how approvals are obtained for a tenant.

    Policies are tenant-scoped configuration records that drive approval behavior.
    Hardcoded workflow logic is forbidden — behavior derives from policy fields.
    """

    __tablename__ = "risk_approval_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Identity
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Approval thresholds
    approval_threshold: Mapped[str] = mapped_column(
        String(64), nullable=False, default="single"
    )
    required_roles: Mapped[list | None] = mapped_column(JSON, nullable=True)
    required_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    quorum_percentage: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Expiration
    auto_expire_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    review_frequency_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90
    )

    # Sequential vs parallel
    sequential: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class RiskAcceptanceApprovalAudit(Base):
    """Append-only audit trail for approval lifecycle events.

    Immutable: no UPDATE or DELETE. Governance evidence must be preserved.
    """

    __tablename__ = "risk_acceptance_approval_audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    approval_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_acceptance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    old_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_risk_approval_audit_tenant_ra", "tenant_id", "risk_acceptance_id"),
    )


class RiskReview(Base):
    """Periodic governance review record for an active risk acceptance.

    Reviews are governance artifacts, not reminders. Each scheduled review
    produces an immutable record regardless of completion status.
    """

    __tablename__ = "risk_reviews"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Linkage
    risk_acceptance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # Classification
    review_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="periodic"
    )

    # Reviewer
    reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")

    # Schedule
    review_due_at: Mapped[str] = mapped_column(String(64), nullable=False)
    review_completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Notes
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_risk_review_tenant_ra", "tenant_id", "risk_acceptance_id"),
        Index("ix_risk_review_status", "tenant_id", "status"),
        Index("ix_risk_review_due", "tenant_id", "review_due_at"),
    )


class RiskGovernanceEscalation(Base):
    """Escalation record for governance debt.

    Escalations are append-only signals consumed by autonomous governance systems.
    They record governance failures — missed reviews, expired approvals, critical risks.
    """

    __tablename__ = "risk_governance_escalations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Linkage
    risk_acceptance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # Classification
    trigger: Mapped[str] = mapped_column(String(128), nullable=False)
    level: Mapped[str] = mapped_column(String(32), nullable=False)

    # Details
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)

    # Resolution
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    resolved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_risk_escalation_tenant_ra", "tenant_id", "risk_acceptance_id"),
        Index("ix_risk_escalation_level", "tenant_id", "level", "resolved"),
    )
