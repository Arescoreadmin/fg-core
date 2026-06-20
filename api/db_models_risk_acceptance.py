# api/db_models_risk_acceptance.py
"""SQLAlchemy ORM models for PR 14.1 — Risk Acceptance Governance Foundation.

Tables:
  risk_acceptances        — first-class governance record; lifecycle-managed
  risk_acceptance_audits  — append-only audit trail (immutable, survives parent deletion)

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — store layer always provides an explicit value.

Append-only contract:
  risk_acceptance_audits is append-only.  No UPDATE or DELETE path exists.
  Must survive parent (risk_acceptance) deletion — no CASCADE DELETE.

Status lifecycle:
  DRAFT → PENDING_APPROVAL → APPROVED → ACTIVE
  ACTIVE → EXPIRED (automatic on expiry date)
  ACTIVE → REVOKED (manual revocation)
  PENDING_APPROVAL → REJECTED
  PENDING_APPROVAL | DRAFT → REVOKED
  Terminal: EXPIRED, REVOKED, REJECTED
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class RiskAcceptance(Base):
    """First-class governance record for a formally accepted risk.

    Risk acceptance is NOT metadata on a remediation task.
    Risk acceptance is NOT a JSON blob.
    Risk acceptance is a governance record.
    """

    __tablename__ = "risk_acceptances"

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # -----------------------------------------------------------------------
    # Entity linkage
    # -----------------------------------------------------------------------
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # nullable — a risk acceptance may exist before or without a remediation task
    remediation_task_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )

    # -----------------------------------------------------------------------
    # Governance content
    # -----------------------------------------------------------------------
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    business_justification: Mapped[str] = mapped_column(Text, nullable=False)
    risk_rationale: Mapped[str] = mapped_column(Text, nullable=False)

    # -----------------------------------------------------------------------
    # Acceptance attribution
    # -----------------------------------------------------------------------
    accepted_by: Mapped[str] = mapped_column(String(255), nullable=False)
    accepted_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Governance authority
    # -----------------------------------------------------------------------
    approver_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    approver_role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # e.g. CISO | RISK_COMMITTEE | EXECUTIVE_SPONSOR | BUSINESS_OWNER
    approval_authority: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # e.g. api_key | oidc | policy_engine | delegated
    approval_source: Mapped[str] = mapped_column(
        String(64), nullable=False, default="api_key"
    )

    # -----------------------------------------------------------------------
    # Expiration management
    # -----------------------------------------------------------------------
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Residual risk scoring
    # -----------------------------------------------------------------------
    # LOW | MEDIUM | HIGH | CRITICAL
    inherent_risk: Mapped[str | None] = mapped_column(String(32), nullable=True)
    residual_risk: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # -----------------------------------------------------------------------
    # Compensating controls (structured JSON list)
    # e.g. [{"type": "network_segmentation", "description": "..."}]
    # -----------------------------------------------------------------------
    compensating_controls: Mapped[list | None] = mapped_column(
        JSON, nullable=True, default=list
    )

    # -----------------------------------------------------------------------
    # Review scheduling
    # -----------------------------------------------------------------------
    review_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    review_frequency_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    next_review_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Timestamps
    # -----------------------------------------------------------------------
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_risk_accept_tenant_finding", "tenant_id", "finding_id"),
        Index("ix_risk_accept_tenant_status", "tenant_id", "status"),
        Index("ix_risk_accept_tenant_assessment", "tenant_id", "assessment_id"),
        Index("ix_risk_accept_expires_at", "tenant_id", "expires_at"),
        Index("ix_risk_accept_next_review", "tenant_id", "next_review_at"),
    )


class RiskAcceptanceAudit(Base):
    """Append-only audit trail for every risk acceptance state change.

    Immutable by contract — no UPDATE or DELETE path.
    Must survive parent (risk_acceptance) deletion (no CASCADE).
    Old/new state snapshots enable full lifecycle reconstruction.
    """

    __tablename__ = "risk_acceptance_audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    risk_acceptance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # RISK_CREATED | RISK_SUBMITTED | RISK_APPROVED | RISK_REJECTED |
    # RISK_ACTIVATED | RISK_EXPIRED | RISK_REVOKED | RISK_UPDATED | RISK_REVIEWED
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # API key prefix or OIDC sub — non-repudiation anchor
    actor: Mapped[str] = mapped_column(String(255), nullable=False)

    old_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    event_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_risk_audits_tenant_ra", "tenant_id", "risk_acceptance_id"),
        Index("ix_risk_audits_event_type", "tenant_id", "event_type"),
        Index("ix_risk_audits_event_at", "event_at"),
    )
