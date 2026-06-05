"""SQLAlchemy ORM models for H14 Governance Decision Ledger.

Tables:
  fa_governance_decisions  — append-only governance decision ledger
  fa_risk_acceptances      — risk acceptance records (linked to decisions)
  fa_governance_exceptions — exception management records (linked to decisions)

All three tables are append-only. DB triggers in migration 0085 enforce
UPDATE/DELETE prohibition at the Postgres layer. The service layer (GovernanceDecisionService)
exposes no mutation methods, providing defence-in-depth.

Decision types (extensible — any string is valid):
  report_approved, risk_accepted, finding_closed, remediation_approved,
  exception_granted, policy_approved, legal_hold_applied, assessment_completed

Attribution model:
  actor_id        — API key prefix or OIDC sub; always captured (non-repudiation anchor)
  actor_name      — human-readable display name (from request body or JWT claim)
  actor_email     — email address for human accountability
  actor_role      — role/title at time of decision
  actor_auth_source — 'api_key', 'oidc', 'system'

Approval chain (supports future dual-control):
  creator_id   — who initiated the decision (defaults to actor_id)
  reviewer_id  — optional second reviewer
  approver_id  — required (defaults to actor_id for single-actor decisions)
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaGovernanceDecision(Base):
    """Immutable governance decision record.

    One row per governance act. Rows are never updated or deleted.
    The decision_type + entity_type + entity_id triple identifies
    what was decided and about what.
    """

    __tablename__ = "fa_governance_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Actor attribution
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_subject: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Auth0 sub / key prefix — non-repudiation anchor (H14)
    actor_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(512), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_auth_source: Mapped[str] = mapped_column(
        String(64), nullable=False, default="api_key"
    )

    # Approval chain
    creator_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)

    # Decision content
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False)
    decision_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")

    # Evidence provenance
    evidence_snapshot_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    evidence_refs: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    related_finding_ids: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON array
    related_control_ids: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON array

    # Timestamps
    decision_at: Mapped[str] = mapped_column(String(64), nullable=False)
    effective_until: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # H13 correlation
    transaction_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Type-specific extensible metadata
    decision_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    __table_args__ = (
        Index("ix_fa_gov_decisions_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_gov_decisions_entity", "entity_type", "entity_id"),
        Index("ix_fa_gov_decisions_type", "tenant_id", "decision_type"),
        Index("ix_fa_gov_decisions_actor", "tenant_id", "actor_id"),
    )


class FaRiskAcceptance(Base):
    """Structured risk acceptance record.

    Linked to a FaGovernanceDecision of type 'risk_accepted'.
    Every risk acceptance has a mandatory expiry and review date — no
    permanent risk acceptance is allowed by design.
    """

    __tablename__ = "fa_risk_acceptances"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    decision_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_owner: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_owner_email: Mapped[str | None] = mapped_column(String(512), nullable=True)
    business_justification: Mapped[str] = mapped_column(Text, nullable=False)
    accepted_risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(64), nullable=False)
    review_date: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_refs: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    approver_email: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_risk_accept_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_risk_accept_status", "tenant_id", "status"),
    )


class FaGovernanceException(Base):
    """Governance exception record.

    Linked to a FaGovernanceDecision of type 'exception_granted'.
    Every exception has a mandatory expiry. Exception sprawl is prevented
    by requiring business justification and compensating controls.
    """

    __tablename__ = "fa_governance_exceptions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    decision_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    exception_type: Mapped[str] = mapped_column(String(64), nullable=False)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_email: Mapped[str | None] = mapped_column(String(512), nullable=True)
    business_justification: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[str] = mapped_column(String(64), nullable=False)
    review_schedule: Mapped[str | None] = mapped_column(String(64), nullable=True)
    related_control_ids: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON array
    related_finding_ids: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON array
    compensating_controls: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON array of descriptions
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_exceptions_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_gov_exceptions_status", "tenant_id", "status"),
    )
