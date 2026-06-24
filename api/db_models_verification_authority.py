# api/db_models_verification_authority.py
"""SQLAlchemy ORM models for PR 14.6.6 — Verification Workflow Authority.

Tables:
  fa_verification_requests       — workflow state machine per evidence
  fa_verification_results        — append-only decision records
  fa_verification_request_audits — append-only audit trail

Design principles:
  - Every table carries tenant_id NOT NULL — never query without it.
  - Append-only tables (results, audits) have ORM-level guards below.
    PostgreSQL-level guards are in migration 0130.
  - fa_verification_requests is the single source of truth for workflow state.

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — the engine always provides an explicit value.
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base
from sqlalchemy import Index


# ---------------------------------------------------------------------------
# fa_verification_requests — workflow state machine
# ---------------------------------------------------------------------------


class FaVerificationRequest(Base):
    """Verification workflow request entity — the workflow authority."""

    __tablename__ = "fa_verification_requests"

    # Identity
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Workflow state
    workflow_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="REQUESTED"
    )

    # Requester
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    requester_actor_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="human"
    )
    requested_at: Mapped[str] = mapped_column(String(64), nullable=False)

    # Assignee
    assignee_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assignee_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assigned_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Priority (0-100, higher = more urgent)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    # Notes
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # SLA deadlines
    review_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    escalation_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assigned_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Terminal timestamps
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cancelled_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expired_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Escalation tracking
    escalation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_escalation_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_escalated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_escalated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Audit timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_verification_requests_evidence",
            "tenant_id",
            "evidence_id",
        ),
        Index(
            "ix_fa_verification_requests_state",
            "tenant_id",
            "workflow_state",
        ),
    )


# ---------------------------------------------------------------------------
# fa_verification_results — append-only decision records
# ---------------------------------------------------------------------------


class FaVerificationResult(Base):
    """Append-only verification decision record.

    Both UPDATE and DELETE are blocked at the ORM layer and PostgreSQL layer.
    """

    __tablename__ = "fa_verification_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)

    result: Mapped[str] = mapped_column(String(32), nullable=False)  # APPROVED/REJECTED
    decided_by: Mapped[str] = mapped_column(String(255), nullable=False)
    decider_actor_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="human"
    )
    decision_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_verification_results_request",
            "tenant_id",
            "request_id",
        ),
    )


@sa_event.listens_for(FaVerificationResult, "before_update")
def _block_result_update(mapper, connection, target):
    raise RuntimeError("fa_verification_results is append-only")


@sa_event.listens_for(FaVerificationResult, "before_delete")
def _block_result_delete(mapper, connection, target):
    raise RuntimeError("fa_verification_results is append-only")


# ---------------------------------------------------------------------------
# fa_verification_request_audits — append-only audit trail
# ---------------------------------------------------------------------------


class FaVerificationRequestAudit(Base):
    """Append-only audit trail for verification workflow events.

    Both UPDATE and DELETE are blocked at the ORM layer and PostgreSQL layer.
    """

    __tablename__ = "fa_verification_request_audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(64), nullable=False, default="human")

    old_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    occurred_at: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_vra_request",
            "tenant_id",
            "request_id",
        ),
    )


@sa_event.listens_for(FaVerificationRequestAudit, "before_update")
def _block_audit_update(mapper, connection, target):
    raise RuntimeError("fa_verification_request_audits is append-only")


@sa_event.listens_for(FaVerificationRequestAudit, "before_delete")
def _block_audit_delete(mapper, connection, target):
    raise RuntimeError("fa_verification_request_audits is append-only")
