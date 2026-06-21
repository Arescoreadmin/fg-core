# api/db_models_control_registry.py
"""SQLAlchemy ORM models for PR 14.3 — Compensating Control Registry.

Tables:
  control_registry               — compensating control records
  control_evidence_links         — evidence → control associations (append-only)
  risk_acceptance_control_links  — risk acceptance → control associations
  control_reviews                — periodic control review records
  control_audits                 — append-only control audit trail

Tenant isolation:
  All queries must include a tenant_id predicate.

Append-only contract:
  control_audits is append-only. No UPDATE or DELETE path.
  control_evidence_links is append-only.

Control lifecycle:
  DRAFT → ACTIVE → RETIRED | SUSPENDED
  SUSPENDED → ACTIVE

Verification lifecycle:
  UNVERIFIED → PENDING → VERIFIED → EXPIRED | FAILED
"""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class ControlRegistry(Base):
    """Compensating control record.

    control_id is the immutable public identifier set at creation.
    Internal id is the DB primary key used in URL paths.
    """

    __tablename__ = "control_registry"

    # Identity
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Immutable public identifier — set at creation, never updated
    control_id: Mapped[str] = mapped_column(String(255), nullable=False)

    # Description
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Classification
    control_type: Mapped[str] = mapped_column(String(64), nullable=False)
    criticality: Mapped[str] = mapped_column(
        String(32), nullable=False, default="medium"
    )

    # Ownership
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Effectiveness and verification
    effectiveness_rating: Mapped[str] = mapped_column(
        String(64), nullable=False, default="unknown"
    )
    verification_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="unverified"
    )

    # Lifecycle
    control_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="draft"
    )

    # Review schedule
    review_frequency_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90
    )
    next_review_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_review_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_verified_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_control_tenant_status", "tenant_id", "control_status"),
        Index("ix_control_tenant_control_id", "tenant_id", "control_id"),
        Index("ix_control_tenant_verification", "tenant_id", "verification_status"),
        Index("ix_control_tenant_type", "tenant_id", "control_type"),
    )


class ControlEvidenceLink(Base):
    """Links a compensating control to an evidence artifact.

    Append-only: no UPDATE or DELETE path. Evidence lineage is immutable.
    """

    __tablename__ = "control_evidence_links"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Control reference
    control_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Evidence reference (external ID — no FK to preserve loose coupling)
    evidence_id: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(128), nullable=False)

    # Linkage metadata
    linked_at: Mapped[str] = mapped_column(String(64), nullable=False)
    linked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_cev_link_tenant_control", "tenant_id", "control_id"),
        Index("ix_cev_link_tenant_evidence", "tenant_id", "evidence_id"),
    )


class RiskAcceptanceControlLink(Base):
    """Links a risk acceptance to a compensating control.

    Many-to-many: one risk may have many controls; one control may cover many risks.
    """

    __tablename__ = "risk_acceptance_control_links"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Linkage
    risk_acceptance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    control_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Rationale
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_racl_tenant_control", "tenant_id", "control_id"),
        Index("ix_racl_tenant_ra", "tenant_id", "risk_acceptance_id"),
    )


class ControlReview(Base):
    """Periodic governance review for a compensating control.

    Reviews are governance artifacts. Each scheduled review produces an
    immutable record regardless of completion status.
    """

    __tablename__ = "control_reviews"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Linkage
    control_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Reviewer
    reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")

    # Schedule
    review_date: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Outcome
    outcome: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Effectiveness before/after
    effectiveness_before: Mapped[str | None] = mapped_column(String(64), nullable=True)
    effectiveness_after: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Evidence at review time
    evidence_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_control_review_tenant_control", "tenant_id", "control_id"),
        Index("ix_control_review_status", "tenant_id", "status"),
        Index("ix_control_review_date", "tenant_id", "review_date"),
    )


class ControlAudit(Base):
    """Append-only audit trail for control lifecycle events.

    Immutable: no UPDATE or DELETE. Governance evidence must be preserved.
    """

    __tablename__ = "control_audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Linkage
    control_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Event
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    old_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_control_audit_tenant_control", "tenant_id", "control_id"),
    )
