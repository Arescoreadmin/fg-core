# api/db_models_governance_reporting.py
"""SQLAlchemy ORM models for PR 14.5 — Governance Reporting & Attestation Engine.

Tables:
  risk_governance_reports          — generated governance report records (PR 14.5)
  risk_governance_report_manifests — cryptographic hash manifests (unique per report)
  risk_governance_attestations     — formal attestations of report integrity
  risk_governance_report_audits    — append-only audit trail for report lifecycle

Note: table names are prefixed with "risk_governance_" to avoid collision with the
existing "governance_reports" table (assessment reports, db_models_governance_report.py).

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.

Append-only contract:
  governance_report_audits is append-only. No UPDATE or DELETE path.
  governance_attestations is append-only. No UPDATE or DELETE path.

Report lifecycle:
  GENERATING → COMPLETED | FAILED
  COMPLETED → SUPERSEDED (when a newer version is generated for same risk)
"""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class GovernanceReport(Base):
    """Generated governance report record.

    Each report is a point-in-time snapshot of a risk acceptance and all
    associated governance artifacts (approvals, reviews, controls, evidence).
    Superseding creates a new record; previous records remain for audit purposes.
    """

    __tablename__ = "risk_governance_reports"

    # Identity
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Linkage
    risk_acceptance_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # Versioning
    report_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Generation metadata
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(255), nullable=False)

    # Integrity
    report_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Schema
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Snapshot context
    snapshot_timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Lifecycle
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="GENERATING"
    )

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_rg_report_tenant_ra", "tenant_id", "risk_acceptance_id"),
        Index("ix_rg_report_tenant_status", "tenant_id", "status"),
        {"extend_existing": True},
    )


class GovernanceReportManifest(Base):
    """Cryptographic hash manifest for a governance report.

    Stores section-level hashes so individual section integrity can be verified
    independently. overall_hash covers all section hashes; report_hash covers
    the full report content at a specific schema_version.
    """

    __tablename__ = "risk_governance_report_manifests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # One-to-one link to the report
    report_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Section hashes
    risk_acceptance_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approval_chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    review_history_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    control_evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    timeline_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    overall_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("report_id", name="uq_gov_manifest_report_id"),
        {"extend_existing": True},
    )


class GovernanceAttestation(Base):
    """Formal attestation of a governance report.

    Attestations are append-only governance artifacts. Multiple attestors may
    attest the same report with different roles (owner, approver, auditor, etc.).
    """

    __tablename__ = "risk_governance_attestations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Linkage
    report_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Attestor identity
    attestor: Mapped[str] = mapped_column(String(255), nullable=False)
    attestor_role: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Classification
    attestation_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Content
    attested_at: Mapped[str] = mapped_column(String(64), nullable=False)
    attestation_statement: Mapped[str] = mapped_column(Text, nullable=False)
    signature_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Schema
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    # Actor type (HUMAN | AGENT | SYSTEM)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="HUMAN")

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_rg_attestation_tenant_report", "tenant_id", "report_id"),
        {"extend_existing": True},
    )


class GovernanceReportAudit(Base):
    """Append-only audit trail for governance report lifecycle events.

    Immutable: no UPDATE or DELETE. Governance evidence must be preserved.
    """

    __tablename__ = "risk_governance_report_audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Linkage
    report_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Event
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    event_at: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_rg_report_audit_tenant_report_event",
            "tenant_id",
            "report_id",
            "event_at",
        ),
        {"extend_existing": True},
    )
