# api/db_models_report_authority.py
"""SQLAlchemy ORM models for PR 18.1 — Enterprise Assessment Report Authority.

Tables:
  fa_report              — canonical report entity
  fa_report_audit_events — append-only audit trail (immutable after insert)
  fa_report_bundles      — export bundle records

Design:
  - Every table carries tenant_id NOT NULL
  - fa_report_audit_events is append-only (ORM-level guard raises on update/delete)
  - fa_report is the single source of truth for all report deliverables
"""

from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_report — canonical report entity
# ---------------------------------------------------------------------------


class FaReport(Base):
    """Canonical report entity — single source of truth for all report deliverables.

    Every other subsystem that needs to reference a generated report should link
    to fa_report.id. No subsystem creates its own report ownership model.
    """

    __tablename__ = "fa_report"

    # Identity
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    report_ref: Mapped[str] = mapped_column(String(512), nullable=False)

    # Classification
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="DRAFT"
    )
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0"
    )

    # Assessment linkage
    assessment_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    objectives: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Personnel
    assessor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    generator_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Quality scores
    quality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_coverage_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_coverage_score: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    freshness_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    completeness_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    quality_grade: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Hashes
    report_hash_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    report_hash_sha512: Mapped[str | None] = mapped_column(String(256), nullable=True)
    manifest_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    manifest_hash_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    manifest_hash_sha512: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Crypto
    transparency_root: Mapped[str | None] = mapped_column(String(256), nullable=True)
    merkle_root: Mapped[str | None] = mapped_column(String(256), nullable=True)
    signing_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Versioning
    report_version: Mapped[str] = mapped_column(
        String(64), nullable=False, default="1.0.0-r0"
    )
    major_version: Mapped[int] = mapped_column(Integer, default=1)
    minor_version: Mapped[int] = mapped_column(Integer, default=0)
    patch_version: Mapped[int] = mapped_column(Integer, default=0)
    report_revision: Mapped[int] = mapped_column(Integer, default=0)

    # Branding
    branding_config: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON blob
    regulatory_profile: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Metadata
    generator_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    export_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    manifest_schema_version: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )

    # Timestamps
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    published_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    superseded_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    archived_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    generation_started_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    generation_completed_at: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Formats
    has_pdf: Mapped[int] = mapped_column(Integer, default=0)
    has_html: Mapped[int] = mapped_column(Integer, default=0)
    has_json: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("ix_fa_report_tenant_state", "tenant_id", "lifecycle_state"),
        Index("ix_fa_report_tenant_assessment", "tenant_id", "assessment_id"),
    )


# ---------------------------------------------------------------------------
# fa_report_audit_events — append-only audit trail
# ---------------------------------------------------------------------------


class FaReportAuditEvent(Base):
    """Append-only audit trail for all report lifecycle mutations.

    Both UPDATE and DELETE are blocked at the ORM layer. Write audit events
    only via INSERT; never mutate or remove existing rows.
    """

    __tablename__ = "fa_report_audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_type: Mapped[str | None] = mapped_column(String(32), nullable=True)

    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    event_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)


@sa_event.listens_for(FaReportAuditEvent, "before_update")
def _block_audit_update(mapper, connection, target):
    raise RuntimeError("fa_report_audit_events is append-only — updates are forbidden")


@sa_event.listens_for(FaReportAuditEvent, "before_delete")
def _block_audit_delete(mapper, connection, target):
    raise RuntimeError("fa_report_audit_events is append-only — deletes are forbidden")


# ---------------------------------------------------------------------------
# fa_report_bundles — export bundle records
# ---------------------------------------------------------------------------


class FaReportBundle(Base):
    """Export bundle record for a report.

    Tracks the state and integrity hashes of a packaged report export (ZIP bundle
    containing PDF, HTML, JSON, manifest, and ancillary verification artifacts).
    """

    __tablename__ = "fa_report_bundles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    bundle_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )

    bundle_hash_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    bundle_hash_sha512: Mapped[str | None] = mapped_column(String(256), nullable=True)
    bundle_signature: Mapped[str | None] = mapped_column(Text, nullable=True)

    contains_pdf: Mapped[int] = mapped_column(Integer, default=0)
    contains_html: Mapped[int] = mapped_column(Integer, default=0)
    contains_json: Mapped[int] = mapped_column(Integer, default=0)
    contains_manifest: Mapped[int] = mapped_column(Integer, default=1)
    contains_trust_manifest: Mapped[int] = mapped_column(Integer, default=0)
    contains_transparency_proof: Mapped[int] = mapped_column(Integer, default=0)
    contains_evidence_index: Mapped[int] = mapped_column(Integer, default=0)
    contains_verification_instructions: Mapped[int] = mapped_column(Integer, default=1)

    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
