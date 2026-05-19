# api/db_models_field_assessment.py
"""SQLAlchemy ORM models for the Field Assessment Engagement Substrate.

Infrastructure note (PR 103):
  Extends Base.metadata with seven field assessment tables.
  Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — store layer always provides an explicit value.

Append-only contract:
  fa_engagement_audit_events is append-only. No UPDATE or DELETE.

Tables:
  fa_engagements              — top-level engagement tracking
  fa_scan_results             — structured scan ingestion
  fa_document_analyses        — document analysis records
  fa_field_observations       — structured assessor observations
  fa_normalized_findings      — core governance finding objects
  fa_evidence_links           — evidence relationship graph
  fa_engagement_audit_events  — append-only audit trail
"""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class FaEngagement(Base):
    """Top-level field assessment engagement record."""

    __tablename__ = "fa_engagements"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    client_name: Mapped[str] = mapped_column(String(255), nullable=False)
    client_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assessor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    assessment_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="scheduled")
    scheduled_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    engagement_metadata: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_engagements_tenant_status", "tenant_id", "status"),
        Index("ix_fa_engagements_tenant_created", "tenant_id", "created_at"),
    )


class FaScanResult(Base):
    """Structured scan ingestion record."""

    __tablename__ = "fa_scan_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    collected_at: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    normalized_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    object_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "engagement_id",
            "tenant_id",
            "evidence_hash",
            name="uq_fa_scan_evidence",
        ),
        Index("ix_fa_scan_results_engagement_tenant", "engagement_id", "tenant_id"),
        Index("ix_fa_scan_results_tenant_source", "tenant_id", "source_type"),
    )


class FaDocumentAnalysis(Base):
    """Document analysis record."""

    __tablename__ = "fa_document_analyses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    document_name: Mapped[str] = mapped_column(String(512), nullable=False)
    document_classification: Mapped[str] = mapped_column(String(64), nullable=False)
    document_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version_label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approval_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    freshness_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analysis_findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    gaps_identified: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_doc_analyses_engagement_tenant", "engagement_id", "tenant_id"),
    )


class FaFieldObservation(Base):
    """Structured assessor observation record."""

    __tablename__ = "fa_field_observations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    domain: Mapped[str] = mapped_column(String(64), nullable=False)
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    interview_role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    structured_evidence: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict
    )
    linked_finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    assessor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_field_obs_engagement_tenant", "engagement_id", "tenant_id"),
        Index("ix_fa_field_obs_tenant_domain", "tenant_id", "domain"),
    )


class FaNormalizedFinding(Base):
    """Core governance finding object — deduplicated via findings_hash."""

    __tablename__ = "fa_normalized_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False)
    findings_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_attribution: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=80)
    framework_mappings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    nist_ai_rmf_mappings: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    evidence_ref_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    remediation_hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "findings_hash", name="uq_fa_finding_hash"),
        Index("ix_fa_findings_engagement_tenant", "engagement_id", "tenant_id"),
        Index("ix_fa_findings_tenant_severity", "tenant_id", "severity"),
        Index("ix_fa_findings_tenant_status", "tenant_id", "status"),
    )


class FaEvidenceLink(Base):
    """Evidence relationship graph edge."""

    __tablename__ = "fa_evidence_links"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    link_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "engagement_id",
            "source_entity_id",
            "source_entity_type",
            "evidence_entity_id",
            "evidence_entity_type",
            name="uq_fa_evidence_link",
        ),
        Index("ix_fa_evidence_links_engagement_tenant", "engagement_id", "tenant_id"),
        Index("ix_fa_evidence_links_source_entity", "tenant_id", "source_entity_id"),
        Index(
            "ix_fa_evidence_links_evidence_entity", "tenant_id", "evidence_entity_id"
        ),
    )


class FaEngagementAuditEvent(Base):
    """Append-only audit event for engagement lifecycle mutations."""

    __tablename__ = "fa_engagement_audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_audit_events_engagement_tenant_time",
            "engagement_id",
            "tenant_id",
            "created_at",
        ),
        Index("ix_fa_audit_events_tenant_type", "tenant_id", "event_type"),
    )
