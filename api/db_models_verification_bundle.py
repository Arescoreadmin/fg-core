"""SQLAlchemy ORM model for PR 52 / PR 52.5 Verification Bundle.

Table:
  fa_verification_bundles — immutable verification bundle records (append-only)

Each row captures a snapshot of a completed verification bundle generation run.
Rows are never updated or deleted. The service layer (VerificationBundleService)
exposes no mutation methods. DB-level append-only enforcement is provided by
Postgres triggers in migration 0087.

Bundle status values:
  verified         — all tamper checks passed, report present
  incomplete       — engagement has no approved report yet
  tamper_detected  — one or more hash/ref integrity issues found

Coverage status values (PR 52.5 H8):
  complete           — all components present, no issues
  partial            — report present but some components empty
  missing_report     — no finalized report
  missing_evidence   — no evidence links recorded
  missing_decisions  — no governance decisions recorded
  tampered           — tamper issues detected
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaVerificationBundle(Base):
    """Immutable verification bundle record.

    One row per generation run. Each bundle captures counts + hashes for all
    components and stores tamper detection results.
    """

    __tablename__ = "fa_verification_bundles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    bundle_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    # Component counts (PR 52 original)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    interview_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    decision_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_acceptance_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    exception_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    audit_event_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )  # scan audit events
    has_report: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # PR 52.5 hardening columns
    engagement_audit_event_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    coverage_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    report_artifact_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report_artifact_hash_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_available"
    )
    chain_of_custody_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    signature_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    regulatory_context: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    governance_activity: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    # Bundle payload
    tamper_details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    component_summary: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    bundle_json: Mapped[str] = mapped_column(Text, nullable=False)  # full bundle JSON

    __table_args__ = (
        Index("ix_fa_vbundles_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_vbundles_engagement_time", "engagement_id", "generated_at"),
    )
