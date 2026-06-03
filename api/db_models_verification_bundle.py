"""SQLAlchemy ORM model for PR 52 Verification Bundle.

Table:
  fa_verification_bundles — immutable verification bundle records (append-only)

Each row captures a snapshot of a completed verification bundle generation run.
Rows are never updated or deleted. The service layer (VerificationBundleService)
exposes no mutation methods.

Bundle status values:
  verified         — all tamper checks passed, report present
  incomplete       — engagement has no approved report yet
  tamper_detected  — one or more hash/ref integrity issues found
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaVerificationBundle(Base):
    """Immutable verification bundle record.

    One row per generation run. Each bundle captures counts + hashes for all
    9 engagement components and stores tamper detection results.
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
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    interview_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    decision_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_acceptance_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    exception_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    audit_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    has_report: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tamper_details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    component_summary: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    bundle_json: Mapped[str] = mapped_column(Text, nullable=False)  # full bundle JSON

    __table_args__ = (
        Index("ix_fa_vbundles_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_vbundles_engagement_time", "engagement_id", "generated_at"),
    )
