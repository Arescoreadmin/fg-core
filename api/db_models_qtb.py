"""SQLAlchemy ORM models for P0-9 Quarterly Trust Briefs (QTB) tables.

Mirrors migration 0114.

Classes:
  FaQtbBrief         — fa_qtb_briefs (status-mutable workflow record)
  FaQtbBriefSection  — fa_qtb_brief_sections (append-only content)
  FaQtbBriefManifest — fa_qtb_brief_manifests (append-only audit anchor)
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaQtbBrief(Base):
    """Quarterly Trust Brief main record.

    Tracks the lifecycle of a generated trust report from draft through
    delivery.  Content is immutable once generated (brief_hash set).
    Status field is the only mutable column after creation.

    report_type: quarterly | board | executive | governance | certification | continuous
    status: draft | generated | reviewed | approved | delivered | archived
    generated_by: human | agent | system | workflow (governance-readiness)
    """

    __tablename__ = "fa_qtb_briefs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    report_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="quarterly"
    )
    year: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quarter: Mapped[int | None] = mapped_column(Integer, nullable=True)
    period_start: Mapped[str | None] = mapped_column(String(64), nullable=True)
    period_end: Mapped[str | None] = mapped_column(String(64), nullable=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    generated_by: Mapped[str] = mapped_column(
        String(255), nullable=False, default="system"
    )
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    brief_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    generation_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="qtb-1.0"
    )
    authority_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="v1"
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaQtbBriefSection(Base):
    """Immutable content section within a quarterly trust brief.

    Each brief has 5–6 sections depending on report_type:
      posture      — trust posture statistics for the period
      drift        — drift event analysis with rule/severity breakdown
      certification — certification lifecycle summary
      governance   — timeline activity + decision memory summary
      evidence     — appendix: all source IDs referenced by this report
      board_summary — condensed strategic overview (board reports only)

    Append-only: section_data is set once and never mutated.
    section_hash is SHA-256(section_data JSON with sorted keys).
    """

    __tablename__ = "fa_qtb_brief_sections"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    brief_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    section_type: Mapped[str] = mapped_column(String(32), nullable=False)
    section_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    section_data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    section_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaQtbBriefManifest(Base):
    """Deterministic audit manifest for a quarterly trust brief.

    One manifest per brief.  Contains JSON arrays of every source ID
    referenced in the report — enabling replay verification and
    auditor traceability from report metric → evidence source.

    Append-only: the manifest is the immutable audit anchor.
    manifest_hash = SHA-256(all source ID arrays).
    report_hash = SHA-256(brief_hash + manifest_hash).
    """

    __tablename__ = "fa_qtb_brief_manifests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    brief_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    snapshot_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    certification_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    drift_event_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    timeline_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    decision_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    bundle_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    report_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    generation_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="qtb-1.0"
    )
    authority_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="v1"
    )
    replay_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="v1"
    )

    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
