"""SQLAlchemy ORM model for governance asset candidates.

Candidates are the persistent state of the pipeline between connector detection
and governance asset promotion. They accumulate detection history across rescans,
carry a lifecycle status, and provide the operator inbox for pending review.

Candidate identity:
  candidate_id = SHA-256(tenant_id:source_type:candidate_type:risk_signal)
  Same risk signal from same source in same tenant → same candidate_id.
  Re-scanning updates detection_count and last_detected_at in-place; it never
  creates a duplicate row. This makes the table a living record of persistent
  governance risk, not a per-scan dump.

Lifecycle:
  detected → under_review → promoted → rejected
                         → superseded (if a newer, higher-confidence candidate
                                       replaces a prior promoted asset)

Auto-promotion threshold:
  Candidates with confidence ≥ AUTO_PROMOTE_CONFIDENCE_THRESHOLD are
  automatically promoted to GaAsset on first detection.
  Lower-confidence candidates land in the review inbox.

Schema:
  ga_asset_candidates(
    candidate_id      TEXT PK  (sha256 of identity key)
    tenant_id         TEXT NOT NULL
    engagement_id     TEXT nullable
    scan_result_id    TEXT nullable
    report_id         TEXT nullable
    source_type       TEXT NOT NULL   (microsoft_graph, aws, ...)
    candidate_type    TEXT NOT NULL   (ai_application, enterprise_application, ...)
    risk_signal       TEXT NOT NULL   (shadow_ai, critical_risky_scopes, ...)
    suggested_name    TEXT NOT NULL
    suggested_asset_type TEXT NOT NULL
    confidence        INTEGER NOT NULL
    status            TEXT NOT NULL DEFAULT 'detected'
    promoted_asset_id TEXT nullable   → GaAsset.asset_id
    promoted_at       TEXT nullable
    rejected_reason   TEXT nullable
    rejected_at       TEXT nullable
    reviewed_by       TEXT nullable
    auto_promoted     BOOLEAN NOT NULL DEFAULT FALSE
    last_manifest_hash TEXT NOT NULL
    evidence_ref_ids  JSON NOT NULL DEFAULT []
    detection_count   INTEGER NOT NULL DEFAULT 1
    peak_confidence   INTEGER NOT NULL
    first_detected_at TEXT NOT NULL
    last_detected_at  TEXT NOT NULL
    schema_version    TEXT NOT NULL DEFAULT '1.0'
    created_at        TEXT NOT NULL
    updated_at        TEXT NOT NULL
  )
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base

AUTO_PROMOTE_CONFIDENCE_THRESHOLD = 88


class GaAssetCandidate(Base):
    """Persistent governance asset candidate with accumulated detection history.

    The table is the operator's governance inbox: every unreviewed high-risk
    signal lands here and stays until promoted, rejected, or superseded.
    """

    __tablename__ = "ga_asset_candidates"

    candidate_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scan_result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    candidate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_signal: Mapped[str] = mapped_column(String(128), nullable=False)

    suggested_name: Mapped[str] = mapped_column(String(512), nullable=False)
    suggested_asset_type: Mapped[str] = mapped_column(String(64), nullable=False)

    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    peak_confidence: Mapped[int] = mapped_column(Integer, nullable=False)

    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="detected", index=True
    )
    promoted_asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    promoted_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auto_promoted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    rejected_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    rejected_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(512), nullable=True)

    last_manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_ref_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_detected_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_detected_at: Mapped[str] = mapped_column(String(64), nullable=False)

    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        # One candidate per (tenant, source, type, signal) — the idempotency key.
        UniqueConstraint(
            "tenant_id",
            "source_type",
            "candidate_type",
            "risk_signal",
            name="uq_ga_candidate_signal",
        ),
        Index("ix_ga_candidates_tenant_status", "tenant_id", "status"),
        Index("ix_ga_candidates_tenant_source", "tenant_id", "source_type"),
        Index("ix_ga_candidates_promoted_asset", "promoted_asset_id"),
    )
