"""SQLAlchemy ORM models for P0-7 Trust Intelligence Monitoring (TIM) tables.

Mirrors migration 0113. Tables are append-only; no UPDATE or DELETE from
service layer.

Classes:
  FaTimTrustSnapshot  — fa_tim_trust_snapshots (0113)
  FaTimDriftEvent     — fa_tim_drift_events (0113)
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaTimTrustSnapshot(Base):
    """Periodic TIM trust state snapshot aggregated from Trust Arc sources.

    Computed by services.trust_monitoring.monitoring_engine and persisted
    after every trust arc activation. Provides point-in-time trust posture,
    certification state, drift summary, and evidence freshness in one row
    without requiring multi-table joins at read time.

    Append-only: each evaluation creates a new row; the most recent row
    per (tenant_id, engagement_id) by evaluated_at is the current state.
    """

    __tablename__ = "fa_tim_trust_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Trust posture (from latest fa_trust_intelligence_snapshot)
    posture_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    posture_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    risk_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )

    # Certification state (from latest fa_trust_certifications)
    certification_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_certified"
    )
    composite_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    certification_valid_until: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Drift summary (derived vs. previous TIM snapshot)
    drift_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    drift_direction: Mapped[str] = mapped_column(
        String(16), nullable=False, default="stable"
    )
    open_drift_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Evidence freshness
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Replay state: ok | failed | no_chain
    replay_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="no_chain"
    )

    # Source links back to Trust Arc tables
    last_snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_certification_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_bundle_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    evaluated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaTimDriftEvent(Base):
    """Deterministic drift event detected by TIM monitoring rules.

    All drift events are produced by rules-based detection (no AI):
      score_degradation      — posture_score dropped >= threshold
      cert_expiration        — certification expires within warning window
      cert_expired           — certification past valid_until
      evidence_staleness     — no new evidence in > threshold days
      replay_failure         — chain_replay_score == 0 or < 50
      missing_bundle         — no verification bundle in > threshold days
      consecutive_degradation — 3+ consecutive snapshots with degrading trend

    Severity levels: info | low | medium | high | critical (deterministic).
    Status is append-only: 'open' on creation; 'resolved' via new row.

    actor_type is governance-readiness extensible:
      system (default) | human | agent | workflow
    """

    __tablename__ = "fa_tim_drift_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    drift_rule: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    detected_at: Mapped[str] = mapped_column(String(64), nullable=False)
    resolved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="{}")  # JSON
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="system"
    )
    acknowledged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    acknowledged_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
