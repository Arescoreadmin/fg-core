"""SQLAlchemy ORM models for P0-11 Continuous Governance Control Tower (CGCT) tables.

Mirrors migration 0116.

Classes:
  FaCgctPostureSnapshot — fg_cgct_posture_snapshots (append-only governance posture)
  FaCgctActionItem      — fg_cgct_action_queue (deterministic action items, append-only)
  FaCgctGraphEdge       — fg_cgct_graph_edges (graph-ready governance relationships, append-only)

All tables are append-only. CGCT aggregates from existing authority systems only —
no new trust/cert/risk/evidence engines.

Authority sources:
  Trust Arc (FaTrustCertification), TIM (FaTimTrustSnapshot, FaTimDriftEvent),
  CLM (FaClmCert), Governance Decision (FaGovernanceDecision),
  Verification Bundle (FaVerificationBundle), Timeline (TimelineEventRecord),
  QTB (FaQtbBrief)
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaCgctPostureSnapshot(Base):
    """Append-only CGCT governance posture snapshot.

    Computed by services.cgct.posture.compute_posture() from authoritative
    source tables. Each evaluation appends a new row — the most recent row
    per (tenant_id, engagement_id) by computed_at is the current posture.

    overall_score: 0-100 weighted composite.
    governance_health: healthy|attention_required|degraded|at_risk|critical
    actor_type: human|agent|system|workflow (governance readiness)
    score_inputs_json: JSON explaining all contributing scores and source IDs.
    """

    __tablename__ = "fg_cgct_posture_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Composite governance score (0-100)
    overall_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    governance_health: Mapped[str] = mapped_column(
        String(32), nullable=False, default="critical"
    )

    # Component scores (0-100 each)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cert_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Operational context
    operational_readiness: Mapped[str | None] = mapped_column(String(64), nullable=True)
    governance_status: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Open item counts
    open_action_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_drift_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active_cert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_cert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Explainability — source IDs enabling audit trail from score → source record
    trust_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cert_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    score_inputs_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    # Governance readiness
    actor_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="system"
    )

    computed_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaCgctActionItem(Base):
    """Append-only CGCT action queue item.

    Generated deterministically from authoritative source tables.
    No AI recommendations — only rules-based detection from existing data.

    action_type: review_certification|renew_certification|investigate_drift|
                 validate_evidence|review_exception|escalate_risk|close_finding|verify_trust
    priority: critical|high|medium|low
    status: open|closed|deferred|acknowledged
    source_system: clm|tim|trust_arc|qtb|decision_ledger|verification_bundle
    actor_type: human|agent|system|workflow (governance readiness)
    """

    __tablename__ = "fg_cgct_action_queue"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Action classification
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    action_title: Mapped[str] = mapped_column(Text, nullable=False)
    action_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Priority and status
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")

    # Source authority link
    source_system: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Evidence references
    evidence_refs_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Governance readiness
    actor_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="system"
    )

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    closed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )


class FaCgctGraphEdge(Base):
    """Append-only CGCT governance graph edge.

    Graph-READY storage: edges are stored relationally, not in a graph DB.
    Consumers derive graph structure from these edges.

    from_node_type / to_node_type:
      trust|certification|evidence|decision|drift|risk|monitoring|
      attestation|lifecycle|renewal|timeline_event|verification_bundle

    relationship:
      influences|impacts|drives|supports|references|validates|supersedes

    direction: directed|bidirectional
    """

    __tablename__ = "fg_cgct_graph_edges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Source node
    from_node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_node_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Target node
    to_node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    to_node_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Relationship metadata
    relationship: Mapped[str] = mapped_column(String(32), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    direction: Mapped[str] = mapped_column(
        String(16), nullable=False, default="directed"
    )

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
