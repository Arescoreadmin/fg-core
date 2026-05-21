# api/db_models_governance_graph.py
"""SQLAlchemy ORM models for the Governance Topology Graph.

Infrastructure note (PR 5):
  Extends Base.metadata with four governance graph tables.
  Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.

Tables:
  governance_graph_snapshots  — rebuild audit trail and counters
  governance_graph_nodes      — derived entity nodes
  governance_graph_edges      — derived relationship edges
  governance_graph_anomalies  — structural anomaly detections
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class GovernanceGraphSnapshot(Base):
    """Rebuild audit record — one row per graph rebuild triggered.

    snapshot_seq is monotonically increasing per tenant.
    triggered_by distinguishes rebuild sources: rebuild_api, msgraph_import, scheduled.
    """

    __tablename__ = "governance_graph_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    snapshot_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    nodes_upserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edges_upserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    nodes_deleted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edges_deleted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    anomalies_detected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    triggered_by: Mapped[str] = mapped_column(
        String(64), nullable=False, default="rebuild_api"
    )
    built_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index("ix_gg_snapshots_tenant_seq", "tenant_id", "snapshot_seq"),
    )


class GovernanceGraphNode(Base):
    """Derived entity node in the governance topology graph.

    node_id = SHA-256(tenant_id:node_type:entity_id) — deterministic and stable.
    trust_score=100 means the source record is live; 0 means the source was deleted.
    degree_centrality is computed by update_centrality() after each rebuild.
    """

    __tablename__ = "governance_graph_nodes"

    node_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(512), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(128), nullable=False)
    label: Mapped[str] = mapped_column(String(512), nullable=False)
    properties: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    degree_centrality: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    centrality_rank: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    source_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    engagement_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    derivation_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    derived_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index("ix_gg_nodes_tenant_type", "tenant_id", "node_type"),
        Index("ix_gg_nodes_tenant_entity", "tenant_id", "entity_id"),
        Index("ix_gg_nodes_tenant_derived_at", "tenant_id", "derived_at"),
    )


class GovernanceGraphEdge(Base):
    """Derived relationship edge in the governance topology graph.

    edge_id = SHA-256(tenant_id:edge_type:source_node_id:target_node_id).
    weight and confidence are updated on each rebuild.
    """

    __tablename__ = "governance_graph_edges"

    edge_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_node_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_node_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    properties: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    engagement_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    derived_at: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index("ix_gg_edges_tenant_type", "tenant_id", "edge_type"),
        Index("ix_gg_edges_tenant_source", "tenant_id", "source_node_id"),
        Index("ix_gg_edges_tenant_target", "tenant_id", "target_node_id"),
        Index("ix_gg_edges_tenant_derived_at", "tenant_id", "derived_at"),
    )


class GovernanceGraphAnomaly(Base):
    """Structural anomaly detected during graph rebuild.

    anomaly_id = SHA-256(tenant_id:pattern_id:snapshot_id).
    is_active=True until manually resolved or superseded by a clean rebuild.
    severity: critical|high|medium|low.
    """

    __tablename__ = "governance_graph_anomalies"

    anomaly_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    pattern_id: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    node_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    edge_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    detected_at: Mapped[str] = mapped_column(String(64), nullable=False)
    resolved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index("ix_gg_anomalies_tenant_pattern", "tenant_id", "pattern_id"),
        Index("ix_gg_anomalies_tenant_active", "tenant_id", "is_active"),
    )
