"""Idempotent graph write operations."""

from __future__ import annotations

import hashlib

from sqlalchemy import delete as sa_delete, func, select
from sqlalchemy.orm import Session

from api.db_models_governance_graph import (
    GovernanceGraphAnomaly,
    GovernanceGraphEdge,
    GovernanceGraphNode,
)
from services.canonical import utc_iso8601_z_now  # noqa: F401 — re-exported


def _node_id(tenant_id: str, node_type: str, entity_id: str) -> str:
    return hashlib.sha256(f"{tenant_id}:{node_type}:{entity_id}".encode()).hexdigest()


def _edge_id(
    tenant_id: str, edge_type: str, source_node_id: str, target_node_id: str
) -> str:
    return hashlib.sha256(
        f"{tenant_id}:{edge_type}:{source_node_id}:{target_node_id}".encode()
    ).hexdigest()


def upsert_node(
    db: Session,
    *,
    tenant_id: str,
    node_type: str,
    entity_id: str,
    entity_type: str,
    label: str,
    properties: dict,
    tags: list,
    trust_score: int = 100,
    confidence: int = 100,
    source_ref: str,
    engagement_id: str | None = None,
    snapshot_id: str | None = None,
    derived_at: str,
) -> GovernanceGraphNode:
    """Upsert a node by deterministic node_id."""
    node_id = _node_id(tenant_id, node_type, entity_id)
    existing = db.get(GovernanceGraphNode, node_id)
    if existing is not None:
        existing.label = label
        existing.properties = properties
        existing.trust_score = trust_score
        existing.confidence = confidence
        existing.source_ref = source_ref
        existing.snapshot_id = snapshot_id
        existing.derived_at = derived_at
        db.flush()
        return existing
    node = GovernanceGraphNode(
        node_id=node_id,
        tenant_id=tenant_id,
        node_type=node_type,
        entity_id=entity_id,
        entity_type=entity_type,
        label=label,
        properties=properties,
        tags=tags,
        trust_score=trust_score,
        degree_centrality=0,
        centrality_rank=None,
        confidence=confidence,
        source_ref=source_ref,
        engagement_id=engagement_id,
        derivation_signature=None,
        snapshot_id=snapshot_id,
        derived_at=derived_at,
        schema_version="1.0",
    )
    db.add(node)
    db.flush()
    return node


def upsert_edge(
    db: Session,
    *,
    tenant_id: str,
    edge_type: str,
    source_node_id: str,
    target_node_id: str,
    weight: int = 1,
    confidence: int = 100,
    properties: dict,
    source_ref: str,
    engagement_id: str | None = None,
    snapshot_id: str | None = None,
    derived_at: str,
) -> GovernanceGraphEdge:
    """Upsert an edge. Skips if source or target node don't exist."""
    edge_id = _edge_id(tenant_id, edge_type, source_node_id, target_node_id)
    existing = db.get(GovernanceGraphEdge, edge_id)
    if existing is not None:
        existing.weight = weight
        existing.confidence = confidence
        existing.properties = properties
        existing.source_ref = source_ref
        existing.snapshot_id = snapshot_id
        existing.derived_at = derived_at
        db.flush()
        return existing
    edge = GovernanceGraphEdge(
        edge_id=edge_id,
        tenant_id=tenant_id,
        edge_type=edge_type,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        weight=weight,
        confidence=confidence,
        properties=properties,
        source_ref=source_ref,
        engagement_id=engagement_id,
        snapshot_id=snapshot_id,
        derived_at=derived_at,
        schema_version="1.0",
    )
    db.add(edge)
    db.flush()
    return edge


def upsert_anomaly(
    db: Session,
    *,
    tenant_id: str,
    pattern_id: str,
    description: str,
    severity: str,
    node_ids: list[str],
    edge_ids: list[str],
    snapshot_id: str,
    detected_at: str,
) -> GovernanceGraphAnomaly:
    """Upsert an anomaly by (tenant_id, pattern_id, snapshot_id)."""
    anomaly_id = hashlib.sha256(
        f"{tenant_id}:{pattern_id}:{snapshot_id}".encode()
    ).hexdigest()
    existing = db.get(GovernanceGraphAnomaly, anomaly_id)
    if existing is not None:
        existing.node_ids = node_ids
        existing.edge_ids = edge_ids
        existing.is_active = True
        db.flush()
        return existing
    a = GovernanceGraphAnomaly(
        anomaly_id=anomaly_id,
        tenant_id=tenant_id,
        pattern_id=pattern_id,
        description=description,
        severity=severity,
        node_ids=node_ids,
        edge_ids=edge_ids,
        snapshot_id=snapshot_id,
        detected_at=detected_at,
        is_active=True,
        schema_version="1.0",
    )
    db.add(a)
    db.flush()
    return a


def delete_stale(db: Session, *, tenant_id: str, older_than: str) -> tuple[int, int]:
    """Delete nodes/edges not touched since older_than. Returns (nodes_deleted, edges_deleted)."""
    r_e = db.execute(
        sa_delete(GovernanceGraphEdge).where(
            GovernanceGraphEdge.tenant_id == tenant_id,
            GovernanceGraphEdge.derived_at < older_than,
        )
    )
    r_n = db.execute(
        sa_delete(GovernanceGraphNode).where(
            GovernanceGraphNode.tenant_id == tenant_id,
            GovernanceGraphNode.derived_at < older_than,
        )
    )
    db.flush()
    return r_n.rowcount, r_e.rowcount


def update_centrality(db: Session, *, tenant_id: str, snapshot_id: str) -> int:
    """Compute degree centrality for all nodes in this snapshot and rank them."""
    nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id,
                GovernanceGraphNode.snapshot_id == snapshot_id,
            )
        )
        .scalars()
        .all()
    )
    for node in nodes:
        out_count = db.execute(
            select(func.count()).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.source_node_id == node.node_id,
            )
        ).scalar_one()
        in_count = db.execute(
            select(func.count()).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.target_node_id == node.node_id,
            )
        ).scalar_one()
        node.degree_centrality = out_count + in_count
    db.flush()
    # Rank by degree_centrality descending
    sorted_nodes = sorted(nodes, key=lambda n: n.degree_centrality, reverse=True)
    for rank, node in enumerate(sorted_nodes, 1):
        node.centrality_rank = rank
    db.flush()
    return len(nodes)
