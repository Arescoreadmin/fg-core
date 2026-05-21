"""Read-only query helpers for the governance topology graph."""

from __future__ import annotations

from collections import deque
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models_governance_graph import (
    GovernanceGraphAnomaly,
    GovernanceGraphEdge,
    GovernanceGraphNode,
    GovernanceGraphSnapshot,
)
from services.governance_graph.models import GraphEdge, GraphNode, GraphTraversalResult

MAX_TRAVERSE_DEPTH = 10
MAX_TRAVERSE_NODES = 500

FRAMEWORK_CONTROLS: dict[str, list[str]] = {
    "NIST-AI-RMF": [
        "GOVERN-1.1", "GOVERN-1.2", "GOVERN-1.3", "GOVERN-2.1", "GOVERN-2.2",
        "GOVERN-3.1", "GOVERN-4.1", "GOVERN-5.1", "GOVERN-5.2", "GOVERN-6.1",
        "MAP-1.1", "MAP-1.5", "MAP-2.1", "MAP-2.2", "MAP-2.3", "MAP-3.1",
        "MAP-3.5", "MAP-4.1", "MAP-5.1",
        "MEASURE-1.1", "MEASURE-2.1", "MEASURE-2.2", "MEASURE-2.3",
        "MEASURE-2.5", "MEASURE-2.6", "MEASURE-2.9", "MEASURE-3.1", "MEASURE-4.1",
        "MANAGE-1.1", "MANAGE-1.3", "MANAGE-2.2", "MANAGE-2.4",
        "MANAGE-3.1", "MANAGE-4.1",
    ],
}


def _orm_node_to_dataclass(n: GovernanceGraphNode) -> GraphNode:
    return GraphNode(
        node_id=n.node_id,
        tenant_id=n.tenant_id,
        node_type=n.node_type,
        entity_id=n.entity_id,
        entity_type=n.entity_type,
        label=n.label,
        properties=n.properties or {},
        tags=n.tags or [],
        trust_score=n.trust_score,
        degree_centrality=n.degree_centrality,
        centrality_rank=n.centrality_rank,
        confidence=n.confidence,
        source_ref=n.source_ref,
        engagement_id=n.engagement_id,
        snapshot_id=n.snapshot_id,
        derived_at=n.derived_at,
    )


def _orm_edge_to_dataclass(e: GovernanceGraphEdge) -> GraphEdge:
    return GraphEdge(
        edge_id=e.edge_id,
        tenant_id=e.tenant_id,
        edge_type=e.edge_type,
        source_node_id=e.source_node_id,
        target_node_id=e.target_node_id,
        weight=e.weight,
        confidence=e.confidence,
        properties=e.properties or {},
        source_ref=e.source_ref,
        engagement_id=e.engagement_id,
        snapshot_id=e.snapshot_id,
        derived_at=e.derived_at,
    )


def get_node(
    db: Session, *, tenant_id: str, node_id: str
) -> GovernanceGraphNode | None:
    """Return a single node by node_id scoped to tenant."""
    node = db.get(GovernanceGraphNode, node_id)
    if node is None or node.tenant_id != tenant_id:
        return None
    return node


def list_nodes(
    db: Session,
    *,
    tenant_id: str,
    node_type: str | None = None,
    tags: list[str] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[GovernanceGraphNode]:
    """List nodes with optional node_type filter."""
    q = select(GovernanceGraphNode).where(GovernanceGraphNode.tenant_id == tenant_id)
    if node_type is not None:
        q = q.where(GovernanceGraphNode.node_type == node_type)
    q = q.offset(offset).limit(limit)
    return list(db.execute(q).scalars().all())


def get_neighbors(
    db: Session,
    *,
    tenant_id: str,
    node_id: str,
    edge_types: list[str] | None = None,
    direction: str = "both",
    limit: int = 50,
) -> list[GovernanceGraphNode]:
    """Return neighbor nodes reachable in one hop."""
    neighbor_ids: set[str] = set()

    def _query_edges(
        src_col: Any, tgt_col: Any, neighbor_col: Any
    ) -> list[str]:
        q = select(neighbor_col).where(
            GovernanceGraphEdge.tenant_id == tenant_id,
            src_col == node_id,
        )
        if edge_types:
            q = q.where(GovernanceGraphEdge.edge_type.in_(edge_types))
        return list(db.execute(q).scalars().all())

    if direction in ("outbound", "both"):
        ids = _query_edges(
            GovernanceGraphEdge.source_node_id,
            GovernanceGraphEdge.target_node_id,
            GovernanceGraphEdge.target_node_id,
        )
        neighbor_ids.update(ids)
    if direction in ("inbound", "both"):
        ids = _query_edges(
            GovernanceGraphEdge.target_node_id,
            GovernanceGraphEdge.source_node_id,
            GovernanceGraphEdge.source_node_id,
        )
        neighbor_ids.update(ids)

    if not neighbor_ids:
        return []

    neighbor_ids_list = list(neighbor_ids)[:limit]
    nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id,
                GovernanceGraphNode.node_id.in_(neighbor_ids_list),
            )
        )
        .scalars()
        .all()
    )
    return list(nodes)


def traverse(
    db: Session,
    *,
    tenant_id: str,
    root_node_id: str,
    max_depth: int = 5,
    edge_types: list[str] | None = None,
    direction: str = "outbound",
) -> GraphTraversalResult:
    """BFS from root_node_id. Hard caps: max_depth=10, max_nodes=500."""
    max_depth = min(max_depth, MAX_TRAVERSE_DEPTH)

    visited_nodes: dict[str, GraphNode] = {}
    visited_edges: dict[str, GraphEdge] = {}
    truncated = False
    max_depth_reached = 0

    root_orm = get_node(db, tenant_id=tenant_id, node_id=root_node_id)
    if root_orm is None:
        return GraphTraversalResult(
            root_node_id=root_node_id,
            nodes=[],
            edges=[],
            max_depth_reached=0,
            truncated=False,
        )

    visited_nodes[root_node_id] = _orm_node_to_dataclass(root_orm)
    queue: deque[tuple[str, int]] = deque([(root_node_id, 0)])

    while queue:
        current_node_id, depth = queue.popleft()
        if depth >= max_depth:
            continue

        # Get edges from this node
        if direction in ("outbound", "both"):
            out_edges_q = select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.source_node_id == current_node_id,
            )
            if edge_types:
                out_edges_q = out_edges_q.where(
                    GovernanceGraphEdge.edge_type.in_(edge_types)
                )
            for edge_orm in db.execute(out_edges_q).scalars().all():
                if len(visited_nodes) >= MAX_TRAVERSE_NODES:
                    truncated = True
                    break
                neighbor_id = edge_orm.target_node_id
                visited_edges[edge_orm.edge_id] = _orm_edge_to_dataclass(edge_orm)
                if neighbor_id not in visited_nodes:
                    neighbor = db.get(GovernanceGraphNode, neighbor_id)
                    if neighbor and neighbor.tenant_id == tenant_id:
                        visited_nodes[neighbor_id] = _orm_node_to_dataclass(neighbor)
                        new_depth = depth + 1
                        max_depth_reached = max(max_depth_reached, new_depth)
                        queue.append((neighbor_id, new_depth))

        if direction in ("inbound", "both"):
            in_edges_q = select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.target_node_id == current_node_id,
            )
            if edge_types:
                in_edges_q = in_edges_q.where(
                    GovernanceGraphEdge.edge_type.in_(edge_types)
                )
            for edge_orm in db.execute(in_edges_q).scalars().all():
                if len(visited_nodes) >= MAX_TRAVERSE_NODES:
                    truncated = True
                    break
                neighbor_id = edge_orm.source_node_id
                visited_edges[edge_orm.edge_id] = _orm_edge_to_dataclass(edge_orm)
                if neighbor_id not in visited_nodes:
                    neighbor = db.get(GovernanceGraphNode, neighbor_id)
                    if neighbor and neighbor.tenant_id == tenant_id:
                        visited_nodes[neighbor_id] = _orm_node_to_dataclass(neighbor)
                        new_depth = depth + 1
                        max_depth_reached = max(max_depth_reached, new_depth)
                        queue.append((neighbor_id, new_depth))

        if truncated:
            break

    return GraphTraversalResult(
        root_node_id=root_node_id,
        nodes=list(visited_nodes.values()),
        edges=list(visited_edges.values()),
        max_depth_reached=max_depth_reached,
        truncated=truncated,
    )


def find_path(
    db: Session,
    *,
    tenant_id: str,
    source_node_id: str,
    target_node_id: str,
    max_depth: int = 8,
) -> list[GovernanceGraphNode] | None:
    """BFS shortest path. Returns None if unreachable within max_depth."""
    if source_node_id == target_node_id:
        node = get_node(db, tenant_id=tenant_id, node_id=source_node_id)
        return [node] if node else None

    visited: set[str] = {source_node_id}
    # Each entry: (node_id, path_so_far)
    queue: deque[tuple[str, list[str]]] = deque([(source_node_id, [source_node_id])])

    while queue:
        current_id, path = queue.popleft()
        if len(path) > max_depth:
            continue

        # Get outbound edges
        edges = (
            db.execute(
                select(GovernanceGraphEdge).where(
                    GovernanceGraphEdge.tenant_id == tenant_id,
                    GovernanceGraphEdge.source_node_id == current_id,
                )
            )
            .scalars()
            .all()
        )
        for edge in edges:
            nid = edge.target_node_id
            if nid == target_node_id:
                full_path = path + [nid]
                result_nodes: list[GovernanceGraphNode] = []
                for pid in full_path:
                    n = db.get(GovernanceGraphNode, pid)
                    if n and n.tenant_id == tenant_id:
                        result_nodes.append(n)
                return result_nodes
            if nid not in visited:
                visited.add(nid)
                queue.append((nid, path + [nid]))

    return None


def get_graph_stats(db: Session, *, tenant_id: str) -> dict[str, Any]:
    """Returns node/edge counts by type, top centrality nodes, trust distribution, last snapshot info."""
    node_count: int = db.execute(
        select(func.count()).where(GovernanceGraphNode.tenant_id == tenant_id)
    ).scalar_one()

    edge_count: int = db.execute(
        select(func.count()).where(GovernanceGraphEdge.tenant_id == tenant_id)
    ).scalar_one()

    # Count by node_type
    by_node_type: dict[str, int] = {}
    for node_type, cnt in db.execute(
        select(GovernanceGraphNode.node_type, func.count())
        .where(GovernanceGraphNode.tenant_id == tenant_id)
        .group_by(GovernanceGraphNode.node_type)
    ).all():
        by_node_type[node_type] = cnt

    # Count by edge_type
    by_edge_type: dict[str, int] = {}
    for edge_type, cnt in db.execute(
        select(GovernanceGraphEdge.edge_type, func.count())
        .where(GovernanceGraphEdge.tenant_id == tenant_id)
        .group_by(GovernanceGraphEdge.edge_type)
    ).all():
        by_edge_type[edge_type] = cnt

    # Top 5 centrality nodes
    top_nodes = (
        db.execute(
            select(GovernanceGraphNode)
            .where(GovernanceGraphNode.tenant_id == tenant_id)
            .order_by(GovernanceGraphNode.degree_centrality.desc())
            .limit(5)
        )
        .scalars()
        .all()
    )
    top_centrality_nodes = [
        {
            "node_id": n.node_id,
            "label": n.label,
            "node_type": n.node_type,
            "degree_centrality": n.degree_centrality,
        }
        for n in top_nodes
    ]

    # Orphaned nodes (trust_score == 0)
    orphaned_nodes: int = db.execute(
        select(func.count()).where(
            GovernanceGraphNode.tenant_id == tenant_id,
            GovernanceGraphNode.trust_score == 0,
        )
    ).scalar_one()

    # Trust score distribution
    trust_100: int = db.execute(
        select(func.count()).where(
            GovernanceGraphNode.tenant_id == tenant_id,
            GovernanceGraphNode.trust_score == 100,
        )
    ).scalar_one()
    trust_score_distribution = {"100": trust_100, "0": orphaned_nodes}

    # Last snapshot
    last_snap_orm = (
        db.execute(
            select(GovernanceGraphSnapshot)
            .where(GovernanceGraphSnapshot.tenant_id == tenant_id)
            .order_by(GovernanceGraphSnapshot.snapshot_seq.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    last_snapshot: dict | None = None
    if last_snap_orm is not None:
        last_snapshot = {
            "snapshot_id": last_snap_orm.snapshot_id,
            "snapshot_seq": last_snap_orm.snapshot_seq,
            "built_at": last_snap_orm.built_at,
            "triggered_by": last_snap_orm.triggered_by,
            "nodes_upserted": last_snap_orm.nodes_upserted,
            "edges_upserted": last_snap_orm.edges_upserted,
            "anomalies_detected": last_snap_orm.anomalies_detected,
        }

    # Anomaly count
    anomaly_count: int = db.execute(
        select(func.count()).where(
            GovernanceGraphAnomaly.tenant_id == tenant_id,
            GovernanceGraphAnomaly.is_active == True,  # noqa: E712
        )
    ).scalar_one()

    return {
        "node_count": node_count,
        "edge_count": edge_count,
        "by_node_type": by_node_type,
        "by_edge_type": by_edge_type,
        "top_centrality_nodes": top_centrality_nodes,
        "orphaned_nodes": orphaned_nodes,
        "trust_score_distribution": trust_score_distribution,
        "last_snapshot": last_snapshot,
        "anomaly_count": anomaly_count,
    }


def get_coverage(
    db: Session, *, tenant_id: str, framework: str = "NIST-AI-RMF"
) -> dict[str, Any]:
    """Query control nodes and compute coverage vs known framework control list."""
    known_controls = FRAMEWORK_CONTROLS.get(framework, [])
    if not known_controls:
        return {
            "framework": framework,
            "total_controls": 0,
            "covered_controls": 0,
            "coverage_pct": 0.0,
            "missing": [],
            "covered": [],
        }

    # Query all control nodes for tenant
    control_nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id,
                GovernanceGraphNode.node_type == "control",
            )
        )
        .scalars()
        .all()
    )

    # Normalize entity_ids: strip framework prefix (e.g. "NIST-AI-RMF-GOVERN-1.2" → "GOVERN-1.2")
    prefix = framework + "-"
    covered_refs: set[str] = set()
    for node in control_nodes:
        eid = node.entity_id
        if eid.startswith(prefix):
            eid = eid[len(prefix):]
        covered_refs.add(eid)

    covered = [c for c in known_controls if c in covered_refs]
    missing = [c for c in known_controls if c not in covered_refs]
    coverage_pct = (len(covered) / len(known_controls) * 100) if known_controls else 0.0

    return {
        "framework": framework,
        "total_controls": len(known_controls),
        "covered_controls": len(covered),
        "coverage_pct": round(coverage_pct, 1),
        "missing": missing,
        "covered": covered,
    }


def list_anomalies(
    db: Session,
    *,
    tenant_id: str,
    active_only: bool = True,
    severity: str | None = None,
    limit: int = 50,
) -> list[GovernanceGraphAnomaly]:
    """List anomalies with optional filters."""
    q = select(GovernanceGraphAnomaly).where(
        GovernanceGraphAnomaly.tenant_id == tenant_id
    )
    if active_only:
        q = q.where(GovernanceGraphAnomaly.is_active == True)  # noqa: E712
    if severity is not None:
        q = q.where(GovernanceGraphAnomaly.severity == severity)
    q = q.order_by(GovernanceGraphAnomaly.detected_at.desc()).limit(limit)
    return list(db.execute(q).scalars().all())
