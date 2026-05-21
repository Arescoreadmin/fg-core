"""Lineage chain reconstruction for the governance topology graph."""

from __future__ import annotations

from collections import deque

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_graph import GovernanceGraphEdge, GovernanceGraphNode
from services.governance_graph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    LineageChain,
)
from services.governance_graph.queries import (
    _orm_edge_to_dataclass,
    _orm_node_to_dataclass,
)

# Edge types that represent provenance / lineage relationships
LINEAGE_EDGE_TYPES: frozenset[EdgeType] = frozenset(
    {
        EdgeType.DETECTED_BY,
        EdgeType.GENERATED,
        EdgeType.SUPPORTS,
        EdgeType.PROMOTED_FROM,
        EdgeType.IMPACTS,
        EdgeType.GOVERNED_BY,
    }
)

_LINEAGE_EDGE_TYPE_VALUES: set[str] = {et.value for et in LINEAGE_EDGE_TYPES}


def reconstruct_lineage(
    db: Session,
    *,
    tenant_id: str,
    node_id: str,
    max_depth: int = 8,
) -> LineageChain:
    """Trace provenance backwards from node_id to origin nodes.

    Traverses inbound edges of lineage types, following the chain upstream.
    Returns LineageChain with chain = [(node, edge_that_led_here), ...].
    The first element has edge=None (the origin node itself).
    """
    root_orm = db.get(GovernanceGraphNode, node_id)
    if root_orm is None or root_orm.tenant_id != tenant_id:
        return LineageChain(
            origin_node_id=node_id,
            chain=[],
            depth=0,
        )

    # BFS backwards following inbound lineage edges
    # Each queue entry: (current_node_id, edge_that_led_here | None, depth)
    visited: set[str] = {node_id}
    chain_map: dict[str, tuple[GraphNode, GraphEdge | None]] = {
        node_id: (_orm_node_to_dataclass(root_orm), None)
    }
    # Track order
    ordered: list[str] = [node_id]

    queue: deque[tuple[str, int]] = deque([(node_id, 0)])
    max_depth_reached = 0

    while queue:
        current_id, depth = queue.popleft()
        if depth >= max_depth:
            continue

        # Get inbound lineage edges
        inbound_edges = (
            db.execute(
                select(GovernanceGraphEdge).where(
                    GovernanceGraphEdge.tenant_id == tenant_id,
                    GovernanceGraphEdge.target_node_id == current_id,
                    GovernanceGraphEdge.edge_type.in_(_LINEAGE_EDGE_TYPE_VALUES),
                )
            )
            .scalars()
            .all()
        )
        for edge_orm in inbound_edges:
            upstream_id = edge_orm.source_node_id
            if upstream_id in visited:
                continue
            upstream_node = db.get(GovernanceGraphNode, upstream_id)
            if upstream_node is None or upstream_node.tenant_id != tenant_id:
                continue
            visited.add(upstream_id)
            edge_dc = _orm_edge_to_dataclass(edge_orm)
            node_dc = _orm_node_to_dataclass(upstream_node)
            chain_map[upstream_id] = (node_dc, edge_dc)
            ordered.append(upstream_id)
            new_depth = depth + 1
            max_depth_reached = max(max_depth_reached, new_depth)
            queue.append((upstream_id, new_depth))

    chain: list[tuple[GraphNode, GraphEdge | None]] = [
        chain_map[nid] for nid in ordered
    ]

    return LineageChain(
        origin_node_id=node_id,
        chain=chain,
        depth=max_depth_reached,
    )
