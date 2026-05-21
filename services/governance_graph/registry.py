"""Edge type registry — valid combinations and validation helpers."""

from __future__ import annotations

from services.governance_graph.models import EdgeType, NodeType

# Maps each edge type to the list of valid (source_node_type, target_node_type) pairs.
VALID_EDGE_COMBINATIONS: dict[EdgeType, list[tuple[NodeType, NodeType]]] = {
    EdgeType.OWNS: [
        (NodeType.identity, NodeType.governance_asset),
        (NodeType.identity, NodeType.ai_system),
        (NodeType.identity, NodeType.oauth_application),
    ],
    EdgeType.GOVERNED_BY: [
        (NodeType.finding, NodeType.governance_asset),
        (NodeType.finding, NodeType.control),
    ],
    EdgeType.USES: [
        (NodeType.governance_asset, NodeType.oauth_application),
        (NodeType.governance_asset, NodeType.ai_system),
        (NodeType.governance_asset, NodeType.enterprise_application),
    ],
    EdgeType.ACCESSES: [
        (NodeType.identity, NodeType.governance_asset),
        (NodeType.identity, NodeType.ai_system),
    ],
    EdgeType.CONNECTED_TO: [
        (NodeType.governance_asset, NodeType.governance_asset),
        (NodeType.ai_system, NodeType.identity),
    ],
    EdgeType.GENERATED: [
        (NodeType.scan, NodeType.finding),
        (NodeType.engagement, NodeType.scan),
    ],
    EdgeType.DETECTED_BY: [
        (NodeType.finding, NodeType.scan),
    ],
    EdgeType.IMPACTS: [
        (NodeType.finding, NodeType.governance_asset),
    ],
    EdgeType.ATTESTED_BY: [
        (NodeType.governance_asset, NodeType.identity),
    ],
    EdgeType.SUPPORTS: [
        (NodeType.engagement, NodeType.scan),
    ],
    EdgeType.RELATED_TO: [
        (NodeType.governance_asset, NodeType.governance_asset),
    ],
    EdgeType.PROMOTED_FROM: [
        (NodeType.governance_asset, NodeType.finding),
    ],
}


def validate_edge(
    edge_type: EdgeType,
    source_node_type: NodeType,
    target_node_type: NodeType,
) -> bool:
    """Return True if (source_node_type, target_node_type) is valid for edge_type."""
    combos = VALID_EDGE_COMBINATIONS.get(edge_type, [])
    return (source_node_type, target_node_type) in combos


def get_valid_targets(
    edge_type: EdgeType,
    source_node_type: NodeType,
) -> list[NodeType]:
    """Return all valid target node types for the given edge_type and source_node_type."""
    combos = VALID_EDGE_COMBINATIONS.get(edge_type, [])
    return [target for src, target in combos if src == source_node_type]
