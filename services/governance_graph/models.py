"""Pure data models for the governance topology graph — no DB access."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    governance_asset = "governance_asset"
    ai_system = "ai_system"
    oauth_application = "oauth_application"
    enterprise_application = "enterprise_application"
    identity = "identity"
    finding = "finding"
    control = "control"
    scan = "scan"
    engagement = "engagement"
    evidence = "evidence"
    vendor = "vendor"
    department = "department"


class EdgeType(str, Enum):
    OWNS = "OWNS"
    GOVERNED_BY = "GOVERNED_BY"
    USES = "USES"
    ACCESSES = "ACCESSES"
    CONNECTED_TO = "CONNECTED_TO"
    GENERATED = "GENERATED"
    DETECTED_BY = "DETECTED_BY"
    IMPACTS = "IMPACTS"
    ATTESTED_BY = "ATTESTED_BY"
    SUPPORTS = "SUPPORTS"
    RELATED_TO = "RELATED_TO"
    PROMOTED_FROM = "PROMOTED_FROM"


class EdgeDirection(str, Enum):
    outbound = "outbound"
    inbound = "inbound"
    both = "both"


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    tenant_id: str
    node_type: str
    entity_id: str
    entity_type: str
    label: str
    properties: dict[str, Any]
    tags: list[str]
    trust_score: int
    degree_centrality: int
    centrality_rank: int | None
    confidence: int
    source_ref: str
    engagement_id: str | None
    snapshot_id: str | None
    derived_at: str


@dataclass(frozen=True)
class GraphEdge:
    edge_id: str
    tenant_id: str
    edge_type: str
    source_node_id: str
    target_node_id: str
    weight: int
    confidence: int
    properties: dict[str, Any]
    source_ref: str
    engagement_id: str | None
    snapshot_id: str | None
    derived_at: str


@dataclass
class GraphTraversalResult:
    root_node_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    max_depth_reached: int
    truncated: bool  # True if 500-node cap hit


@dataclass
class LineageChain:
    origin_node_id: str
    chain: list[tuple[GraphNode, GraphEdge | None]]  # (node, edge_that_led_here)
    depth: int


@dataclass
class GraphBuildResult:
    snapshot_id: str
    snapshot_seq: int
    tenant_id: str
    nodes_upserted: int
    edges_upserted: int
    nodes_deleted: int
    edges_deleted: int
    anomalies_detected: int
    triggered_by: str
    built_at: str
