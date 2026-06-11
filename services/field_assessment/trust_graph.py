"""Trust Graph Foundation — PR 1.6.

FrostGate Trust Graph: universal trust substrate.

Every trust decision traversable. Every trust path explainable.
Every trust relationship replayable.

Graph model (current assessment domain):

  Evidence → Finding → Control → Framework
                    ↓
                   Risk → Report
  Evidence ─────────────────────→ Report

All traversal is deterministic (stable sort on node_id).
All nodes and edges are tenant-scoped and engagement-scoped.
Fail closed: security violations raise TrustGraphError.

Extensibility:
  Future authority types (Identity, RBAC, Agent, AGI Governance) integrate by
  adding NodeType entries and factory functions. The graph engine (TrustGraph,
  verify_trust_graph, traversal, manifest) requires no changes.

Replay compatibility (PR 1.9):
  Every node and edge carries created_at so snapshots can answer
  "What trust path existed at time T?" without redesign.

Performance targets:
  100 nodes   < 50ms traversal
  1000 nodes  < 250ms traversal
  10000 nodes < 1000ms traversal

All traversal is O(V+E) via adjacency lists. No N+1 queries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from services.canonical import utc_iso8601_z_now

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GRAPH_VERSION: str = "trust-graph-v1"
MANIFEST_VERSION: str = "trust-graph-manifest-v1"


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------


class NodeType(str, Enum):
    """Bounded set of trust graph node types.

    Extend here to add future authorities (Identity, RBAC, Agent, etc.).
    The graph engine treats all types uniformly via TrustGraphNode.
    """

    EVIDENCE = "evidence"
    FINDING = "finding"
    CONTROL = "control"
    FRAMEWORK = "framework"
    RISK = "risk"
    REPORT = "report"


# ---------------------------------------------------------------------------
# Edge types
# ---------------------------------------------------------------------------


class EdgeType(str, Enum):
    """Bounded set of directed trust graph edge types.

    Each edge type encodes a semantically meaningful trust relationship.
    """

    EVIDENCE_TO_FINDING = "evidence_to_finding"
    FINDING_TO_CONTROL = "finding_to_control"
    CONTROL_TO_FRAMEWORK = "control_to_framework"
    FINDING_TO_RISK = "finding_to_risk"
    RISK_TO_REPORT = "risk_to_report"
    EVIDENCE_TO_REPORT = "evidence_to_report"


# Valid (source_type, target_type) pairs per edge type — enforced at add_edge time.
_VALID_EDGES: dict[EdgeType, tuple[NodeType, NodeType]] = {
    EdgeType.EVIDENCE_TO_FINDING: (NodeType.EVIDENCE, NodeType.FINDING),
    EdgeType.FINDING_TO_CONTROL: (NodeType.FINDING, NodeType.CONTROL),
    EdgeType.CONTROL_TO_FRAMEWORK: (NodeType.CONTROL, NodeType.FRAMEWORK),
    EdgeType.FINDING_TO_RISK: (NodeType.FINDING, NodeType.RISK),
    EdgeType.RISK_TO_REPORT: (NodeType.RISK, NodeType.REPORT),
    EdgeType.EVIDENCE_TO_REPORT: (NodeType.EVIDENCE, NodeType.REPORT),
}

# Reverse lookup: (source_type, target_type) → allowed EdgeType
_REVERSE_EDGE_MAP: dict[tuple[NodeType, NodeType], set[EdgeType]] = {}
for _et, (_src, _tgt) in _VALID_EDGES.items():
    _REVERSE_EDGE_MAP.setdefault((_src, _tgt), set()).add(_et)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TrustGraphError(ValueError):
    """Raised when a graph operation violates a trust or security invariant.

    Fail closed: callers must handle this explicitly.
    """


# ---------------------------------------------------------------------------
# Core dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustGraphNode:
    """Immutable graph node with typed payload.

    node_id must be globally unique within a graph (scoped by tenant_id +
    engagement_id). The payload carries domain-specific fields; the graph engine
    treats it as opaque. This allows future node types without engine changes.
    """

    node_id: str
    node_type: NodeType
    tenant_id: str
    engagement_id: str
    payload: dict[str, Any]
    created_at: str = field(default_factory=utc_iso8601_z_now)


@dataclass(frozen=True)
class TrustGraphEdge:
    """Immutable directed edge between two graph nodes.

    edge_id must be unique within a graph. Edges are tenant-scoped and
    engagement-scoped; cross-boundary edges are rejected at add_edge time.
    """

    edge_id: str
    edge_type: EdgeType
    source_node_id: str
    target_node_id: str
    tenant_id: str
    engagement_id: str
    created_at: str = field(default_factory=utc_iso8601_z_now)


# ---------------------------------------------------------------------------
# Graph container
# ---------------------------------------------------------------------------


class TrustGraph:
    """In-memory trust graph with adjacency-list traversal.

    Thread safety: not thread-safe. Build graphs within a single request/task
    scope. For concurrent reads, build once then share the frozen state.

    Security invariants enforced at mutation time:
      - No cross-tenant node linkage
      - No cross-engagement node linkage
      - No duplicate node IDs
      - No duplicate edges (same source, target, edge_type)
      - Edge type must match source/target node types
    """

    def __init__(self, tenant_id: str, engagement_id: str) -> None:
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id
        self._nodes: dict[str, TrustGraphNode] = {}
        self._edges: list[TrustGraphEdge] = []
        self._adj_out: dict[str, list[TrustGraphEdge]] = {}
        self._adj_in: dict[str, list[TrustGraphEdge]] = {}
        self._edge_keys: set[tuple[str, str, EdgeType]] = set()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_node(self, node: TrustGraphNode) -> None:
        """Add a node. Rejects cross-tenant, cross-engagement, or duplicate IDs."""
        if node.tenant_id != self.tenant_id:
            raise TrustGraphError(
                f"cross-tenant node rejected: node.tenant_id={node.tenant_id!r} "
                f"graph.tenant_id={self.tenant_id!r}"
            )
        if node.engagement_id != self.engagement_id:
            raise TrustGraphError(
                f"cross-engagement node rejected: node.engagement_id={node.engagement_id!r} "
                f"graph.engagement_id={self.engagement_id!r}"
            )
        if node.node_id in self._nodes:
            raise TrustGraphError(f"duplicate node_id: {node.node_id!r}")
        self._nodes[node.node_id] = node
        self._adj_out.setdefault(node.node_id, [])
        self._adj_in.setdefault(node.node_id, [])

    def add_edge(self, edge: TrustGraphEdge) -> None:
        """Add a directed edge. Enforces all security invariants."""
        if edge.tenant_id != self.tenant_id:
            raise TrustGraphError(
                f"cross-tenant edge rejected: edge.tenant_id={edge.tenant_id!r}"
            )
        if edge.engagement_id != self.engagement_id:
            raise TrustGraphError(
                f"cross-engagement edge rejected: edge.engagement_id={edge.engagement_id!r}"
            )

        src = self._nodes.get(edge.source_node_id)
        tgt = self._nodes.get(edge.target_node_id)
        if src is None:
            raise TrustGraphError(f"source node not found: {edge.source_node_id!r}")
        if tgt is None:
            raise TrustGraphError(f"target node not found: {edge.target_node_id!r}")

        # Type check: edge_type must be valid for (src_type, tgt_type)
        expected = _VALID_EDGES.get(edge.edge_type)
        if expected is None or (src.node_type, tgt.node_type) != expected:
            raise TrustGraphError(
                f"invalid edge type {edge.edge_type!r} for "
                f"({src.node_type!r} → {tgt.node_type!r})"
            )

        # Cross-tenant node pairing guard
        if src.tenant_id != tgt.tenant_id:
            raise TrustGraphError(
                f"cross-tenant edge: src.tenant_id={src.tenant_id!r} "
                f"tgt.tenant_id={tgt.tenant_id!r}"
            )
        if src.engagement_id != tgt.engagement_id:
            raise TrustGraphError(
                f"cross-engagement edge: src.engagement_id={src.engagement_id!r} "
                f"tgt.engagement_id={tgt.engagement_id!r}"
            )

        # Duplicate edge guard
        edge_key = (edge.source_node_id, edge.target_node_id, edge.edge_type)
        if edge_key in self._edge_keys:
            raise TrustGraphError(
                f"duplicate edge: {edge.source_node_id!r} → {edge.target_node_id!r} "
                f"type={edge.edge_type!r}"
            )

        self._edge_keys.add(edge_key)
        self._edges.append(edge)
        self._adj_out[edge.source_node_id].append(edge)
        self._adj_in[edge.target_node_id].append(edge)

    # ------------------------------------------------------------------
    # Read access
    # ------------------------------------------------------------------

    def get_node(self, node_id: str) -> TrustGraphNode | None:
        return self._nodes.get(node_id)

    def nodes(self) -> list[TrustGraphNode]:
        """All nodes, sorted by node_id for determinism."""
        return sorted(self._nodes.values(), key=lambda n: n.node_id)

    def edges(self) -> list[TrustGraphEdge]:
        """All edges, sorted by (source, target, edge_type) for determinism."""
        return sorted(
            self._edges, key=lambda e: (e.source_node_id, e.target_node_id, e.edge_type)
        )

    def nodes_by_type(self, node_type: NodeType) -> list[TrustGraphNode]:
        return sorted(
            (n for n in self._nodes.values() if n.node_type == node_type),
            key=lambda n: n.node_id,
        )

    def edges_from(self, node_id: str) -> list[TrustGraphEdge]:
        """Outgoing edges from node_id, sorted for determinism."""
        return sorted(
            self._adj_out.get(node_id, []),
            key=lambda e: (e.target_node_id, e.edge_type),
        )

    def edges_to(self, node_id: str) -> list[TrustGraphEdge]:
        """Incoming edges to node_id, sorted for determinism."""
        return sorted(
            self._adj_in.get(node_id, []),
            key=lambda e: (e.source_node_id, e.edge_type),
        )

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)


# ---------------------------------------------------------------------------
# Node factory functions
# ---------------------------------------------------------------------------


def build_evidence_node(
    *,
    node_id: str,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str,
    event_hash: str,
    authority_status: str = "unknown",
    trust_score: int = 0,
    created_at: str | None = None,
) -> TrustGraphNode:
    """Build an Evidence node from FaEvidenceProvenance fields."""
    return TrustGraphNode(
        node_id=node_id,
        node_type=NodeType.EVIDENCE,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload={
            "evidence_id": evidence_id,
            "event_hash": event_hash,
            "authority_status": authority_status,
            "trust_score": trust_score,
        },
        created_at=created_at or utc_iso8601_z_now(),
    )


def build_finding_node(
    *,
    node_id: str,
    tenant_id: str,
    engagement_id: str,
    finding_id: str,
    severity: str,
    confidence: str = "medium",
    status: str = "open",
    created_at: str | None = None,
) -> TrustGraphNode:
    return TrustGraphNode(
        node_id=node_id,
        node_type=NodeType.FINDING,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload={
            "finding_id": finding_id,
            "severity": severity,
            "confidence": confidence,
            "status": status,
        },
        created_at=created_at or utc_iso8601_z_now(),
    )


def build_control_node(
    *,
    node_id: str,
    tenant_id: str,
    engagement_id: str,
    control_id: str,
    framework: str,
    control_status: str = "not_evaluated",
    created_at: str | None = None,
) -> TrustGraphNode:
    return TrustGraphNode(
        node_id=node_id,
        node_type=NodeType.CONTROL,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload={
            "control_id": control_id,
            "framework": framework,
            "control_status": control_status,
        },
        created_at=created_at or utc_iso8601_z_now(),
    )


def build_framework_node(
    *,
    node_id: str,
    tenant_id: str,
    engagement_id: str,
    framework_id: str,
    framework_name: str,
    version: str = "1.0",
    created_at: str | None = None,
) -> TrustGraphNode:
    return TrustGraphNode(
        node_id=node_id,
        node_type=NodeType.FRAMEWORK,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload={
            "framework_id": framework_id,
            "framework_name": framework_name,
            "version": version,
        },
        created_at=created_at or utc_iso8601_z_now(),
    )


def build_risk_node(
    *,
    node_id: str,
    tenant_id: str,
    engagement_id: str,
    risk_id: str,
    risk_level: str,
    risk_type: str,
    created_at: str | None = None,
) -> TrustGraphNode:
    return TrustGraphNode(
        node_id=node_id,
        node_type=NodeType.RISK,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload={
            "risk_id": risk_id,
            "risk_level": risk_level,
            "risk_type": risk_type,
        },
        created_at=created_at or utc_iso8601_z_now(),
    )


def build_report_node(
    *,
    node_id: str,
    tenant_id: str,
    engagement_id: str,
    report_id: str,
    report_hash: str = "",
    report_signature: str = "",
    report_status: str = "draft",
    created_at: str | None = None,
) -> TrustGraphNode:
    return TrustGraphNode(
        node_id=node_id,
        node_type=NodeType.REPORT,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload={
            "report_id": report_id,
            "report_hash": report_hash,
            "report_signature": report_signature,
            "report_status": report_status,
        },
        created_at=created_at or utc_iso8601_z_now(),
    )


# ---------------------------------------------------------------------------
# Graph integrity engine
# ---------------------------------------------------------------------------


def verify_trust_graph(graph: TrustGraph) -> dict[str, Any]:
    """Verify all structural and security invariants of a trust graph.

    Runs in O(V+E). Fail closed: returns graph_valid=False and a violations
    list on any integrity failure. Never raises; never silently corrects.

    Returns:
        {
            "graph_valid": bool,
            "violations": list[str],
            "node_count": int,
            "edge_count": int,
        }
    """
    violations: list[str] = []
    nodes = graph.nodes()
    edges = graph.edges()
    node_ids = {n.node_id for n in nodes}

    # --- Missing node endpoints ---
    for e in edges:
        if e.source_node_id not in node_ids:
            violations.append(
                f"missing_node: edge {e.edge_id!r} source {e.source_node_id!r} not in graph"
            )
        if e.target_node_id not in node_ids:
            violations.append(
                f"missing_node: edge {e.edge_id!r} target {e.target_node_id!r} not in graph"
            )

    # --- Cross-tenant / cross-engagement edges ---
    for e in edges:
        src = graph.get_node(e.source_node_id)
        tgt = graph.get_node(e.target_node_id)
        if src and tgt:
            if src.tenant_id != tgt.tenant_id:
                violations.append(
                    f"cross_tenant_edge: {e.edge_id!r} "
                    f"src={src.tenant_id!r} tgt={tgt.tenant_id!r}"
                )
            if src.engagement_id != tgt.engagement_id:
                violations.append(
                    f"cross_engagement_edge: {e.edge_id!r} "
                    f"src={src.engagement_id!r} tgt={tgt.engagement_id!r}"
                )

    # --- Invalid edge types ---
    for e in edges:
        src = graph.get_node(e.source_node_id)
        tgt = graph.get_node(e.target_node_id)
        if src and tgt:
            expected = _VALID_EDGES.get(e.edge_type)
            if expected is None or (src.node_type, tgt.node_type) != expected:
                violations.append(
                    f"invalid_edge: {e.edge_id!r} type={e.edge_type!r} "
                    f"({src.node_type!r}→{tgt.node_type!r})"
                )

    # --- Duplicate edges ---
    seen_keys: set[tuple[str, str, EdgeType]] = set()
    for e in edges:
        k = (e.source_node_id, e.target_node_id, e.edge_type)
        if k in seen_keys:
            violations.append(
                f"duplicate_edge: {e.source_node_id!r}→{e.target_node_id!r} "
                f"type={e.edge_type!r}"
            )
        seen_keys.add(k)

    # --- Orphaned nodes (non-evidence nodes with no edges at all) ---
    connected: set[str] = set()
    for e in edges:
        connected.add(e.source_node_id)
        connected.add(e.target_node_id)
    for n in nodes:
        if n.node_type != NodeType.EVIDENCE and n.node_id not in connected:
            violations.append(f"orphaned_node: {n.node_id!r} type={n.node_type!r}")

    # --- Cycle detection (DFS coloring) ---
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {n.node_id: WHITE for n in nodes}

    def _dfs_has_cycle(start: str) -> bool:
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            nid, leaving = stack.pop()
            if leaving:
                color[nid] = BLACK
                continue
            if color[nid] == GRAY:
                return True
            if color[nid] == BLACK:
                continue
            color[nid] = GRAY
            stack.append((nid, True))
            for e in graph.edges_from(nid):
                if color[e.target_node_id] == GRAY:
                    return True
                if color[e.target_node_id] == WHITE:
                    stack.append((e.target_node_id, False))
        return False

    for n in nodes:
        if color[n.node_id] == WHITE:
            if _dfs_has_cycle(n.node_id):
                violations.append(
                    f"cyclic_authority_path: cycle detected from {n.node_id!r}"
                )

    # --- Replay mismatch: evidence nodes must have non-empty event_hash ---
    for n in nodes:
        if n.node_type == NodeType.EVIDENCE:
            eh = n.payload.get("event_hash", "")
            if not eh:
                violations.append(
                    f"replay_mismatch: evidence node {n.node_id!r} has empty event_hash"
                )

    return {
        "graph_valid": len(violations) == 0,
        "violations": violations,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


# ---------------------------------------------------------------------------
# Traversal helpers
# ---------------------------------------------------------------------------


def _upstream_bfs(graph: TrustGraph, start_id: str) -> list[TrustGraphNode]:
    """BFS backward (incoming edges) from start_id. Returns nodes in stable order."""
    visited: set[str] = {start_id}
    queue: list[str] = [start_id]
    result: list[TrustGraphNode] = []
    while queue:
        nid = queue.pop(0)
        node = graph.get_node(nid)
        if node:
            result.append(node)
        for e in graph.edges_to(nid):
            if e.source_node_id not in visited:
                visited.add(e.source_node_id)
                queue.append(e.source_node_id)
    return sorted(result, key=lambda n: n.node_id)


def _downstream_bfs(graph: TrustGraph, start_id: str) -> list[TrustGraphNode]:
    """BFS forward (outgoing edges) from start_id. Returns nodes in stable order."""
    visited: set[str] = {start_id}
    queue: list[str] = [start_id]
    result: list[TrustGraphNode] = []
    while queue:
        nid = queue.pop(0)
        node = graph.get_node(nid)
        if node:
            result.append(node)
        for e in graph.edges_from(nid):
            if e.target_node_id not in visited:
                visited.add(e.target_node_id)
                queue.append(e.target_node_id)
    return sorted(result, key=lambda n: n.node_id)


# ---------------------------------------------------------------------------
# Lineage functions
# ---------------------------------------------------------------------------


def get_evidence_lineage(graph: TrustGraph, node_id: str) -> list[TrustGraphNode]:
    """All nodes reachable downstream from an evidence node (forward traversal).

    Returns the evidence node and every downstream node it supports,
    sorted by node_id.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.EVIDENCE:
        raise TrustGraphError(f"evidence node not found or wrong type: {node_id!r}")
    return _downstream_bfs(graph, node_id)


def get_finding_lineage(graph: TrustGraph, node_id: str) -> list[TrustGraphNode]:
    """All nodes reachable upstream from a finding node (backward to evidence).

    Returns the finding node and all upstream evidence nodes that support it,
    sorted by node_id.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.FINDING:
        raise TrustGraphError(f"finding node not found or wrong type: {node_id!r}")
    return _upstream_bfs(graph, node_id)


def get_control_lineage(graph: TrustGraph, node_id: str) -> list[TrustGraphNode]:
    """All nodes reachable upstream from a control node.

    Traverses: Control ← Finding ← Evidence
    Returns sorted by node_id.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.CONTROL:
        raise TrustGraphError(f"control node not found or wrong type: {node_id!r}")
    return _upstream_bfs(graph, node_id)


def get_risk_lineage(graph: TrustGraph, node_id: str) -> list[TrustGraphNode]:
    """All nodes reachable upstream from a risk node.

    Traverses: Risk ← Finding ← Evidence
    Returns sorted by node_id.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.RISK:
        raise TrustGraphError(f"risk node not found or wrong type: {node_id!r}")
    return _upstream_bfs(graph, node_id)


def get_report_lineage(graph: TrustGraph, node_id: str) -> list[TrustGraphNode]:
    """All nodes reachable upstream from a report node.

    Traverses: Report ← Risk ← Finding ← Evidence
               Report ← Evidence (direct links)
    Returns sorted by node_id.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.REPORT:
        raise TrustGraphError(f"report node not found or wrong type: {node_id!r}")
    return _upstream_bfs(graph, node_id)


# ---------------------------------------------------------------------------
# Trust path generation
# ---------------------------------------------------------------------------


def generate_trust_path(
    graph: TrustGraph,
    start_node_id: str,
    end_node_id: str,
) -> list[TrustGraphNode]:
    """Find a deterministic path from start_node_id to end_node_id.

    Uses BFS forward (following outgoing edges). If start can reach end,
    returns the shortest path as a list of nodes [start, ..., end].
    Returns an empty list if no path exists.

    Output is deterministic: when multiple shortest paths exist, the one
    with lexicographically smallest node_id sequence is returned.
    """
    if graph.get_node(start_node_id) is None:
        raise TrustGraphError(f"start node not found: {start_node_id!r}")
    if graph.get_node(end_node_id) is None:
        raise TrustGraphError(f"end node not found: {end_node_id!r}")

    if start_node_id == end_node_id:
        node = graph.get_node(start_node_id)
        return [node] if node else []

    # BFS with path tracking; sort neighbors for determinism
    parent: dict[str, str | None] = {start_node_id: None}
    queue: list[str] = [start_node_id]
    found = False

    while queue and not found:
        nid = queue.pop(0)
        neighbors = sorted(
            (e.target_node_id for e in graph.edges_from(nid)),
            key=lambda x: x,
        )
        for neighbor in neighbors:
            if neighbor not in parent:
                parent[neighbor] = nid
                if neighbor == end_node_id:
                    found = True
                    break
                queue.append(neighbor)

    if not found:
        return []

    # Reconstruct path
    path_ids: list[str] = []
    cur: str | None = end_node_id
    while cur is not None:
        path_ids.append(cur)
        cur = parent.get(cur)
    path_ids.reverse()

    return [graph.get_node(nid) for nid in path_ids if graph.get_node(nid) is not None]  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Graph manifest
# ---------------------------------------------------------------------------


def _canonical_graph_bytes(graph: TrustGraph) -> bytes:
    """Deterministic canonical serialization of graph structure for hashing.

    Nodes and edges are sorted by their IDs. No runtime-dependent ordering.
    Only structural fields are hashed (not created_at timestamps).
    """
    canonical: dict[str, Any] = {
        "tenant_id": graph.tenant_id,
        "engagement_id": graph.engagement_id,
        "graph_version": GRAPH_VERSION,
        "nodes": [
            {
                "node_id": n.node_id,
                "node_type": n.node_type.value,
                "payload": n.payload,
            }
            for n in graph.nodes()
        ],
        "edges": [
            {
                "edge_id": e.edge_id,
                "edge_type": e.edge_type.value,
                "source_node_id": e.source_node_id,
                "target_node_id": e.target_node_id,
            }
            for e in graph.edges()
        ],
    }
    return json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def generate_trust_graph_manifest(graph: TrustGraph) -> dict[str, Any]:
    """Generate a signed, hashable manifest for the trust graph.

    The graph_hash is SHA-256 over the canonical graph structure.
    No nondeterminism: sorted nodes and edges, no timestamps in hash.

    Returns:
        {
            "manifest_version": str,
            "graph_version": str,
            "tenant_id": str,
            "engagement_id": str,
            "node_count": int,
            "edge_count": int,
            "root_nodes": list[str],   # node_ids with no incoming edges
            "graph_hash": str,         # SHA-256 hex
            "generated_at": str,       # ISO-8601 UTC
        }
    """
    nodes = graph.nodes()
    edges = graph.edges()

    # Root nodes: no incoming edges (sorted for determinism)
    has_incoming: set[str] = {e.target_node_id for e in edges}
    root_nodes = sorted(n.node_id for n in nodes if n.node_id not in has_incoming)

    graph_hash = hashlib.sha256(_canonical_graph_bytes(graph)).hexdigest()

    return {
        "manifest_version": MANIFEST_VERSION,
        "graph_version": GRAPH_VERSION,
        "tenant_id": graph.tenant_id,
        "engagement_id": graph.engagement_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "root_nodes": root_nodes,
        "graph_hash": graph_hash,
        "generated_at": utc_iso8601_z_now(),
    }
