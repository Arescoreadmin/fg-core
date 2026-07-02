"""Deterministic Evidence Graph and Decision Provenance (PR 18.5A).

Pure functions + ProvenanceGraph class. No DB I/O, constructed from data.
All outputs are deterministic and content-addressed via SHA-256.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Node type constants
# ---------------------------------------------------------------------------

ASSESSMENT = "ASSESSMENT"
FINDING = "FINDING"
EVIDENCE = "EVIDENCE"
VERIFICATION = "VERIFICATION"
CONTROL = "CONTROL"
FRAMEWORK = "FRAMEWORK"
REMEDIATION = "REMEDIATION"
POLICY = "POLICY"
ORCHESTRATION = "ORCHESTRATION"
SIMULATION = "SIMULATION"
BENCHMARK = "BENCHMARK"
FORECAST = "FORECAST"
RECOMMENDATION = "RECOMMENDATION"
EXECUTIVE_INSIGHT = "EXECUTIVE_INSIGHT"
DASHBOARD_WIDGET = "DASHBOARD_WIDGET"
REPORT = "REPORT"
TRUST_RECORD = "TRUST_RECORD"
TRANSPARENCY_ENTRY = "TRANSPARENCY_ENTRY"

ALL_NODE_TYPES: frozenset[str] = frozenset(
    {
        ASSESSMENT,
        FINDING,
        EVIDENCE,
        VERIFICATION,
        CONTROL,
        FRAMEWORK,
        REMEDIATION,
        POLICY,
        ORCHESTRATION,
        SIMULATION,
        BENCHMARK,
        FORECAST,
        RECOMMENDATION,
        EXECUTIVE_INSIGHT,
        DASHBOARD_WIDGET,
        REPORT,
        TRUST_RECORD,
        TRANSPARENCY_ENTRY,
    }
)


# ---------------------------------------------------------------------------
# ProvenanceNode dataclass
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceNode:
    """Single node in the evidence / decision provenance graph."""

    id: str
    node_type: str
    authority: str
    authority_version: str
    source_object_id: str
    sha256_digest: str
    timestamp: str
    parent_ids: list[str] = field(default_factory=list)
    child_ids: list[str] = field(default_factory=list)
    trust_ref: str | None = None
    transparency_ref: str | None = None
    confidence_ref: str | None = None
    simulation_ref: str | None = None
    replay_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type,
            "authority": self.authority,
            "authority_version": self.authority_version,
            "source_object_id": self.source_object_id,
            "sha256_digest": self.sha256_digest,
            "timestamp": self.timestamp,
            "parent_ids": sorted(self.parent_ids),
            "child_ids": sorted(self.child_ids),
            "trust_ref": self.trust_ref,
            "transparency_ref": self.transparency_ref,
            "confidence_ref": self.confidence_ref,
            "simulation_ref": self.simulation_ref,
            "replay_ref": self.replay_ref,
        }


# ---------------------------------------------------------------------------
# ProvenanceGraph class
# ---------------------------------------------------------------------------


class ProvenanceGraph:
    """In-memory directed acyclic graph of ProvenanceNodes.

    Nodes are keyed by their `id`. Edges are tracked via parent_ids /
    child_ids on the nodes themselves.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, ProvenanceNode] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_node(self, node: ProvenanceNode) -> None:
        """Add or replace a node.  Updates parent/child cross-links."""
        self._nodes[node.id] = node
        # Ensure parents know about this child
        for parent_id in node.parent_ids:
            if parent_id in self._nodes:
                parent = self._nodes[parent_id]
                if node.id not in parent.child_ids:
                    parent.child_ids.append(node.id)
        # Ensure children know about this parent
        for child_id in node.child_ids:
            if child_id in self._nodes:
                child = self._nodes[child_id]
                if node.id not in child.parent_ids:
                    child.parent_ids.append(node.id)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_node(self, node_id: str) -> ProvenanceNode | None:
        return self._nodes.get(node_id)

    def get_ancestors(self, node_id: str) -> list[ProvenanceNode]:
        """Return all ancestors (transitively) in breadth-first order."""
        visited: set[str] = set()
        queue: list[str] = [node_id]
        result: list[ProvenanceNode] = []
        while queue:
            current = queue.pop(0)
            node = self._nodes.get(current)
            if node is None:
                continue
            for pid in node.parent_ids:
                if pid not in visited:
                    visited.add(pid)
                    parent = self._nodes.get(pid)
                    if parent is not None:
                        result.append(parent)
                    queue.append(pid)
        return result

    def get_descendants(self, node_id: str) -> list[ProvenanceNode]:
        """Return all descendants (transitively) in breadth-first order."""
        visited: set[str] = set()
        queue: list[str] = [node_id]
        result: list[ProvenanceNode] = []
        while queue:
            current = queue.pop(0)
            node = self._nodes.get(current)
            if node is None:
                continue
            for cid in node.child_ids:
                if cid not in visited:
                    visited.add(cid)
                    child = self._nodes.get(cid)
                    if child is not None:
                        result.append(child)
                    queue.append(cid)
        return result

    def detect_cycles(self) -> list[str]:
        """Detect cycles using DFS with coloring.

        Returns list of node_ids that form the first cycle found, or empty
        list if the graph is acyclic.
        """
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {nid: WHITE for nid in self._nodes}
        cycle_path: list[str] = []

        def dfs(nid: str, path: list[str]) -> bool:
            color[nid] = GRAY
            path.append(nid)
            node = self._nodes.get(nid)
            if node is not None:
                for child_id in node.child_ids:
                    if child_id not in color:
                        continue
                    if color[child_id] == GRAY:
                        # Found cycle — extract cycle portion
                        cycle_start = path.index(child_id)
                        cycle_path.extend(path[cycle_start:])
                        return True
                    if color[child_id] == WHITE:
                        if dfs(child_id, path):
                            return True
            color[nid] = BLACK
            path.pop()
            return False

        for nid in list(self._nodes.keys()):
            if color.get(nid, WHITE) == WHITE:
                if dfs(nid, []):
                    return cycle_path
        return []

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_graph(self) -> dict[str, Any]:
        """Export the graph as a deterministic, sorted dict."""
        nodes_sorted = sorted(self._nodes.values(), key=lambda n: n.id)
        edges: list[dict[str, str]] = []
        for node in nodes_sorted:
            for child_id in sorted(node.child_ids):
                edges.append({"parent_id": node.id, "child_id": child_id})
        edges_sorted = sorted(edges, key=lambda e: (e["parent_id"], e["child_id"]))
        return {
            "nodes": [n.to_dict() for n in nodes_sorted],
            "edges": edges_sorted,
            "node_count": len(self._nodes),
            "cycle_detected": bool(self.detect_cycles()),
        }

    def to_sorted_list(self) -> list[dict[str, Any]]:
        """Return nodes as a sorted list of dicts (by id)."""
        return [n.to_dict() for n in sorted(self._nodes.values(), key=lambda n: n.id)]


# ---------------------------------------------------------------------------
# Pure helper functions
# ---------------------------------------------------------------------------


def compute_node_digest(data: dict[str, Any]) -> str:
    """SHA-256 of deterministically serialised ``data``."""
    serialised = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def build_node(
    node_type: str,
    authority: str,
    source_object_id: str,
    data: dict[str, Any],
    parent_ids: list[str],
    *,
    authority_version: str = "1.0",
    timestamp: str = "",
    trust_ref: str | None = None,
    transparency_ref: str | None = None,
    confidence_ref: str | None = None,
    simulation_ref: str | None = None,
    replay_ref: str | None = None,
) -> ProvenanceNode:
    """Build a ProvenanceNode deterministically from inputs.

    The node `id` is the SHA-256 digest of the canonical payload.
    """
    if not timestamp:
        from services.canonical import utc_iso8601_z_now

        timestamp = utc_iso8601_z_now()

    payload: dict[str, Any] = {
        "node_type": node_type,
        "authority": authority,
        "authority_version": authority_version,
        "source_object_id": source_object_id,
        "data": data,
        "parent_ids": sorted(parent_ids),
        "timestamp": timestamp,
    }
    digest = compute_node_digest(payload)

    return ProvenanceNode(
        id=digest,
        node_type=node_type,
        authority=authority,
        authority_version=authority_version,
        source_object_id=source_object_id,
        sha256_digest=digest,
        timestamp=timestamp,
        parent_ids=list(parent_ids),
        child_ids=[],
        trust_ref=trust_ref,
        transparency_ref=transparency_ref,
        confidence_ref=confidence_ref,
        simulation_ref=simulation_ref,
        replay_ref=replay_ref,
    )
