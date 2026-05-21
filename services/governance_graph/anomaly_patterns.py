"""Structural anomaly detectors for the governance topology graph.

Each detector function takes (db, tenant_id, snapshot_id, now) and returns a list
of anomaly dicts with keys: pattern_id, description, severity, node_ids, edge_ids.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_graph import GovernanceGraphEdge, GovernanceGraphNode

log = logging.getLogger("frostgate.governance_graph.anomaly_patterns")


def _detect_ungoverned_high_centrality(
    db: Session, tenant_id: str, snapshot_id: str, now: str
) -> list[dict[str, Any]]:
    """governance_asset nodes with degree_centrality >= 5 and trust_score == 100
    that have zero OWNS edges pointing to them.

    These are high-connectivity assets with no declared owner — critical risk.
    Severity: critical.
    """
    results = []
    nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id,
                GovernanceGraphNode.snapshot_id == snapshot_id,
                GovernanceGraphNode.node_type == "governance_asset",
                GovernanceGraphNode.degree_centrality >= 5,
                GovernanceGraphNode.trust_score == 100,
            )
        )
        .scalars()
        .all()
    )
    for node in nodes:
        owns_count = db.execute(
            select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.snapshot_id == snapshot_id,
                GovernanceGraphEdge.edge_type == "OWNS",
                GovernanceGraphEdge.target_node_id == node.node_id,
            )
        ).scalars().first()
        if owns_count is None:
            results.append({
                "pattern_id": "ungoverned_high_centrality",
                "description": (
                    f"High-centrality governance_asset '{node.label}' "
                    f"(degree={node.degree_centrality}) has no declared owners."
                ),
                "severity": "critical",
                "node_ids": [node.node_id],
                "edge_ids": [],
            })
    return results


def _detect_privileged_identity_to_shadow_ai(
    db: Session, tenant_id: str, snapshot_id: str, now: str
) -> list[dict[str, Any]]:
    """Identity nodes with ACCESSES or CONNECTED_TO edges to ai_system nodes
    where the ai_system's properties include discovery_source == 'discovered'.

    Severity: high.
    """
    results: list[dict[str, Any]] = []
    # Find ai_system nodes with discovery_source == "discovered"
    shadow_ai_nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id,
                GovernanceGraphNode.snapshot_id == snapshot_id,
                GovernanceGraphNode.node_type == "ai_system",
            )
        )
        .scalars()
        .all()
    )
    shadow_ai_ids = {
        n.node_id
        for n in shadow_ai_nodes
        if (n.properties or {}).get("discovery_source") == "discovered"
    }
    if not shadow_ai_ids:
        return results

    # Find identity nodes connected to shadow AI
    for ai_node_id in shadow_ai_ids:
        risky_edges = (
            db.execute(
                select(GovernanceGraphEdge).where(
                    GovernanceGraphEdge.tenant_id == tenant_id,
                    GovernanceGraphEdge.snapshot_id == snapshot_id,
                    GovernanceGraphEdge.edge_type.in_(["ACCESSES", "CONNECTED_TO"]),
                    GovernanceGraphEdge.target_node_id == ai_node_id,
                )
            )
            .scalars()
            .all()
        )
        for edge in risky_edges:
            src_node = db.get(GovernanceGraphNode, edge.source_node_id)
            if src_node and src_node.node_type == "identity":
                results.append({
                    "pattern_id": "privileged_identity_to_shadow_ai",
                    "description": (
                        f"Identity '{src_node.label}' has a '{edge.edge_type}' edge "
                        f"to shadow AI system '{ai_node_id}' (discovery_source=discovered)."
                    ),
                    "severity": "high",
                    "node_ids": [src_node.node_id, ai_node_id],
                    "edge_ids": [edge.edge_id],
                })
    return results


def _detect_orphaned_findings(
    db: Session, tenant_id: str, snapshot_id: str, now: str
) -> list[dict[str, Any]]:
    """finding nodes with no IMPACTS edges and no DETECTED_BY edges.

    These are completely disconnected findings. Severity: medium.
    """
    results = []
    finding_nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id,
                GovernanceGraphNode.snapshot_id == snapshot_id,
                GovernanceGraphNode.node_type == "finding",
            )
        )
        .scalars()
        .all()
    )
    for node in finding_nodes:
        impacts = db.execute(
            select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.snapshot_id == snapshot_id,
                GovernanceGraphEdge.edge_type == "IMPACTS",
                GovernanceGraphEdge.source_node_id == node.node_id,
            )
        ).scalars().first()
        detected_by = db.execute(
            select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.snapshot_id == snapshot_id,
                GovernanceGraphEdge.edge_type == "DETECTED_BY",
                GovernanceGraphEdge.source_node_id == node.node_id,
            )
        ).scalars().first()
        if impacts is None and detected_by is None:
            results.append({
                "pattern_id": "orphaned_finding",
                "description": (
                    f"Finding node '{node.label}' has no IMPACTS or DETECTED_BY edges — "
                    "completely disconnected from the graph."
                ),
                "severity": "medium",
                "node_ids": [node.node_id],
                "edge_ids": [],
            })
    return results


def _detect_zero_trust_score_nodes(
    db: Session, tenant_id: str, snapshot_id: str, now: str
) -> list[dict[str, Any]]:
    """Any node with trust_score == 0.

    These are nodes whose source record was deleted after derivation.
    Severity: high.
    """
    results = []
    nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id,
                GovernanceGraphNode.snapshot_id == snapshot_id,
                GovernanceGraphNode.trust_score == 0,
            )
        )
        .scalars()
        .all()
    )
    for node in nodes:
        results.append({
            "pattern_id": "zero_trust_score_node",
            "description": (
                f"Node '{node.label}' (type={node.node_type}) has trust_score=0 — "
                "source record was deleted after derivation."
            ),
            "severity": "high",
            "node_ids": [node.node_id],
            "edge_ids": [],
        })
    return results


def _detect_promoted_candidate_no_owner(
    db: Session, tenant_id: str, snapshot_id: str, now: str
) -> list[dict[str, Any]]:
    """governance_asset nodes with a PROMOTED_FROM edge but zero OWNS edges.

    Auto-promoted assets without an owner need attention. Severity: high.
    """
    results = []
    # Find governance_asset nodes that have a PROMOTED_FROM outbound edge
    promoted_edges = (
        db.execute(
            select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.snapshot_id == snapshot_id,
                GovernanceGraphEdge.edge_type == "PROMOTED_FROM",
            )
        )
        .scalars()
        .all()
    )
    promoted_asset_ids = {e.source_node_id for e in promoted_edges}
    for asset_node_id in promoted_asset_ids:
        asset_node = db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.node_id == asset_node_id,
                GovernanceGraphNode.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        if asset_node is None or asset_node.node_type != "governance_asset":
            continue
        owns_edge = db.execute(
            select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id,
                GovernanceGraphEdge.snapshot_id == snapshot_id,
                GovernanceGraphEdge.edge_type == "OWNS",
                GovernanceGraphEdge.target_node_id == asset_node_id,
            )
        ).scalars().first()
        if owns_edge is None:
            results.append({
                "pattern_id": "promoted_candidate_no_owner",
                "description": (
                    f"Governance asset '{asset_node.label}' was auto-promoted from a candidate "
                    "but has no OWNS edges — no declared owner."
                ),
                "severity": "high",
                "node_ids": [asset_node_id],
                "edge_ids": [],
            })
    return results


_DETECTORS = [
    _detect_ungoverned_high_centrality,
    _detect_privileged_identity_to_shadow_ai,
    _detect_orphaned_findings,
    _detect_zero_trust_score_nodes,
    _detect_promoted_candidate_no_owner,
]


def run_all_patterns(
    db: Session, tenant_id: str, snapshot_id: str, now: str
) -> list[dict[str, Any]]:
    """Run all structural anomaly detectors. Best-effort: exceptions per detector are logged."""
    all_anomalies: list[dict[str, Any]] = []
    for detector in _DETECTORS:
        try:
            anomalies = detector(db, tenant_id, snapshot_id, now)
            all_anomalies.extend(anomalies)
        except Exception:  # noqa: BLE001
            log.warning(
                "Anomaly detector %s failed",
                detector.__name__,
                exc_info=True,
            )
    return all_anomalies
