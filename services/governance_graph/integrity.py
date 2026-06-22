"""Graph integrity checks — orphan detection, trust score recomputation, invariant validation."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_graph import GovernanceGraphEdge, GovernanceGraphNode
from services.governance_graph.models import NodeType

log = logging.getLogger("frostgate.governance_graph.integrity")

# Mapping from entity_type (source_ref prefix) to ORM class for trust-score recomputation.
# Each entry: entity_type string → (ORM class | None, primary-key attribute name)
_ENTITY_TYPE_MAP: dict[str, tuple[Any, str]] = {}


def _get_entity_type_map() -> dict[str, tuple[Any, str]]:
    """Lazy-load the entity type → ORM class mapping to avoid circular imports."""
    global _ENTITY_TYPE_MAP
    if _ENTITY_TYPE_MAP:
        return _ENTITY_TYPE_MAP

    try:
        from api.db_models_governance_assets import GaAsset
        from api.db_models_field_assessment import (
            FaNormalizedFinding,
            FaScanResult,
            FaEngagement,
        )
        from api.db_models_governance_asset_candidates import GaAssetCandidate

        _ENTITY_TYPE_MAP = {
            "governance_assets": (GaAsset, "asset_id"),
            "fa_normalized_findings": (FaNormalizedFinding, "id"),
            "fa_scan_results": (FaScanResult, "id"),
            "fa_engagements": (FaEngagement, "id"),
            "ga_asset_candidates": (GaAssetCandidate, "candidate_id"),
            "governance_asset_owners": (
                None,
                "",
            ),  # owners don't have a standalone table lookup
            "governance_asset_attestations": (None, ""),
            "framework_control": (None, ""),  # virtual — always live
        }
    except ImportError:
        pass

    return _ENTITY_TYPE_MAP


def detect_orphan_edges(db: Session, *, tenant_id: str) -> list[str]:
    """Return edge_ids where source or target node_id doesn't exist in tenant."""
    orphan_ids: list[str] = []
    edges = (
        db.execute(
            select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id
            )
        )
        .scalars()
        .all()
    )
    for edge in edges:
        src = db.get(GovernanceGraphNode, edge.source_node_id)
        tgt = db.get(GovernanceGraphNode, edge.target_node_id)
        if src is None or tgt is None:
            orphan_ids.append(edge.edge_id)
    return orphan_ids


def recompute_trust_scores(db: Session, *, tenant_id: str) -> int:
    """Check each node's source_ref still points to a live record. Sets trust_score=0 if not.

    Parses source_ref as "table_name:entity_id". Returns count of nodes updated.
    """
    entity_map = _get_entity_type_map()
    nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id
            )
        )
        .scalars()
        .all()
    )
    updated = 0
    for node in nodes:
        source_ref = node.source_ref or ""
        if ":" not in source_ref:
            continue
        table_name, entity_id = source_ref.split(":", 1)
        mapping = entity_map.get(table_name)
        if mapping is None:
            # Unknown table — keep trust score as-is
            continue
        orm_class, _ = mapping
        if orm_class is None:
            # Virtual entity type — always considered live
            continue
        try:
            record = db.get(orm_class, entity_id)
            if record is None and node.trust_score != 0:
                node.trust_score = 0
                updated += 1
        except Exception:  # noqa: BLE001
            log.debug("Could not look up source_ref %s", source_ref)
    if updated:
        db.flush()
    return updated


_VALID_NODE_TYPES = {nt.value for nt in NodeType}
_VALID_EDGE_TYPES = {
    "OWNS",
    "GOVERNED_BY",
    "USES",
    "ACCESSES",
    "CONNECTED_TO",
    "GENERATED",
    "DETECTED_BY",
    "IMPACTS",
    "ATTESTED_BY",
    "SUPPORTS",
    "RELATED_TO",
    "PROMOTED_FROM",
}


def validate_graph_invariants(db: Session, *, tenant_id: str) -> list[str]:
    """Return list of violation descriptions. Empty list means the graph is valid.

    Checks:
    - No orphan edges (source or target node missing)
    - No self-loops (source_node_id == target_node_id)
    - Valid node_type values
    - Valid edge_type values
    """
    violations: list[str] = []

    # Check orphan edges
    orphans = detect_orphan_edges(db, tenant_id=tenant_id)
    for eid in orphans:
        violations.append(f"orphan_edge:{eid}")

    # Check self-loops
    edges = (
        db.execute(
            select(GovernanceGraphEdge).where(
                GovernanceGraphEdge.tenant_id == tenant_id
            )
        )
        .scalars()
        .all()
    )
    for edge in edges:
        if edge.source_node_id == edge.target_node_id:
            violations.append(f"self_loop_edge:{edge.edge_id}")
        if edge.edge_type not in _VALID_EDGE_TYPES:
            violations.append(f"invalid_edge_type:{edge.edge_id}:{edge.edge_type}")

    # Check valid node types
    nodes = (
        db.execute(
            select(GovernanceGraphNode).where(
                GovernanceGraphNode.tenant_id == tenant_id
            )
        )
        .scalars()
        .all()
    )
    for node in nodes:
        if node.node_type not in _VALID_NODE_TYPES:
            violations.append(f"invalid_node_type:{node.node_id}:{node.node_type}")

    return violations
