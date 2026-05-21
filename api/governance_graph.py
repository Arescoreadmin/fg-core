"""Governance Topology Graph API.

Read and rebuild the governance topology graph — a derived, queryable
knowledge graph of governance assets, identities, findings, controls,
scans, and engagements.

Not standalone: depends on governance_assets (PR 3.5), field_assessment (PR 103),
and governance_asset_candidates (PR 4.5). The graph is always derived from
those upstream tables.

Routes:
  GET  /governance/graph/nodes               — governance:read  — list nodes
  GET  /governance/graph/nodes/{node_id}     — governance:read  — get node + neighbors
  GET  /governance/graph/traverse            — governance:read  — BFS traversal
  GET  /governance/graph/lineage/{node_id}   — governance:read  — provenance chain
  GET  /governance/graph/stats               — governance:read  — graph stats
  GET  /governance/graph/coverage            — governance:read  — framework coverage
  GET  /governance/graph/anomalies           — governance:read  — active anomalies
  POST /governance/graph/rebuild             — governance:write — trigger rebuild

Scopes:
  governance:read  — all read endpoints
  governance:write — rebuild
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.governance_graph import builder, lineage as lineage_svc, queries

log = logging.getLogger("frostgate.api.governance_graph")

router = APIRouter(
    prefix="/governance/graph",
    tags=["governance-graph"],
)


# ---------------------------------------------------------------------------
# Auth helpers (mirrors governance_assets.py pattern)
# ---------------------------------------------------------------------------


def _resolve_caller_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tid = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tid)


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class RebuildRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    triggered_by: str = "rebuild_api"


class GraphBuildResultResponse(BaseModel):
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


class NodeResponse(BaseModel):
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


class NodeDetailResponse(BaseModel):
    node: NodeResponse
    neighbors: list[NodeResponse]


class EdgeResponse(BaseModel):
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


class TraversalResponse(BaseModel):
    root_node_id: str
    nodes: list[NodeResponse]
    edges: list[EdgeResponse]
    max_depth_reached: int
    truncated: bool


class AnomalyResponse(BaseModel):
    anomaly_id: str
    tenant_id: str
    pattern_id: str
    description: str
    severity: str
    node_ids: list[str]
    edge_ids: list[str]
    snapshot_id: str
    detected_at: str
    resolved_at: str | None
    is_active: bool


def _node_to_response(node: Any) -> NodeResponse:
    """Convert ORM node to response model."""
    return NodeResponse(
        node_id=node.node_id,
        tenant_id=node.tenant_id,
        node_type=node.node_type,
        entity_id=node.entity_id,
        entity_type=node.entity_type,
        label=node.label,
        properties=node.properties or {},
        tags=node.tags or [],
        trust_score=node.trust_score,
        degree_centrality=node.degree_centrality,
        centrality_rank=node.centrality_rank,
        confidence=node.confidence,
        source_ref=node.source_ref,
        engagement_id=node.engagement_id,
        snapshot_id=node.snapshot_id,
        derived_at=node.derived_at,
    )


def _graph_node_to_response(node: Any) -> NodeResponse:
    """Convert dataclass GraphNode to response model."""
    return NodeResponse(
        node_id=node.node_id,
        tenant_id=node.tenant_id,
        node_type=node.node_type,
        entity_id=node.entity_id,
        entity_type=node.entity_type,
        label=node.label,
        properties=node.properties or {},
        tags=node.tags or [],
        trust_score=node.trust_score,
        degree_centrality=node.degree_centrality,
        centrality_rank=node.centrality_rank,
        confidence=node.confidence,
        source_ref=node.source_ref,
        engagement_id=node.engagement_id,
        snapshot_id=node.snapshot_id,
        derived_at=node.derived_at,
    )


def _graph_edge_to_response(edge: Any) -> EdgeResponse:
    """Convert dataclass GraphEdge to response model."""
    return EdgeResponse(
        edge_id=edge.edge_id,
        tenant_id=edge.tenant_id,
        edge_type=edge.edge_type,
        source_node_id=edge.source_node_id,
        target_node_id=edge.target_node_id,
        weight=edge.weight,
        confidence=edge.confidence,
        properties=edge.properties or {},
        source_ref=edge.source_ref,
        engagement_id=edge.engagement_id,
        snapshot_id=edge.snapshot_id,
        derived_at=edge.derived_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/nodes",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[NodeResponse],
)
def list_nodes(
    request: Request,
    node_type: str | None = Query(default=None, description="Filter by node type"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[NodeResponse]:
    """List governance graph nodes with optional type filter."""
    tenant_id = _resolve_caller_tenant(request)
    nodes = queries.list_nodes(
        db,
        tenant_id=tenant_id,
        node_type=node_type,
        limit=limit,
        offset=offset,
    )
    return [_node_to_response(n) for n in nodes]


@router.get(
    "/nodes/{node_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=NodeDetailResponse,
)
def get_node(
    node_id: str,
    request: Request,
    direction: str = Query(default="both", description="outbound|inbound|both"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(auth_ctx_db_session),
) -> NodeDetailResponse:
    """Get a single node with its immediate neighbors."""
    tenant_id = _resolve_caller_tenant(request)
    node = queries.get_node(db, tenant_id=tenant_id, node_id=node_id)
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=api_error("GRAPH_NODE_NOT_FOUND", f"Node {node_id} not found"),
        )
    neighbors = queries.get_neighbors(
        db,
        tenant_id=tenant_id,
        node_id=node_id,
        direction=direction,
        limit=limit,
    )
    return NodeDetailResponse(
        node=_node_to_response(node),
        neighbors=[_node_to_response(n) for n in neighbors],
    )


@router.get(
    "/traverse",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TraversalResponse,
)
def traverse_graph(
    request: Request,
    from_node: str = Query(alias="from", description="Root node ID"),
    max_depth: int = Query(default=5, ge=1, le=10),
    edge_types: str | None = Query(
        default=None, description="Comma-separated edge types to follow"
    ),
    direction: str = Query(default="outbound", description="outbound|inbound|both"),
    db: Session = Depends(auth_ctx_db_session),
) -> TraversalResponse:
    """BFS traversal from a root node. Capped at depth=10 and 500 nodes."""
    tenant_id = _resolve_caller_tenant(request)
    edge_type_list = (
        [e.strip() for e in edge_types.split(",") if e.strip()]
        if edge_types
        else None
    )
    result = queries.traverse(
        db,
        tenant_id=tenant_id,
        root_node_id=from_node,
        max_depth=max_depth,
        edge_types=edge_type_list,
        direction=direction,
    )
    return TraversalResponse(
        root_node_id=result.root_node_id,
        nodes=[_graph_node_to_response(n) for n in result.nodes],
        edges=[_graph_edge_to_response(e) for e in result.edges],
        max_depth_reached=result.max_depth_reached,
        truncated=result.truncated,
    )


@router.get(
    "/lineage/{node_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_lineage(
    node_id: str,
    request: Request,
    max_depth: int = Query(default=8, ge=1, le=10),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Reconstruct provenance chain backwards from a node."""
    tenant_id = _resolve_caller_tenant(request)
    chain = lineage_svc.reconstruct_lineage(
        db, tenant_id=tenant_id, node_id=node_id, max_depth=max_depth
    )
    chain_out = []
    for node_dc, edge_dc in chain.chain:
        chain_out.append({
            "node": _graph_node_to_response(node_dc).model_dump(),
            "edge": _graph_edge_to_response(edge_dc).model_dump() if edge_dc else None,
        })
    return {
        "origin_node_id": chain.origin_node_id,
        "chain": chain_out,
        "depth": chain.depth,
    }


@router.get(
    "/stats",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_stats(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return graph statistics: node/edge counts, centrality, trust distribution."""
    tenant_id = _resolve_caller_tenant(request)
    return queries.get_graph_stats(db, tenant_id=tenant_id)


@router.get(
    "/coverage",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_coverage(
    request: Request,
    framework: str = Query(default="NIST-AI-RMF", description="Framework identifier"),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return framework coverage based on control nodes in the graph."""
    tenant_id = _resolve_caller_tenant(request)
    return queries.get_coverage(db, tenant_id=tenant_id, framework=framework)


@router.get(
    "/anomalies",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[AnomalyResponse],
)
def list_anomalies(
    request: Request,
    active_only: bool = Query(default=True, description="Only return active anomalies"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(auth_ctx_db_session),
) -> list[AnomalyResponse]:
    """List structural graph anomalies."""
    tenant_id = _resolve_caller_tenant(request)
    anomalies = queries.list_anomalies(
        db,
        tenant_id=tenant_id,
        active_only=active_only,
        severity=severity,
        limit=limit,
    )
    return [
        AnomalyResponse(
            anomaly_id=a.anomaly_id,
            tenant_id=a.tenant_id,
            pattern_id=a.pattern_id,
            description=a.description,
            severity=a.severity,
            node_ids=a.node_ids or [],
            edge_ids=a.edge_ids or [],
            snapshot_id=a.snapshot_id,
            detected_at=a.detected_at,
            resolved_at=a.resolved_at,
            is_active=a.is_active,
        )
        for a in anomalies
    ]


@router.post(
    "/rebuild",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=GraphBuildResultResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def rebuild_graph(
    request: Request,
    body: RebuildRequest | None = None,
    db: Session = Depends(auth_ctx_db_session),
) -> GraphBuildResultResponse:
    """Trigger a full governance topology graph rebuild for the caller's tenant."""
    tenant_id = _resolve_caller_tenant(request)
    triggered_by = (body.triggered_by if body else None) or "rebuild_api"
    result = builder.build_graph(db, tenant_id=tenant_id, triggered_by=triggered_by)
    db.commit()
    return GraphBuildResultResponse(
        snapshot_id=result.snapshot_id,
        snapshot_seq=result.snapshot_seq,
        tenant_id=result.tenant_id,
        nodes_upserted=result.nodes_upserted,
        edges_upserted=result.edges_upserted,
        nodes_deleted=result.nodes_deleted,
        edges_deleted=result.edges_deleted,
        anomalies_detected=result.anomalies_detected,
        triggered_by=result.triggered_by,
        built_at=result.built_at,
    )
