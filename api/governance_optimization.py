# api/governance_optimization.py
"""Governance Optimization Engine Authority API — PR 17.6D.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Route ordering: fixed paths before parameterized paths.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - governance:read for GET routes
  - governance:write for POST routes
  - No AI, no LLMs — all outputs deterministic
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.governance_optimization.engine import GovernanceOptimizationEngine
from services.governance_optimization.schemas import (
    CGINOptimizationSnapshot,
    OptimizationAggregateResponse,
    OptimizationDashboardResponse,
    OptimizationDecisionResponse,
    OptimizationSnapshotResponse,
    RankRequest,
    RecalculateOptimizationRequest,
)

router = APIRouter(tags=["governance-optimization"])


# ---------------------------------------------------------------------------
# GET /governance-optimization/dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=OptimizationDashboardResponse,
)
def get_dashboard(request: Request) -> OptimizationDashboardResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).get_dashboard()


# ---------------------------------------------------------------------------
# GET /governance-optimization/decisions
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/decisions",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationDecisionResponse],
)
def list_decisions(
    request: Request,
    optimization_type: Optional[str] = Query(default=None),
    target_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_decisions(
            optimization_type=optimization_type,
            target_type=target_type,
            limit=limit,
            offset=offset,
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/aggregates
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/aggregates",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationAggregateResponse],
)
def list_aggregates(
    request: Request,
    target_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[OptimizationAggregateResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_aggregates(
            target_type=target_type, limit=limit, offset=offset
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/snapshots
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/snapshots",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationSnapshotResponse],
)
def list_snapshots(
    request: Request,
    snapshot_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[OptimizationSnapshotResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_snapshots(
            snapshot_type=snapshot_type, limit=limit, offset=offset
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/recommendation-rankings
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/recommendation-rankings",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationDecisionResponse],
)
def get_recommendation_rankings(request: Request) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_decisions(
            optimization_type="RECOMMENDATION_RANKING"
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/control-priorities  (placeholder)
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/control-priorities",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationDecisionResponse],
)
def get_control_priorities(request: Request) -> list[OptimizationDecisionResponse]:
    """Placeholder — control data requires running POST /rank-controls first."""
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_decisions(
            optimization_type="CONTROL_PRIORITIZATION"
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/remediation-priorities
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/remediation-priorities",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationDecisionResponse],
)
def get_remediation_priorities(request: Request) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_decisions(
            optimization_type="REMEDIATION_PRIORITIZATION"
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/bridge-priorities
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/bridge-priorities",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationDecisionResponse],
)
def get_bridge_priorities(request: Request) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_decisions(
            optimization_type="BRIDGE_PRIORITIZATION"
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/strategy-weights
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/strategy-weights",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[OptimizationDecisionResponse],
)
def get_strategy_weights(request: Request) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).list_decisions(
            optimization_type="STRATEGY_WEIGHTING"
        )


# ---------------------------------------------------------------------------
# GET /governance-optimization/cgin/snapshot
# ---------------------------------------------------------------------------


@router.get(
    "/governance-optimization/cgin/snapshot",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CGINOptimizationSnapshot,
)
def get_cgin_snapshot(request: Request) -> CGINOptimizationSnapshot:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).get_cgin_snapshot()


# ---------------------------------------------------------------------------
# POST /governance-optimization/recalculate  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-optimization/recalculate",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_200_OK,
)
def recalculate(
    body: RecalculateOptimizationRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).recalculate(
            optimization_type=body.optimization_type
        )


# ---------------------------------------------------------------------------
# POST /governance-optimization/rank-recommendations  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-optimization/rank-recommendations",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=list[OptimizationDecisionResponse],
    status_code=status.HTTP_200_OK,
)
def rank_recommendations(
    body: RankRequest,
    request: Request,
) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).rank_recommendations(
            persist=body.persist
        )


# ---------------------------------------------------------------------------
# POST /governance-optimization/rank-controls  (placeholder, governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-optimization/rank-controls",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=list[OptimizationDecisionResponse],
    status_code=status.HTTP_200_OK,
)
def rank_controls(
    body: RankRequest,
    request: Request,
) -> list[OptimizationDecisionResponse]:
    """Placeholder — returns empty list until control effectiveness data is ingested."""
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).rank_controls(
            persist=body.persist
        )


# ---------------------------------------------------------------------------
# POST /governance-optimization/rank-remediations  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-optimization/rank-remediations",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=list[OptimizationDecisionResponse],
    status_code=status.HTTP_200_OK,
)
def rank_remediations(
    body: RankRequest,
    request: Request,
) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).rank_remediations(
            persist=body.persist
        )


# ---------------------------------------------------------------------------
# POST /governance-optimization/rank-bridges  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-optimization/rank-bridges",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=list[OptimizationDecisionResponse],
    status_code=status.HTTP_200_OK,
)
def rank_bridges(
    body: RankRequest,
    request: Request,
) -> list[OptimizationDecisionResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceOptimizationEngine(db, tenant_id).rank_bridges(
            persist=body.persist
        )
