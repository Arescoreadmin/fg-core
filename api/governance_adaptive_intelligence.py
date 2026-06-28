# api/governance_adaptive_intelligence.py
"""Governance Adaptive Intelligence Authority API — PR 17.6C.

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
from services.governance_adaptive_intelligence.engine import (
    GovernanceAdaptiveIntelligenceEngine,
)
from services.governance_adaptive_intelligence.schemas import (
    AcceptRecommendationRequest,
    AdaptiveAccuracyResponse,
    AdaptiveDashboardResponse,
    CGINAdaptiveSnapshot,
    CalibrationResponse,
    ExecuteRecommendationRequest,
    PlaybookResponse,
    RecalculateAdaptiveRequest,
    RecordOutcomeRequest,
    RecommendationHistoryResponse,
    RecommendationOutcomeResponse,
    StrategyProfileResponse,
    TrackRecommendationRequest,
)

router = APIRouter(tags=["governance-adaptive-intelligence"])


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AdaptiveDashboardResponse,
)
def get_dashboard(request: Request) -> AdaptiveDashboardResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).get_dashboard()


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/recommendations
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/recommendations",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[RecommendationHistoryResponse],
)
def list_recommendations(
    request: Request,
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[RecommendationHistoryResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).list_recommendations(
            status=status, limit=limit, offset=offset
        )


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/outcomes
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/outcomes",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[RecommendationOutcomeResponse],
)
def list_outcomes(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[RecommendationOutcomeResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).list_outcomes(
            limit=limit, offset=offset
        )


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/accuracy
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/accuracy",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AdaptiveAccuracyResponse,
)
def get_accuracy(request: Request) -> AdaptiveAccuracyResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).get_accuracy()


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/calibration
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/calibration",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CalibrationResponse,
)
def get_calibration(request: Request) -> CalibrationResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).get_calibration()


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/playbooks
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/playbooks",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[PlaybookResponse],
)
def list_playbooks(request: Request) -> list[PlaybookResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).list_playbooks()


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/strategy-profiles
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/strategy-profiles",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=list[StrategyProfileResponse],
)
def list_strategy_profiles(request: Request) -> list[StrategyProfileResponse]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(
            db, tenant_id
        ).list_strategy_profiles()


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/cgin/snapshot
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/cgin/snapshot",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CGINAdaptiveSnapshot,
)
def get_cgin_snapshot(request: Request) -> CGINAdaptiveSnapshot:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).get_cgin_snapshot()


# ---------------------------------------------------------------------------
# POST /governance-adaptive-intelligence/track  (governance:write, 201)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-adaptive-intelligence/track",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_201_CREATED,
)
def track_recommendation(
    body: TrackRecommendationRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).track_recommendation(
            body
        )


# ---------------------------------------------------------------------------
# POST /governance-adaptive-intelligence/accept  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-adaptive-intelligence/accept",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_200_OK,
)
def accept_recommendation(
    body: AcceptRecommendationRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(
            db, tenant_id
        ).accept_recommendation(body)


# ---------------------------------------------------------------------------
# POST /governance-adaptive-intelligence/execute  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-adaptive-intelligence/execute",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_200_OK,
)
def execute_recommendation(
    body: ExecuteRecommendationRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(
            db, tenant_id
        ).execute_recommendation(body)


# ---------------------------------------------------------------------------
# POST /governance-adaptive-intelligence/record-outcome  (governance:write, 201)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-adaptive-intelligence/record-outcome",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_201_CREATED,
)
def record_outcome(
    body: RecordOutcomeRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).record_outcome(body)


# ---------------------------------------------------------------------------
# POST /governance-adaptive-intelligence/recalculate  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-adaptive-intelligence/recalculate",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_200_OK,
)
def recalculate(
    body: RecalculateAdaptiveRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(db, tenant_id).recalculate(body)


# ---------------------------------------------------------------------------
# GET /governance-adaptive-intelligence/recommendations/{recommendation_id}
# (must come AFTER all fixed paths)
# ---------------------------------------------------------------------------


@router.get(
    "/governance-adaptive-intelligence/recommendations/{recommendation_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RecommendationHistoryResponse,
)
def get_recommendation_detail(
    recommendation_id: str,
    request: Request,
) -> RecommendationHistoryResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceAdaptiveIntelligenceEngine(
            db, tenant_id
        ).get_recommendation_detail(recommendation_id)
