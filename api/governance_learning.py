# api/governance_learning.py
"""Governance Learning Loop Authority API — PR 17.6B.

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
from services.governance_learning.engine import GovernanceLearningEngine
from services.governance_learning.schemas import (
    IngestOutcomeRequest,
    LearningAggregateListResponse,
    LearningCGINSnapshot,
    LearningDashboardResponse,
    LearningRecordListResponse,
    GovernanceMomentumResponse,
    RecalculateRequest,
    RecommendationListResponse,
)

router = APIRouter(tags=["governance-learning"])


# ---------------------------------------------------------------------------
# GET /governance-learning/dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=LearningDashboardResponse,
)
def get_dashboard(request: Request) -> LearningDashboardResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).get_dashboard()


# ---------------------------------------------------------------------------
# GET /governance-learning/learning-records
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/learning-records",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=LearningRecordListResponse,
)
def list_learning_records(
    request: Request,
    learning_category: Optional[str] = Query(default=None),
    remediation_category: Optional[str] = Query(default=None),
    control_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> LearningRecordListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).list_records(
            learning_category=learning_category,
            remediation_category=remediation_category,
            control_id=control_id,
            limit=limit,
            offset=offset,
        )


# ---------------------------------------------------------------------------
# GET /governance-learning/aggregates
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/aggregates",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=LearningAggregateListResponse,
)
def list_aggregates(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> LearningAggregateListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).list_aggregates(
            limit=limit, offset=offset
        )


# ---------------------------------------------------------------------------
# GET /governance-learning/recommendations
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/recommendations",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RecommendationListResponse,
)
def get_recommendations(request: Request) -> RecommendationListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).get_recommendations()


# ---------------------------------------------------------------------------
# GET /governance-learning/top-performers
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/top-performers",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=LearningAggregateListResponse,
)
def get_top_performers(
    request: Request,
    limit: int = Query(default=5, ge=1, le=50),
) -> LearningAggregateListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).get_top_performers(limit=limit)


# ---------------------------------------------------------------------------
# GET /governance-learning/top-failures
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/top-failures",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=LearningAggregateListResponse,
)
def get_top_failures(
    request: Request,
    limit: int = Query(default=5, ge=1, le=50),
) -> LearningAggregateListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).get_failures(limit=limit)


# ---------------------------------------------------------------------------
# GET /governance-learning/momentum
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/momentum",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=GovernanceMomentumResponse,
)
def get_momentum(request: Request) -> GovernanceMomentumResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).get_momentum()


# ---------------------------------------------------------------------------
# GET /governance-learning/cgin/snapshot
# ---------------------------------------------------------------------------


@router.get(
    "/governance-learning/cgin/snapshot",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=LearningCGINSnapshot,
)
def get_cgin_snapshot(request: Request) -> LearningCGINSnapshot:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).get_cgin_snapshot()


# ---------------------------------------------------------------------------
# POST /governance-learning/ingest-outcome  (governance:write, 201)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-learning/ingest-outcome",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_201_CREATED,
)
def ingest_outcome(
    body: IngestOutcomeRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).ingest_outcome(body)


# ---------------------------------------------------------------------------
# POST /governance-learning/recalculate  (governance:write, 200)
# ---------------------------------------------------------------------------


@router.post(
    "/governance-learning/recalculate",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=None,
    status_code=status.HTTP_200_OK,
)
def recalculate(
    body: RecalculateRequest,
    request: Request,
):
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return GovernanceLearningEngine(db, tenant_id).recalculate(body)
