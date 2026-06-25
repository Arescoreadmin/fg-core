# api/control_effectiveness_explainability.py
"""Control Effectiveness Explainability & Governance Action Engine API — PR 16.5.1.

All routes are tenant-scoped. All routes require governance:read.

Route ordering note:
  /priorities, /rankings, /executive-dashboard are 2-segment routes and must be
  registered BEFORE /{control_id} on the main CE router. This router must be
  included in main.py BEFORE the control_effectiveness_router to guarantee that.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.control_effectiveness_explainability.engine import ExplainabilityEngine
from services.control_effectiveness_explainability.schemas import (
    ControlExplainResponse,
    ExecutiveDashboardResponse,
    GovernanceActionsResponse,
    PrioritiesResponse,
    RankingsResponse,
    ScoreContributorsResponse,
)
from sqlalchemy.orm import Session

router = APIRouter(tags=["control-effectiveness-explainability"])


@router.get(
    "/control-effectiveness/executive-dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ExecutiveDashboardResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_executive_dashboard(request: Request) -> ExecutiveDashboardResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return ExplainabilityEngine(db, tenant_id).get_executive_dashboard()


@router.get(
    "/control-effectiveness/priorities",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PrioritiesResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_priorities(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> PrioritiesResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return ExplainabilityEngine(db, tenant_id).get_priorities(
            limit=limit, offset=offset
        )


@router.get(
    "/control-effectiveness/rankings",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RankingsResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_rankings(request: Request) -> RankingsResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return ExplainabilityEngine(db, tenant_id).get_rankings()


@router.get(
    "/control-effectiveness/explain/{control_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlExplainResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Control not found"},
    },
)
def explain_control(
    control_id: str,
    request: Request,
) -> ControlExplainResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        result = ExplainabilityEngine(db, tenant_id).explain(control_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Control not found")
        return result


@router.get(
    "/control-effectiveness/contributors/{control_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ScoreContributorsResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Control not found"},
    },
)
def get_contributors(
    control_id: str,
    request: Request,
) -> ScoreContributorsResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        result = ExplainabilityEngine(db, tenant_id).get_contributors(control_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Control not found")
        return result


@router.get(
    "/control-effectiveness/actions/{control_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=GovernanceActionsResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Control not found"},
    },
)
def get_actions(
    control_id: str,
    request: Request,
) -> GovernanceActionsResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        result = ExplainabilityEngine(db, tenant_id).get_actions(control_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Control not found")
        return result
