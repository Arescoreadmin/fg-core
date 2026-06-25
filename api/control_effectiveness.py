# api/control_effectiveness.py
"""Control Effectiveness Engine API — PR 16.5.

All routes are tenant-scoped. All routes require governance:read or governance:write.

Route ordering:
  /dashboard, /cgin/snapshot, POST /recalculate MUST be registered before
  /{control_id} to prevent the path-param route from capturing them.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.control_effectiveness.engine import ControlEffectivenessEngine
from services.control_effectiveness.schemas import (
    CGINEffectivenessSnapshot,
    ControlEffectivenessDashboardResponse,
    ControlEffectivenessHistoryResponse,
    ControlEffectivenessListResponse,
    ControlEffectivenessResponse,
    ControlNotFound,
    RecalculateRequest,
    RecalculateResponse,
)
from sqlalchemy.orm import Session

router = APIRouter(tags=["control-effectiveness"])


@router.get(
    "/control-effectiveness/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlEffectivenessDashboardResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_dashboard(request: Request) -> ControlEffectivenessDashboardResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return ControlEffectivenessEngine(db, tenant_id).get_dashboard()


@router.get(
    "/control-effectiveness/cgin/snapshot",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CGINEffectivenessSnapshot,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_cgin_snapshot(request: Request) -> CGINEffectivenessSnapshot:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return ControlEffectivenessEngine(db, tenant_id).get_cgin_snapshot()


@router.post(
    "/control-effectiveness/recalculate",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RecalculateResponse,
    status_code=200,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        422: {"description": "Validation error"},
    },
)
def recalculate(
    req: RecalculateRequest,
    request: Request,
) -> RecalculateResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = ControlEffectivenessEngine(db, tenant_id)
        if req.control_id is not None:
            try:
                result = engine.recalculate(req.control_id)
            except ControlNotFound:
                raise HTTPException(status_code=404, detail="Control not found")
            return RecalculateResponse(
                tenant_id=tenant_id,
                controls_recalculated=1,
                control_id=req.control_id,
                calculated_at=result.last_calculated_at,
            )
        return engine.recalculate_all()


@router.get(
    "/control-effectiveness",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlEffectivenessListResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def list_effectiveness(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> ControlEffectivenessListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return ControlEffectivenessEngine(db, tenant_id).list_effectiveness(
            limit=limit, offset=offset
        )


@router.get(
    "/control-effectiveness/{control_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlEffectivenessResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Control not found"},
    },
)
def get_effectiveness(
    control_id: str,
    request: Request,
) -> ControlEffectivenessResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        try:
            return ControlEffectivenessEngine(db, tenant_id).get_effectiveness(
                control_id
            )
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found")


@router.get(
    "/control-effectiveness/history/{control_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlEffectivenessHistoryResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "No history found"},
    },
)
def get_history(
    control_id: str,
    request: Request,
    limit: int = Query(default=90, ge=1, le=365),
    offset: int = Query(default=0, ge=0),
) -> ControlEffectivenessHistoryResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return ControlEffectivenessEngine(db, tenant_id).get_history(
            control_id, limit=limit, offset=offset
        )
