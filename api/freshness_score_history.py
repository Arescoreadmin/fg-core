# api/freshness_score_history.py
"""Freshness Score History API — PR 14.6.8.

All routes are tenant-scoped.

Route ordering note:
  This router MUST be registered in main.py BEFORE evidence_freshness_router.
  evidence_freshness_authority.py has GET /freshness/{evidence_id} which would
  capture /freshness/trends, /freshness/history/*, /freshness/snapshots/run
  if registered first.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - actor_id always from request state (key_prefix) — never from body
  - All routes require audit:read or audit:write scope
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.freshness_score_history.engine import FreshnessScoreHistoryEngine
from services.freshness_score_history.schemas import (
    FreshnessCGINTrendSnapshot,
    FreshnessHistoryResponse,
    FreshnessTrendDashboardResponse,
    FreshnessTrendResponse,
    FreshnessSnapshotNotFound,
    RunSnapshotRequest,
    RunSnapshotResponse,
)

router = APIRouter(tags=["freshness-score-history"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _actor_type(request: Request) -> str:
    return str(getattr(getattr(request, "state", None), "actor_type", None) or "human")


@router.post(
    "/freshness/snapshots/run",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=RunSnapshotResponse,
    status_code=201,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        422: {"description": "Validation error"},
    },
)
def run_snapshot(
    req: RunSnapshotRequest,
    request: Request,
) -> RunSnapshotResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = FreshnessScoreHistoryEngine(db, tenant_id=tenant_id)
        return svc.run_snapshot(
            req, actor_id=_actor(request), actor_type=_actor_type(request)
        )


@router.get(
    "/freshness/history/{evidence_id}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessHistoryResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "No snapshot history found for evidence_id"},
    },
)
def get_evidence_history(
    evidence_id: str,
    request: Request,
    days: int = Query(default=30, ge=7, le=365),
    limit: int = Query(default=90, ge=1, le=365),
    offset: int = Query(default=0, ge=0),
) -> FreshnessHistoryResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = FreshnessScoreHistoryEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_evidence_history(
                evidence_id, days=days, limit=limit, offset=offset
            )
        except FreshnessSnapshotNotFound:
            raise HTTPException(
                status_code=404, detail="No snapshot history found for this evidence"
            )


@router.get(
    "/freshness/trends/dashboard",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessTrendDashboardResponse,
)
def get_trends_dashboard(
    request: Request,
) -> FreshnessTrendDashboardResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = FreshnessScoreHistoryEngine(db, tenant_id=tenant_id)
        return svc.get_trends_dashboard()


@router.get(
    "/freshness/trends",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessTrendResponse,
)
def get_trends(
    request: Request,
    period_days: int = Query(default=30, ge=7, le=365),
) -> FreshnessTrendResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = FreshnessScoreHistoryEngine(db, tenant_id=tenant_id)
        return svc.get_trends(period_days=period_days)


@router.get(
    "/freshness/cgin/trends",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessCGINTrendSnapshot,
)
def get_cgin_trends(
    request: Request,
) -> FreshnessCGINTrendSnapshot:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = FreshnessScoreHistoryEngine(db, tenant_id=tenant_id)
        return svc.get_cgin_trends()
