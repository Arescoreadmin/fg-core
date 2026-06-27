# api/governance_chain.py
"""Canonical Governance Chain Authority API — PR 17.6.

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

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.governance_chain.engine import GovernanceChainEngine
from services.governance_chain.schemas import (
    CGINChainSnapshotBundle,
    ChainBridgeNotFound,
    ChainDiagnosticsResponse,
    ChainEventListResponse,
    ChainExecutionListResponse,
    ChainExecutionNotFound,
    ChainExecutionResponse,
    ChainValidationResponse,
    ExecuteBridgeRequest,
    GovernanceHealthHistoryResponse,
    GovernanceHealthNotFound,
    GovernanceHealthResponse,
    RecalculateHealthRequest,
)

router = APIRouter(tags=["governance-chain"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# GET /governance-chain/health   — latest governance health snapshot
# ---------------------------------------------------------------------------


@router.get(
    "/governance-chain/health",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=GovernanceHealthResponse,
)
def get_governance_health(request: Request) -> GovernanceHealthResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        try:
            return engine.get_latest_health()
        except GovernanceHealthNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /governance-chain/diagnostics   — chain diagnostics + authority availability
# ---------------------------------------------------------------------------


@router.get(
    "/governance-chain/diagnostics",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ChainDiagnosticsResponse,
)
def get_chain_diagnostics(request: Request) -> ChainDiagnosticsResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        return engine.get_diagnostics()


# ---------------------------------------------------------------------------
# GET /governance-chain/cgin/snapshot   — CGIN anonymized benchmark snapshot
# ---------------------------------------------------------------------------


@router.get(
    "/governance-chain/cgin/snapshot",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CGINChainSnapshotBundle,
)
def get_cgin_snapshot(request: Request) -> CGINChainSnapshotBundle:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        return engine.get_cgin_snapshot()


# ---------------------------------------------------------------------------
# GET /governance-chain/executions   — list bridge executions
# ---------------------------------------------------------------------------


@router.get(
    "/governance-chain/executions",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ChainExecutionListResponse,
)
def list_executions(
    request: Request,
    bridge_type: Optional[str] = Query(None),
    success: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ChainExecutionListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        return engine.list_executions(
            bridge_type=bridge_type, success=success, limit=limit, offset=offset
        )


# ---------------------------------------------------------------------------
# GET /governance-chain/executions/{execution_id}   — single execution
# ---------------------------------------------------------------------------


@router.get(
    "/governance-chain/executions/{execution_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ChainExecutionResponse,
)
def get_execution(request: Request, execution_id: str) -> ChainExecutionResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        try:
            return engine.get_execution(execution_id)
        except ChainExecutionNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /governance-chain/events/{correlation_id}   — events by correlation
# ---------------------------------------------------------------------------


@router.get(
    "/governance-chain/events/{correlation_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ChainEventListResponse,
)
def list_events_by_correlation(
    request: Request, correlation_id: str
) -> ChainEventListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        return engine.list_events_by_correlation(correlation_id)


# ---------------------------------------------------------------------------
# POST /governance-chain/execute   — dispatch a bridge
# ---------------------------------------------------------------------------


@router.post(
    "/governance-chain/execute",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ChainExecutionResponse,
    status_code=status.HTTP_201_CREATED,
)
def execute_bridge(
    request: Request,
    body: ExecuteBridgeRequest,
) -> ChainExecutionResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        try:
            return engine.execute_bridge(body, actor_id=actor, actor_type="human")
        except ChainBridgeNotFound as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /governance-chain/recalculate-health   — compute and store health snapshot
# ---------------------------------------------------------------------------


@router.post(
    "/governance-chain/recalculate-health",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=GovernanceHealthResponse,
    status_code=status.HTTP_201_CREATED,
)
def recalculate_health(
    request: Request,
    body: RecalculateHealthRequest,
) -> GovernanceHealthResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        return engine.generate_governance_health_snapshot(body)


# ---------------------------------------------------------------------------
# GET /governance-chain/health/history — health snapshot history
# ---------------------------------------------------------------------------


@router.get(
    "/governance-chain/health/history",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=GovernanceHealthHistoryResponse,
)
def get_health_history(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> GovernanceHealthHistoryResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        return engine.list_health_history(limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# POST /governance-chain/validate — validate chain integrity
# ---------------------------------------------------------------------------


@router.post(
    "/governance-chain/validate",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ChainValidationResponse,
    status_code=status.HTTP_200_OK,
)
def validate_chain(request: Request) -> ChainValidationResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = GovernanceChainEngine(db, tenant_id=tenant_id)
        return engine.validate_chain()
