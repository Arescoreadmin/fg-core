# api/risk_acceptance.py
"""Risk Acceptance Governance API router — PR 14.1.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through RiskAcceptanceEngine
  - All status transitions enforced by RiskAcceptanceEngine.transition()
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.risk_acceptance.engine import RiskAcceptanceEngine
from services.risk_acceptance.schemas import (
    AllowedTransitionsResponse,
    CreateRiskAcceptanceRequest,
    RiskAcceptanceAuditListResponse,
    RiskAcceptanceConflict,
    RiskAcceptanceInvalidTransition,
    RiskAcceptanceListResponse,
    RiskAcceptanceNotFound,
    RiskAcceptanceResponse,
    TransitionRiskAcceptanceRequest,
    UpdateRiskAcceptanceRequest,
)

router = APIRouter(tags=["risk-acceptance"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# POST /risk-acceptances
# ---------------------------------------------------------------------------


@router.post(
    "/risk-acceptances",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RiskAcceptanceResponse,
)
def create_risk_acceptance(
    body: CreateRiskAcceptanceRequest,
    request: Request,
) -> RiskAcceptanceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=tenant_id)
        result = svc.create(body, actor=_actor(request))
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /risk-acceptances
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RiskAcceptanceListResponse,
)
def list_risk_acceptances(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    finding_id: str | None = Query(default=None),
    assessment_id: str | None = Query(default=None),
    remediation_task_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> RiskAcceptanceListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=tenant_id)
        return svc.list(
            status=status_filter,
            finding_id=finding_id,
            assessment_id=assessment_id,
            remediation_task_id=remediation_task_id,
            limit=limit,
            offset=offset,
        )


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RiskAcceptanceResponse,
)
def get_risk_acceptance(
    ra_id: str,
    request: Request,
) -> RiskAcceptanceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get(ra_id)
        except RiskAcceptanceNotFound:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")


# ---------------------------------------------------------------------------
# PATCH /risk-acceptances/{ra_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/risk-acceptances/{ra_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RiskAcceptanceResponse,
)
def update_risk_acceptance(
    ra_id: str,
    body: UpdateRiskAcceptanceRequest,
    request: Request,
) -> RiskAcceptanceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.update(ra_id, body, actor=_actor(request))
            db.commit()
            return result
        except RiskAcceptanceNotFound:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
        except RiskAcceptanceConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /risk-acceptances/{ra_id}/transitions
# ---------------------------------------------------------------------------


@router.post(
    "/risk-acceptances/{ra_id}/transitions",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RiskAcceptanceResponse,
)
def transition_risk_acceptance(
    ra_id: str,
    body: TransitionRiskAcceptanceRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> RiskAcceptanceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.transition(
                ra_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except RiskAcceptanceNotFound:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
        except RiskAcceptanceInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/transitions
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/transitions",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AllowedTransitionsResponse,
)
def get_allowed_transitions(
    ra_id: str,
    request: Request,
) -> AllowedTransitionsResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.allowed_transitions(ra_id)
        except RiskAcceptanceNotFound:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/audit
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/audit",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RiskAcceptanceAuditListResponse,
)
def get_risk_acceptance_audit(
    ra_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> RiskAcceptanceAuditListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_audit(ra_id, limit=limit, offset=offset)
        except RiskAcceptanceNotFound:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
