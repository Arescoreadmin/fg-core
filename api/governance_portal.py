# api/governance_portal.py
"""Governance Portal Integration API router — PR 14.4.

All routes are tenant-scoped. Tenant is resolved from auth context only.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through GovernancePortalEngine
  - Portal-owned tables (acknowledgements, audit) are append-only

Route ordering note:
  /portal/governance/dashboard and literal paths MUST be defined before
  parametric paths to prevent FastAPI matching literal segments as IDs.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.governance_portal.engine import GovernancePortalEngine
from services.governance_portal.schemas import (
    AcknowledgementListResponse,
    AcknowledgementResponse,
    CreateAcknowledgementRequest,
    PortalAcknowledgementNotFound,
    PortalAuditListResponse,
    PortalControlDetailResponse,
    PortalControlListResponse,
    PortalDashboardResponse,
    PortalEntityNotFound,
    PortalEvidenceDetailResponse,
    PortalEvidenceListResponse,
    PortalRiskDetailResponse,
    PortalRiskListResponse,
)

router = APIRouter(tags=["governance-portal"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# GET /portal/governance/dashboard  (literal path — before parametric routes)
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalDashboardResponse,
)
def portal_dashboard(request: Request) -> PortalDashboardResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        result = svc.dashboard()
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/governance/risks
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/risks",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalRiskListResponse,
)
def list_portal_risks(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> PortalRiskListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        result = svc.list_risks(limit=limit, offset=offset)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/governance/risks/{risk_id}
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/risks/{risk_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalRiskDetailResponse,
)
def get_portal_risk(risk_id: str, request: Request) -> PortalRiskDetailResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        try:
            result = svc.get_risk(risk_id, actor=_actor(request))
            db.commit()
        except PortalEntityNotFound:
            raise HTTPException(status_code=404, detail="Risk not found.")
    return result


# ---------------------------------------------------------------------------
# GET /portal/governance/controls
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/controls",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalControlListResponse,
)
def list_portal_controls(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    verification_filter: str | None = Query(default=None, alias="verification_status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> PortalControlListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        return svc.list_controls(
            control_status=status_filter,
            verification_status=verification_filter,
            limit=limit,
            offset=offset,
        )


# ---------------------------------------------------------------------------
# GET /portal/governance/controls/{ctl_id}
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/controls/{ctl_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalControlDetailResponse,
)
def get_portal_control(ctl_id: str, request: Request) -> PortalControlDetailResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        try:
            result = svc.get_control(ctl_id, actor=_actor(request))
            db.commit()
        except PortalEntityNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")
    return result


# ---------------------------------------------------------------------------
# GET /portal/governance/evidence
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/evidence",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalEvidenceListResponse,
)
def list_portal_evidence(
    request: Request,
    control_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> PortalEvidenceListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        return svc.list_evidence(control_id=control_id, limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# GET /portal/governance/evidence/{evidence_id}
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/evidence/{evidence_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalEvidenceDetailResponse,
)
def get_portal_evidence(
    evidence_id: str, request: Request
) -> PortalEvidenceDetailResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        try:
            result = svc.get_evidence(evidence_id, actor=_actor(request))
            db.commit()
        except PortalEntityNotFound:
            raise HTTPException(status_code=404, detail="Evidence not found.")
    return result


# ---------------------------------------------------------------------------
# POST /portal/governance/acknowledgements
# ---------------------------------------------------------------------------


@router.post(
    "/portal/governance/acknowledgements",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=AcknowledgementResponse,
)
def create_acknowledgement(
    body: CreateAcknowledgementRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> AcknowledgementResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        result = svc.create_acknowledgement(
            body,
            actor=_actor(request),
            notification_recipient=notify_recipient,
        )
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/governance/acknowledgements
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/acknowledgements",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AcknowledgementListResponse,
)
def list_acknowledgements(
    request: Request,
    entity_type: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AcknowledgementListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        return svc.list_acknowledgements(
            entity_type=entity_type,
            entity_id=entity_id,
            limit=limit,
            offset=offset,
        )


# ---------------------------------------------------------------------------
# GET /portal/governance/acknowledgements/{ack_id}
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/acknowledgements/{ack_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AcknowledgementResponse,
)
def get_acknowledgement(ack_id: str, request: Request) -> AcknowledgementResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_acknowledgement(ack_id)
        except PortalAcknowledgementNotFound:
            raise HTTPException(status_code=404, detail="Acknowledgement not found.")


# ---------------------------------------------------------------------------
# GET /portal/governance/audit
# ---------------------------------------------------------------------------


@router.get(
    "/portal/governance/audit",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalAuditListResponse,
)
def get_portal_audit(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> PortalAuditListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernancePortalEngine(db, tenant_id=tenant_id)
        result = svc.get_audit(limit=limit, offset=offset, actor=_actor(request))
        db.commit()
    return result
