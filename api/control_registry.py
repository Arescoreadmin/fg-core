# api/control_registry.py
"""Compensating Control Registry API router — PR 14.3.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through ControlRegistryEngine
  - Control integrity enforced by ControlRegistryEngine

Route ordering note:
  /controls/dashboard and /controls/maintenance/* MUST be defined before
  /controls/{ctl_id} to prevent FastAPI matching "dashboard" as a ctl_id.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.control_registry.engine import ControlRegistryEngine
from services.control_registry.schemas import (
    CompleteControlReviewRequest,
    ControlAuditListResponse,
    ControlConflict,
    ControlDashboardResponse,
    ControlEvidenceLinkListResponse,
    ControlEvidenceLinkResponse,
    ControlInvalidTransition,
    ControlListResponse,
    ControlNotFound,
    ControlResponse,
    ControlReviewConflict,
    ControlReviewListResponse,
    ControlReviewNotFound,
    ControlReviewResponse,
    ControlVerificationError,
    CreateControlRequest,
    CreateControlReviewRequest,
    FreshnessSweepResponse,
    LinkEvidenceRequest,
    LinkRiskRequest,
    ReviewSweepResponse,
    RiskAcceptanceControlLinkListResponse,
    RiskAcceptanceControlLinkResponse,
    UpdateControlRequest,
    VerifyControlRequest,
)

router = APIRouter(tags=["control-registry"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# GET /controls/dashboard  (must appear before /controls/{ctl_id})
# ---------------------------------------------------------------------------


@router.get(
    "/controls/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlDashboardResponse,
)
def control_dashboard(request: Request) -> ControlDashboardResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        return svc.dashboard()


# ---------------------------------------------------------------------------
# POST /controls/maintenance/freshness  (before /controls/{ctl_id})
# ---------------------------------------------------------------------------


@router.post(
    "/controls/maintenance/freshness",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=FreshnessSweepResponse,
)
def expire_stale_verifications(request: Request) -> FreshnessSweepResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        result = svc.expire_stale_verifications(actor=_actor(request))
        db.commit()
    return result


# ---------------------------------------------------------------------------
# POST /controls/maintenance/review-sweep  (before /controls/{ctl_id})
# ---------------------------------------------------------------------------


@router.post(
    "/controls/maintenance/review-sweep",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ReviewSweepResponse,
)
def mark_overdue_reviews(request: Request) -> ReviewSweepResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        result = svc.mark_overdue_reviews(actor=_actor(request))
        db.commit()
    return result


# ---------------------------------------------------------------------------
# POST /controls
# ---------------------------------------------------------------------------


@router.post(
    "/controls",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ControlResponse,
)
def create_control(
    body: CreateControlRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> ControlResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        result = svc.create_control(
            body,
            actor=_actor(request),
            notification_recipient=notify_recipient,
        )
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /controls
# ---------------------------------------------------------------------------


@router.get(
    "/controls",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlListResponse,
)
def list_controls(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    type_filter: str | None = Query(default=None, alias="control_type"),
    verification_filter: str | None = Query(default=None, alias="verification_status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ControlListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        return svc.list_controls(
            control_status=status_filter,
            control_type=type_filter,
            verification_status=verification_filter,
            limit=limit,
            offset=offset,
        )


# ---------------------------------------------------------------------------
# GET /controls/{ctl_id}
# ---------------------------------------------------------------------------


@router.get(
    "/controls/{ctl_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlResponse,
)
def get_control(ctl_id: str, request: Request) -> ControlResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_control(ctl_id)
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")


# ---------------------------------------------------------------------------
# PATCH /controls/{ctl_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/controls/{ctl_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ControlResponse,
)
def update_control(
    ctl_id: str,
    body: UpdateControlRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> ControlResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            result = svc.update_control(
                ctl_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")
        except ControlInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except ControlConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /controls/{ctl_id}/verify
# ---------------------------------------------------------------------------


@router.post(
    "/controls/{ctl_id}/verify",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ControlResponse,
)
def verify_control(
    ctl_id: str,
    body: VerifyControlRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> ControlResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            result = svc.verify_control(
                ctl_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")
        except ControlVerificationError as exc:
            raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /controls/{ctl_id}/evidence
# ---------------------------------------------------------------------------


@router.post(
    "/controls/{ctl_id}/evidence",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ControlEvidenceLinkResponse,
)
def link_evidence(
    ctl_id: str,
    body: LinkEvidenceRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> ControlEvidenceLinkResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            result = svc.link_evidence(
                ctl_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")


# ---------------------------------------------------------------------------
# GET /controls/{ctl_id}/evidence
# ---------------------------------------------------------------------------


@router.get(
    "/controls/{ctl_id}/evidence",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlEvidenceLinkListResponse,
)
def list_evidence(
    ctl_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ControlEvidenceLinkListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_evidence(ctl_id, limit=limit, offset=offset)
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")


# ---------------------------------------------------------------------------
# POST /controls/{ctl_id}/risk-links
# ---------------------------------------------------------------------------


@router.post(
    "/controls/{ctl_id}/risk-links",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RiskAcceptanceControlLinkResponse,
)
def link_risk(
    ctl_id: str,
    body: LinkRiskRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> RiskAcceptanceControlLinkResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            result = svc.link_risk(
                ctl_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")
        except ControlConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /controls/{ctl_id}/risk-links
# ---------------------------------------------------------------------------


@router.get(
    "/controls/{ctl_id}/risk-links",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RiskAcceptanceControlLinkListResponse,
)
def list_risk_links(
    ctl_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> RiskAcceptanceControlLinkListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_risk_links(ctl_id, limit=limit, offset=offset)
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")


# ---------------------------------------------------------------------------
# POST /controls/{ctl_id}/reviews
# ---------------------------------------------------------------------------


@router.post(
    "/controls/{ctl_id}/reviews",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ControlReviewResponse,
)
def create_review(
    ctl_id: str,
    body: CreateControlReviewRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> ControlReviewResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_review(
                ctl_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")


# ---------------------------------------------------------------------------
# GET /controls/{ctl_id}/reviews
# ---------------------------------------------------------------------------


@router.get(
    "/controls/{ctl_id}/reviews",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlReviewListResponse,
)
def list_reviews(
    ctl_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ControlReviewListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_reviews(ctl_id, limit=limit, offset=offset)
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")


# ---------------------------------------------------------------------------
# POST /controls/{ctl_id}/reviews/{review_id}/complete
# ---------------------------------------------------------------------------


@router.post(
    "/controls/{ctl_id}/reviews/{review_id}/complete",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ControlReviewResponse,
)
def complete_review(
    ctl_id: str,
    review_id: str,
    body: CompleteControlReviewRequest,
    request: Request,
    notify_recipient: str | None = Query(default=None),
) -> ControlReviewResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            result = svc.complete_review(
                ctl_id,
                review_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")
        except ControlReviewNotFound:
            raise HTTPException(status_code=404, detail="Review not found.")
        except ControlReviewConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /controls/{ctl_id}/audit
# ---------------------------------------------------------------------------


@router.get(
    "/controls/{ctl_id}/audit",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ControlAuditListResponse,
)
def get_audit(
    ctl_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ControlAuditListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = ControlRegistryEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_audit(ctl_id, limit=limit, offset=offset)
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="Control not found.")
