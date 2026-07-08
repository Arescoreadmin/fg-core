# api/risk_governance.py
"""Risk Governance API router — PR 14.2.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through GovernanceEngine
  - Approval and review integrity enforced by GovernanceEngine
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.risk_governance.engine import GovernanceEngine
from services.risk_governance.schemas import (
    ApprovalAuditListResponse,
    ApprovalDecisionRequest,
    ApprovalInvalidTransition,
    ApprovalListResponse,
    ApprovalNotFound,
    ApprovalResponse,
    CompleteReviewRequest,
    CreateApprovalRequest,
    CreatePolicyRequest,
    CreateReviewRequest,
    EscalationLevel,
    EscalationListResponse,
    EscalationResponse,
    EscalationTrigger,
    GovernanceDashboardResponse,
    GovernanceTenantViolation,
    PolicyListResponse,
    PolicyNotFound,
    PolicyResponse,
    ReviewConflict,
    ReviewListResponse,
    ReviewNotFound,
    ReviewResponse,
)

router = APIRouter(tags=["risk-governance"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# POST /risk-acceptances/{ra_id}/approvals
# ---------------------------------------------------------------------------


@router.post(
    "/risk-acceptances/{ra_id}/approvals",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ApprovalResponse,
)
def create_approval(
    ra_id: str,
    body: CreateApprovalRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    notify_recipient: str | None = Query(default=None),
) -> ApprovalResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_approval(
                ra_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
        except GovernanceTenantViolation as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/approvals
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/approvals",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ApprovalListResponse,
)
def list_approvals(
    ra_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ApprovalListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_approvals(
                ra_id, status=status_filter, limit=limit, offset=offset
            )
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/approvals/{approval_id}
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/approvals/{approval_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ApprovalResponse,
)
def get_approval(
    ra_id: str,
    approval_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> ApprovalResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_approval(ra_id, approval_id)
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
        except ApprovalNotFound:
            raise HTTPException(status_code=404, detail="Approval not found.")


# ---------------------------------------------------------------------------
# POST /risk-acceptances/{ra_id}/approvals/{approval_id}/decision
# ---------------------------------------------------------------------------


@router.post(
    "/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ApprovalResponse,
)
def decide_approval(
    ra_id: str,
    approval_id: str,
    body: ApprovalDecisionRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    notify_recipient: str | None = Query(default=None),
) -> ApprovalResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.decide_approval(
                ra_id,
                approval_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
        except ApprovalNotFound:
            raise HTTPException(status_code=404, detail="Approval not found.")
        except ApprovalInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/approvals/{approval_id}/audit
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/approvals/{approval_id}/audit",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ApprovalAuditListResponse,
)
def get_approval_audit(
    ra_id: str,
    approval_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ApprovalAuditListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_approval_audit(
                ra_id, approval_id, limit=limit, offset=offset
            )
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
        except ApprovalNotFound:
            raise HTTPException(status_code=404, detail="Approval not found.")


# ---------------------------------------------------------------------------
# POST /risk-acceptances/{ra_id}/reviews
# ---------------------------------------------------------------------------


@router.post(
    "/risk-acceptances/{ra_id}/reviews",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ReviewResponse,
)
def create_review(
    ra_id: str,
    body: CreateReviewRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    notify_recipient: str | None = Query(default=None),
) -> ReviewResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_review(
                ra_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
    return result


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/reviews
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/reviews",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ReviewListResponse,
)
def list_reviews(
    ra_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ReviewListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_reviews(
                ra_id, status=status_filter, limit=limit, offset=offset
            )
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/reviews/{review_id}
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/reviews/{review_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ReviewResponse,
)
def get_review(
    ra_id: str,
    review_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> ReviewResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_review(ra_id, review_id)
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
        except ReviewNotFound:
            raise HTTPException(status_code=404, detail="Review not found.")


# ---------------------------------------------------------------------------
# POST /risk-acceptances/{ra_id}/reviews/{review_id}/complete
# ---------------------------------------------------------------------------


@router.post(
    "/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ReviewResponse,
)
def complete_review(
    ra_id: str,
    review_id: str,
    body: CompleteReviewRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    notify_recipient: str | None = Query(default=None),
) -> ReviewResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.complete_review(
                ra_id,
                review_id,
                body,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
            return result
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
        except ReviewNotFound:
            raise HTTPException(status_code=404, detail="Review not found.")
        except ReviewConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /risk-acceptances/{ra_id}/escalations
# ---------------------------------------------------------------------------


@router.get(
    "/risk-acceptances/{ra_id}/escalations",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=EscalationListResponse,
)
def list_escalations(
    ra_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    resolved: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> EscalationListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_escalations(
                ra_id, resolved=resolved, limit=limit, offset=offset
            )
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")


# ---------------------------------------------------------------------------
# POST /risk-acceptances/{ra_id}/escalations
# ---------------------------------------------------------------------------


@router.post(
    "/risk-acceptances/{ra_id}/escalations",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=EscalationResponse,
)
def create_escalation_route(
    ra_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    trigger: EscalationTrigger = Query(...),
    level: EscalationLevel = Query(...),
    notify_recipient: str | None = Query(default=None),
) -> EscalationResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_escalation(
                ra_id,
                trigger=trigger,
                level=level,
                actor=_actor(request),
                notification_recipient=notify_recipient,
            )
            db.commit()
        except GovernanceTenantViolation:
            raise HTTPException(status_code=404, detail="Risk acceptance not found.")
    return result


# ---------------------------------------------------------------------------
# GET /risk-governance/policies
# ---------------------------------------------------------------------------


@router.get(
    "/risk-governance/policies",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyListResponse,
)
def list_policies(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    active_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> PolicyListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        return svc.list_policies(active_only=active_only, limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# POST /risk-governance/policies
# ---------------------------------------------------------------------------


@router.post(
    "/risk-governance/policies",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=PolicyResponse,
)
def create_policy(
    body: CreatePolicyRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> PolicyResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        result = svc.create_policy(body, actor=_actor(request))
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /risk-governance/policies/{policy_id}
# ---------------------------------------------------------------------------


@router.get(
    "/risk-governance/policies/{policy_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyResponse,
)
def get_policy(
    policy_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> PolicyResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_policy(policy_id)
        except PolicyNotFound:
            raise HTTPException(status_code=404, detail="Policy not found.")


# ---------------------------------------------------------------------------
# GET /risk-governance/dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/risk-governance/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=GovernanceDashboardResponse,
)
def governance_dashboard(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> GovernanceDashboardResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        return svc.governance_dashboard()


# ---------------------------------------------------------------------------
# POST /risk-governance/maintenance/expire-approvals
# ---------------------------------------------------------------------------


@router.post(
    "/risk-governance/maintenance/expire-approvals",
    dependencies=[Depends(require_scopes("governance:write"))],
)
def expire_overdue_approvals(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> dict:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        count = svc.expire_overdue_approvals(actor=_actor(request))
        db.commit()
    return {"expired": count}


# ---------------------------------------------------------------------------
# POST /risk-governance/maintenance/mark-overdue-reviews
# ---------------------------------------------------------------------------


@router.post(
    "/risk-governance/maintenance/mark-overdue-reviews",
    dependencies=[Depends(require_scopes("governance:write"))],
)
def mark_overdue_reviews(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> dict:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = GovernanceEngine(db, tenant_id=tenant_id)
        count = svc.mark_overdue_reviews(actor=_actor(request))
        db.commit()
    return {"marked_overdue": count}
