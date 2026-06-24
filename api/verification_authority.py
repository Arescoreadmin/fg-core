# api/verification_authority.py
"""Verification Workflow Authority API — PR 14.6.6.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Route ordering note:
  Static/aggregated routes MUST appear before /{req_id} to prevent FastAPI
  matching them as request IDs.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks or scope checks
  - No direct ORM access — all ops go through VerificationAuthorityEngine
  - audit events always written (never skipped)
  - actor_id always from request state (key_prefix) — never from body
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.verification_authority.engine import VerificationAuthorityEngine
from services.verification_authority.schemas import (
    AssignVerificationRequest,
    CreateVerificationRequestRequest,
    EscalateVerificationRequest,
    QueueResponse,
    RecordResultRequest,
    SetWorkflowSlaRequest,
    TransitionWorkflowRequest,
    VerificationAuditListResponse,
    VerificationRequestConflict,
    VerificationRequestListResponse,
    VerificationRequestNotFound,
    VerificationRequestResponse,
    VerificationResultResponse,
    VerificationWorkflowInvalidTransition,
    WorkflowCginSnapshot,
    WorkflowDashboardResponse,
    WorkflowSlaStatusResponse,
)

router = APIRouter(tags=["verification-workflow"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _actor_type(request: Request) -> str:
    """Resolve actor type from request state. Defaults to 'human'."""
    return str(getattr(getattr(request, "state", None), "actor_type", None) or "human")


def _get_svc(tenant_id: str, db: Session) -> VerificationAuthorityEngine:
    return VerificationAuthorityEngine(db, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Static/aggregated routes FIRST (before /{req_id})
# ---------------------------------------------------------------------------


@router.post(
    "/verification-requests",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=VerificationRequestResponse,
    status_code=201,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        422: {"description": "Validation error"},
    },
)
def create_request(
    body: CreateVerificationRequestRequest,
    request: Request,
) -> VerificationRequestResponse:
    """Create a new verification workflow request."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.create_request(
                body, actor_id=_actor(request), actor_type=_actor_type(request)
            )
        except VerificationRequestConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))


@router.get(
    "/verification-requests",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=VerificationRequestListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_requests(
    request: Request,
    evidence_id: str | None = Query(default=None),
    workflow_state: str | None = Query(default=None),
    assignee_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> VerificationRequestListResponse:
    """List verification workflow requests for the tenant."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        return svc.list_requests(
            evidence_id=evidence_id,
            workflow_state=workflow_state,
            assignee_id=assignee_id,
            limit=limit,
            offset=offset,
        )


@router.get(
    "/verification-requests/dashboard",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=WorkflowDashboardResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_dashboard(request: Request) -> WorkflowDashboardResponse:
    """Workflow authority dashboard metrics."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        return svc.get_dashboard_metrics()


@router.get(
    "/verification-requests/cgin/snapshot",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=WorkflowCginSnapshot,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_cgin_snapshot(request: Request) -> WorkflowCginSnapshot:
    """CGIN canonical snapshot for verification workflow."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        return svc.get_cgin_snapshot()


@router.get(
    "/verification-requests/queue/{state}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=QueueResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_queue(
    state: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
) -> QueueResponse:
    """Get verification workflow queue for a specific state."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        return svc.get_queue(workflow_state=state, limit=limit)


# ---------------------------------------------------------------------------
# Per-request routes (parameterized — must be after static routes)
# ---------------------------------------------------------------------------


@router.get(
    "/verification-requests/{req_id}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=VerificationRequestResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def get_request(req_id: str, request: Request) -> VerificationRequestResponse:
    """Get a single verification workflow request."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.get_request(req_id)
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@router.post(
    "/verification-requests/{req_id}/assign",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=VerificationRequestResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        422: {"description": "Invalid transition"},
    },
)
def assign_verification(
    req_id: str,
    body: AssignVerificationRequest,
    request: Request,
) -> VerificationRequestResponse:
    """Assign a verifier to a verification request."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.assign_verification(
                req_id, body, actor_id=_actor(request), actor_type=_actor_type(request)
            )
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except VerificationWorkflowInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/verification-requests/{req_id}/transition",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=VerificationRequestResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        422: {"description": "Invalid transition"},
    },
)
def transition_workflow(
    req_id: str,
    body: TransitionWorkflowRequest,
    request: Request,
) -> VerificationRequestResponse:
    """Transition a verification request to a new workflow state."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.transition_workflow(
                req_id, body, actor_id=_actor(request), actor_type=_actor_type(request)
            )
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except VerificationWorkflowInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/verification-requests/{req_id}/escalate",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=VerificationRequestResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        422: {"description": "Invalid state for escalation"},
    },
)
def escalate_verification(
    req_id: str,
    body: EscalateVerificationRequest,
    request: Request,
) -> VerificationRequestResponse:
    """Escalate a verification request."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.escalate_verification(
                req_id, body, actor_id=_actor(request), actor_type=_actor_type(request)
            )
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except VerificationWorkflowInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/verification-requests/{req_id}/result",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=VerificationResultResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        422: {"description": "Invalid state for result"},
    },
)
def record_result(
    req_id: str,
    body: RecordResultRequest,
    request: Request,
) -> VerificationResultResponse:
    """Record a verification decision result."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.record_result(
                req_id, body, actor_id=_actor(request), actor_type=_actor_type(request)
            )
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except VerificationWorkflowInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))


@router.put(
    "/verification-requests/{req_id}/sla",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=WorkflowSlaStatusResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def set_sla_deadlines(
    req_id: str,
    body: SetWorkflowSlaRequest,
    request: Request,
) -> WorkflowSlaStatusResponse:
    """Set SLA deadlines for a verification request."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.set_sla_deadlines(
                req_id, body, actor_id=_actor(request), actor_type=_actor_type(request)
            )
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/verification-requests/{req_id}/sla",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=WorkflowSlaStatusResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def get_sla_status(req_id: str, request: Request) -> WorkflowSlaStatusResponse:
    """Get SLA status for a verification request."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.get_sla_status(req_id)
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/verification-requests/{req_id}/audit",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=VerificationAuditListResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def list_audit_trail(
    req_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> VerificationAuditListResponse:
    """List audit trail for a verification request."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = _get_svc(tenant_id, db)
        try:
            return svc.list_audit_trail(req_id, limit=limit)
        except VerificationRequestNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
