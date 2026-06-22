# api/portal_remediation.py
"""Client Portal Remediation API — PR 13.4.

Routes:
  GET  /portal/remediation                                    — dashboard
  GET  /portal/remediation/tasks/{task_id}                    — task detail
  GET  /portal/remediation/tasks/{task_id}/comments           — list comments
  POST /portal/remediation/tasks/{task_id}/comments           — add comment
  PATCH /portal/remediation/tasks/{task_id}/comments/{cid}   — edit comment
  GET  /portal/remediation/tasks/{task_id}/evidence           — list evidence
  POST /portal/remediation/tasks/{task_id}/evidence           — submit evidence
  POST /portal/remediation/tasks/{task_id}/acknowledge        — acknowledge ownership
  GET  /portal/remediation/tasks/{task_id}/audit              — portal audit trail

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - All routes use governance:read or governance:write scope
  - No direct ORM access — all logic through PortalRemediationEngine
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine as _get_engine, set_tenant_context
from services.remediation_portal.engine import PortalRemediationEngine
from services.remediation_portal.schemas import (
    AcknowledgeOwnershipRequest,
    AcknowledgeOwnershipResponse,
    AddCommentRequest,
    EditCommentRequest,
    PortalAuditListResponse,
    PortalCommentListResponse,
    PortalCommentNotFound,
    PortalCommentResponse,
    PortalDashboardResponse,
    PortalEvidenceDuplicate,
    PortalEvidenceListResponse,
    PortalEvidenceResponse,
    PortalNotFound,
    PortalRateLimitExceeded,
    PortalTaskView,
    SubmitEvidenceRequest,
)

portal_remediation_router = APIRouter(
    prefix="/portal/remediation",
    tags=["portal-remediation"],
)

_ACTOR_UNKNOWN = "unknown"


def _rate_limited(exc: PortalRateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "error": "RATE_LIMIT_EXCEEDED",
            "retry_after_seconds": exc.retry_after_seconds,
        },
        headers={"Retry-After": str(exc.retry_after_seconds)},
    )


@contextmanager
def _db(tenant_id: str) -> Iterator[Session]:
    """Open a DB session and bind the RLS tenant context before yielding."""
    with Session(_get_engine()) as db:
        set_tenant_context(db, tenant_id)
        yield db


def _actor(request: Request) -> str:
    state = getattr(request, "state", None)
    auth = getattr(state, "auth", None)
    return str(
        getattr(state, "portal_client_id", None)
        or getattr(auth, "key_db_id", None)
        or getattr(state, "key_prefix", None)
        or _ACTOR_UNKNOWN
    )


@portal_remediation_router.get(
    "",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalDashboardResponse,
)
def portal_remediation_dashboard(request: Request) -> PortalDashboardResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        return PortalRemediationEngine(db, tenant_id=tenant_id).get_dashboard()


@portal_remediation_router.get(
    "/tasks/{task_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalTaskView,
)
def portal_get_task(task_id: str, request: Request) -> PortalTaskView:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.get_task(task_id=task_id, actor=_actor(request))
            db.commit()
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


@portal_remediation_router.get(
    "/tasks/{task_id}/comments",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalCommentListResponse,
)
def portal_list_comments(
    task_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PortalCommentListResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        try:
            return PortalRemediationEngine(db, tenant_id=tenant_id).list_comments(
                task_id=task_id, limit=limit, offset=offset
            )
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@portal_remediation_router.post(
    "/tasks/{task_id}/comments",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=PortalCommentResponse,
)
def portal_add_comment(
    task_id: str, body: AddCommentRequest, request: Request
) -> PortalCommentResponse | JSONResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.add_comment(
                task_id=task_id, request=body, actor=_actor(request)
            )
            db.commit()
        except PortalRateLimitExceeded as exc:
            db.commit()
            return _rate_limited(exc)
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


@portal_remediation_router.patch(
    "/tasks/{task_id}/comments/{comment_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=PortalCommentResponse,
)
def portal_edit_comment(
    task_id: str, comment_id: str, body: EditCommentRequest, request: Request
) -> PortalCommentResponse | JSONResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.edit_comment(
                task_id=task_id,
                comment_id=comment_id,
                request=body,
                actor=_actor(request),
            )
            db.commit()
        except PortalRateLimitExceeded as exc:
            db.commit()
            return _rate_limited(exc)
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except PortalCommentNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


@portal_remediation_router.get(
    "/tasks/{task_id}/evidence",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalEvidenceListResponse,
)
def portal_list_evidence(
    task_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PortalEvidenceListResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        try:
            return PortalRemediationEngine(db, tenant_id=tenant_id).list_evidence(
                task_id=task_id, limit=limit, offset=offset
            )
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@portal_remediation_router.post(
    "/tasks/{task_id}/evidence",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=PortalEvidenceResponse,
)
def portal_submit_evidence(
    task_id: str, body: SubmitEvidenceRequest, request: Request
) -> PortalEvidenceResponse | JSONResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.submit_evidence(
                task_id=task_id, request=body, actor=_actor(request)
            )
            db.commit()
        except PortalRateLimitExceeded as exc:
            db.commit()
            return _rate_limited(exc)
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except PortalEvidenceDuplicate as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    return result


@portal_remediation_router.post(
    "/tasks/{task_id}/acknowledge",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=AcknowledgeOwnershipResponse,
)
def portal_acknowledge_ownership(
    task_id: str, body: AcknowledgeOwnershipRequest, request: Request
) -> AcknowledgeOwnershipResponse | JSONResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.acknowledge_ownership(
                task_id=task_id, request=body, actor=_actor(request)
            )
            db.commit()
        except PortalRateLimitExceeded as exc:
            db.commit()
            return _rate_limited(exc)
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


@portal_remediation_router.get(
    "/tasks/{task_id}/audit",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalAuditListResponse,
)
def portal_get_audit(
    task_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PortalAuditListResponse:
    tenant_id = require_bound_tenant(request)
    with _db(tenant_id) as db:
        try:
            return PortalRemediationEngine(db, tenant_id=tenant_id).get_portal_audit(
                task_id=task_id, limit=limit, offset=offset
            )
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
