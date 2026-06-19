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
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
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
    PortalTaskView,
    SubmitEvidenceRequest,
)

portal_remediation_router = APIRouter(
    prefix="/portal/remediation",
    tags=["portal-remediation"],
)

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    state = getattr(request, "state", None)
    return str(
        getattr(state, "portal_client_id", None)
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
    with Session(get_engine()) as db:
        return PortalRemediationEngine(db, tenant_id=tenant_id).get_dashboard()


@portal_remediation_router.get(
    "/tasks/{task_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalTaskView,
)
def portal_get_task(task_id: str, request: Request) -> PortalTaskView:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
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
def portal_list_comments(task_id: str, request: Request) -> PortalCommentListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        try:
            return PortalRemediationEngine(db, tenant_id=tenant_id).list_comments(
                task_id=task_id
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
) -> PortalCommentResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.add_comment(
                task_id=task_id, request=body, actor=_actor(request)
            )
            db.commit()
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
) -> PortalCommentResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.edit_comment(
                task_id=task_id,
                comment_id=comment_id,
                request=body,
                actor=_actor(request),
            )
            db.commit()
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
def portal_list_evidence(task_id: str, request: Request) -> PortalEvidenceListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        try:
            return PortalRemediationEngine(db, tenant_id=tenant_id).list_evidence(
                task_id=task_id
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
) -> PortalEvidenceResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.submit_evidence(
                task_id=task_id, request=body, actor=_actor(request)
            )
            db.commit()
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
) -> AcknowledgeOwnershipResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        engine = PortalRemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.acknowledge_ownership(
                task_id=task_id, request=body, actor=_actor(request)
            )
            db.commit()
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


@portal_remediation_router.get(
    "/tasks/{task_id}/audit",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PortalAuditListResponse,
)
def portal_get_audit(task_id: str, request: Request) -> PortalAuditListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        try:
            return PortalRemediationEngine(db, tenant_id=tenant_id).get_portal_audit(
                task_id=task_id
            )
        except PortalNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
