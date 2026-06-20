# api/remediation.py
"""Remediation Management API router.

PR 13.1 — Remediation Management Foundation.
PR 13.2 — Remediation Status Workflow Engine.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through RemediationEngine
  - All status transitions enforced by RemediationEngine.validate_transition()
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.remediation.engine import RemediationEngine
from services.remediation.schemas import (
    AllowedTransitionsResponse,
    AssignOwnerRequest,
    AuditListResponse,
    CreateTaskRequest,
    RemediationConflict,
    RemediationInvalidTransition,
    RemediationNotFound,
    RemediationOwnershipError,
    RemediationReferenceError,
    RemediationTenantViolation,
    SetDueDateRequest,
    SlaResponse,
    TaskListResponse,
    TaskResponse,
    TimelineListResponse,
    TransitionResponse,
    TransitionTaskRequest,
    UnassignRequest,
    UpdateTaskRequest,
)


class AcknowledgeNotificationRequest(BaseModel):
    actor: str


router = APIRouter(tags=["remediation"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    """Extract actor identifier from auth context for audit records."""
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# POST /remediation/tasks
# ---------------------------------------------------------------------------


@router.post(
    "/remediation/tasks",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TaskResponse,
)
def create_remediation_task(
    body: CreateTaskRequest,
    request: Request,
) -> TaskResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.create_task(request=body, actor=_actor(request))
            db.commit()
        except RemediationReferenceError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except RemediationTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# GET /remediation/tasks/overdue  — MUST be before /{task_id}
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks/overdue",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TaskListResponse,
)
def list_overdue_remediation_tasks(
    request: Request,
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> TaskListResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        return engine.list_overdue_tasks(limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# GET /remediation/tasks/unassigned  — MUST be before /{task_id}
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks/unassigned",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TaskListResponse,
)
def list_unassigned_remediation_tasks(
    request: Request,
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> TaskListResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        return engine.list_unassigned_tasks(limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# GET /remediation/tasks/{task_id}
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks/{task_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TaskResponse,
)
def get_remediation_task(
    task_id: str,
    request: Request,
) -> TaskResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            return engine.get_task(task_id=task_id)
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /remediation/tasks
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TaskListResponse,
)
def list_remediation_tasks(
    request: Request,
    finding_id: str | None = Query(default=None),
    assessment_id: str | None = Query(default=None),
    task_status: str | None = Query(default=None, alias="status"),
    priority: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> TaskListResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        return engine.list_tasks(
            finding_id=finding_id,
            assessment_id=assessment_id,
            status=task_status,
            priority=priority,
            limit=limit,
            offset=offset,
        )


# ---------------------------------------------------------------------------
# PATCH /remediation/tasks/{task_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/remediation/tasks/{task_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TaskResponse,
)
def update_remediation_task(
    task_id: str,
    body: UpdateTaskRequest,
    request: Request,
) -> TaskResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.update_task(
                task_id=task_id,
                request=body,
                actor=_actor(request),
            )
            db.commit()
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# POST /remediation/tasks/{task_id}/transition  (PR 13.2)
# ---------------------------------------------------------------------------


@router.post(
    "/remediation/tasks/{task_id}/transition",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TransitionResponse,
)
def transition_remediation_task(
    task_id: str,
    body: TransitionTaskRequest,
    request: Request,
) -> TransitionResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.transition_status(
                task_id=task_id,
                request=body,
                actor=_actor(request),
            )
            db.commit()
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RemediationInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# GET /remediation/tasks/{task_id}/allowed-transitions  (PR 13.2)
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks/{task_id}/allowed-transitions",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AllowedTransitionsResponse,
)
def get_allowed_transitions(
    task_id: str,
    request: Request,
) -> AllowedTransitionsResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            return engine.get_allowed_transitions(task_id=task_id)
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /remediation/tasks/{task_id}/close
# ---------------------------------------------------------------------------


@router.post(
    "/remediation/tasks/{task_id}/close",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TaskResponse,
)
def close_remediation_task(
    task_id: str,
    request: Request,
) -> TaskResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.close_task(task_id=task_id, actor=_actor(request))
            db.commit()
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RemediationConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except RemediationInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# DELETE /remediation/tasks/{task_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/remediation/tasks/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def delete_remediation_task(
    task_id: str,
    request: Request,
) -> None:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            engine.delete_task(task_id=task_id, actor=_actor(request))
            db.commit()
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /remediation/tasks/{task_id}/audit  (PR 13.3 — used in new tests)
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks/{task_id}/audit",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AuditListResponse,
)
def get_remediation_task_audit(
    task_id: str,
    request: Request,
) -> AuditListResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        return engine.get_task_audit_trail(task_id=task_id)


# ---------------------------------------------------------------------------
# POST /remediation/tasks/{task_id}/assign  (PR 13.3)
# ---------------------------------------------------------------------------


@router.post(
    "/remediation/tasks/{task_id}/assign",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TaskResponse,
)
def assign_remediation_task_owner(
    task_id: str,
    body: AssignOwnerRequest,
    request: Request,
) -> TaskResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.assign_owner(
                task_id=task_id,
                request=body,
                actor=_actor(request),
            )
            db.commit()
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# POST /remediation/tasks/{task_id}/unassign  (PR 13.3)
# ---------------------------------------------------------------------------


@router.post(
    "/remediation/tasks/{task_id}/unassign",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TaskResponse,
)
def unassign_remediation_task_owner(
    task_id: str,
    body: UnassignRequest,
    request: Request,
) -> TaskResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.remove_owner(
                task_id=task_id,
                request=body,
                actor=_actor(request),
            )
            db.commit()
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RemediationOwnershipError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# POST /remediation/tasks/{task_id}/due-date  (PR 13.3)
# ---------------------------------------------------------------------------


@router.post(
    "/remediation/tasks/{task_id}/due-date",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TaskResponse,
)
def set_remediation_task_due_date(
    task_id: str,
    body: SetDueDateRequest,
    request: Request,
) -> TaskResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            result = engine.set_due_date(
                task_id=task_id,
                request=body,
                actor=_actor(request),
            )
            db.commit()
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# GET /remediation/tasks/{task_id}/sla  (PR 13.3)
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks/{task_id}/sla",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SlaResponse,
)
def get_remediation_task_sla(
    task_id: str,
    request: Request,
) -> SlaResponse:
    tenant_id = require_bound_tenant(request)
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        engine = RemediationEngine(db, tenant_id=tenant_id)
        try:
            return engine.get_sla(task_id=task_id)
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /remediation/tasks/{task_id}/timeline  (PR 13.7)
# MUST be before /{task_id} — already fine as a sub-path
# ---------------------------------------------------------------------------


@router.get(
    "/remediation/tasks/{task_id}/timeline",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TimelineListResponse,
)
def get_remediation_task_timeline(
    task_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
) -> TimelineListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        from services.remediation.timeline import UnifiedTimelineEngine

        try:
            return UnifiedTimelineEngine(db, tenant_id=tenant_id).get_timeline(
                task_id=task_id,
                limit=limit,
                offset=offset,
                event_type=event_type,
                source=source,
                since=since,
                until=until,
            )
        except RemediationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /remediation/tasks/{task_id}/notifications/{notification_id}/acknowledge  (PR 13.7)
# ---------------------------------------------------------------------------


@router.post(
    "/remediation/tasks/{task_id}/notifications/{notification_id}/acknowledge",
    dependencies=[Depends(require_scopes("governance:write"))],
)
def acknowledge_notification(
    task_id: str,
    notification_id: str,
    body: AcknowledgeNotificationRequest,
    request: Request,
) -> dict:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        from services.notifications.engine import NotificationEngine
        from services.notifications.schemas import NotificationNotFound

        try:
            notification = NotificationEngine(db, tenant_id=tenant_id).acknowledge(
                notification_id=notification_id, actor=body.actor
            )
            db.commit()
            return {
                "notification_id": notification.id,
                "delivery_status": notification.delivery_status,
                "acknowledged_at": notification.acknowledged_at,
            }
        except NotificationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
