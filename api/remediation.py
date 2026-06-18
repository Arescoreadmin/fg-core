# api/remediation.py
"""Remediation Management API router.

PR 13.1 — Remediation Management Foundation.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through RemediationEngine
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.remediation.engine import RemediationEngine
from services.remediation.schemas import (
    AuditEventResponse,
    CreateTaskRequest,
    RemediationConflict,
    RemediationNotFound,
    RemediationReferenceError,
    RemediationTenantViolation,
    TaskListResponse,
    TaskResponse,
    UpdateTaskRequest,
)

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
