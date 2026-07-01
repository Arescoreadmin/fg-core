# api/remediation_authority.py
"""Enterprise Remediation Authority API - PR 18.3.

All routes are tenant-scoped except ``/remediation-authority/health``.
Tenant is resolved from auth context only (never from request body).

Security invariants:
  - ``tenant_id`` always from ``require_bound_tenant(request)``.
  - Every handler calls ``set_tenant_context(db, tenant_id)`` immediately
    after opening the session so RLS is bound before any engine call.
  - No handler bypasses tenant checks, scope checks, or timeline writes.
  - No direct ORM access - everything routes through
    ``RemediationAuthorityEngine``.
  - Caller (this router) owns ``db.commit()``.

The prefix ``/remediation-authority/`` is deliberately distinct from the
existing ``/remediation`` router which serves a different subsystem.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine, set_tenant_context
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.schemas import (
    AssignmentListResponse,
    AssignmentResponse,
    CreateAssignmentRequest,
    CreateDependencyRequest,
    CreatePlanRequest,
    CreateTaskRequest,
    CreateVerificationRequest,
    DashboardResponse,
    DependencyListResponse,
    DependencyResponse,
    ForecastResponse,
    HealthResponse,
    HistoryResponse,
    PlanListResponse,
    PlanResponse,
    RemediationAssignmentError,
    RemediationConflict,
    RemediationDependencyError,
    RemediationImmutableState,
    RemediationInvalidTransition,
    RemediationNotFound,
    RemediationTenantViolation,
    RemediationValidationError,
    RemediationVerificationError,
    RiskResponse,
    SearchResponse,
    StatisticsResponse,
    TaskListResponse,
    TaskResponse,
    TimelineResponse,
    TransitionTaskRequest,
    UpdatePlanRequest,
    UpdateTaskRequest,
    VerificationListResponse,
    VerificationResponse,
)


router = APIRouter(tags=["remediation-authority"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _map_domain_error(exc: Exception) -> HTTPException:
    """Map a domain exception to an HTTPException with the right status."""
    if isinstance(exc, RemediationNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, RemediationTenantViolation):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, RemediationConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, RemediationImmutableState):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, RemediationInvalidTransition):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, RemediationDependencyError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RemediationAssignmentError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RemediationVerificationError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RemediationValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Health (public, must precede parametric routes)
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-authority/health",
    response_model=HealthResponse,
)
def remediation_authority_health() -> HealthResponse:
    """Public liveness probe for the Remediation Authority."""
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, "__health__")
        svc = RemediationAuthorityEngine(db, tenant_id="__health__")
        return svc.health()


# ---------------------------------------------------------------------------
# Plans (static paths first)
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-authority/plans",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=PlanListResponse,
)
def list_plans(
    request: Request,
    plan_state: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> PlanListResponse:
    """List remediation plans for the tenant."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.list_plans(plan_state=plan_state, offset=offset, limit=limit)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/remediation-authority/plans",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=PlanResponse,
    status_code=201,
)
def create_plan(req: CreatePlanRequest, request: Request) -> PlanResponse:
    """Create a new remediation plan."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_plan(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/plans/{plan_id}",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=PlanResponse,
)
def get_plan(plan_id: str, request: Request) -> PlanResponse:
    """Return a single remediation plan."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_plan(plan_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.patch(
    "/remediation-authority/plans/{plan_id}",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=PlanResponse,
)
def update_plan(plan_id: str, req: UpdatePlanRequest, request: Request) -> PlanResponse:
    """Partially update a remediation plan."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.update_plan(plan_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-authority/tasks",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=TaskListResponse,
)
def list_tasks(
    request: Request,
    plan_id: Optional[str] = Query(default=None),
    task_state: Optional[str] = Query(default=None),
    priority: Optional[str] = Query(default=None),
    owner_id: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> TaskListResponse:
    """List remediation tasks with optional filters."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_tasks(
                plan_id=plan_id,
                task_state=task_state,
                priority=priority,
                owner_id=owner_id,
                offset=offset,
                limit=limit,
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/remediation-authority/tasks",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=TaskResponse,
    status_code=201,
)
def create_task(req: CreateTaskRequest, request: Request) -> TaskResponse:
    """Create a new remediation task."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_task(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/tasks/{task_id}",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=TaskResponse,
)
def get_task(task_id: str, request: Request) -> TaskResponse:
    """Return a single remediation task."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_task(task_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.patch(
    "/remediation-authority/tasks/{task_id}",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=TaskResponse,
)
def update_task(task_id: str, req: UpdateTaskRequest, request: Request) -> TaskResponse:
    """Partially update a remediation task."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.update_task(task_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/remediation-authority/tasks/{task_id}/transition",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=TaskResponse,
)
def transition_task(
    task_id: str, req: TransitionTaskRequest, request: Request
) -> TaskResponse:
    """Transition a remediation task to a new state."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.transition_task(task_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/tasks/{task_id}/timeline",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=TimelineResponse,
)
def get_task_timeline(task_id: str, request: Request) -> TimelineResponse:
    """Return the append-only timeline events for a task."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_timeline(task_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/tasks/{task_id}/history",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=HistoryResponse,
)
def get_task_history(task_id: str, request: Request) -> HistoryResponse:
    """Return the state history for a task."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_history(task_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-authority/assignments",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=AssignmentListResponse,
)
def list_assignments(
    request: Request,
    task_id: Optional[str] = Query(default=None),
) -> AssignmentListResponse:
    """List assignments (optionally filtered by task)."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_assignments(task_id=task_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/remediation-authority/assignments",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=AssignmentResponse,
    status_code=201,
)
def create_assignment(
    req: CreateAssignmentRequest, request: Request
) -> AssignmentResponse:
    """Create an assignment for a task."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_assignment(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-authority/dependencies",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=DependencyListResponse,
)
def list_dependencies(request: Request) -> DependencyListResponse:
    """List dependency edges for the tenant."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_dependencies()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/remediation-authority/dependencies",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=DependencyResponse,
    status_code=201,
)
def create_dependency(
    req: CreateDependencyRequest, request: Request
) -> DependencyResponse:
    """Create a dependency edge between two tasks."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_dependency(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.delete(
    "/remediation-authority/dependencies/{dep_id}",
    dependencies=[Depends(require_scopes("remediation:write"))],
    status_code=204,
)
def delete_dependency(dep_id: str, request: Request) -> None:
    """Delete a dependency edge."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            svc.delete_dependency(dep_id, actor_id=actor)
            db.commit()
            return None
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Verifications
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-authority/verification",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=VerificationListResponse,
)
def list_verifications(
    request: Request,
    task_id: Optional[str] = Query(default=None),
) -> VerificationListResponse:
    """List verification records (optionally filtered by task)."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_verifications(task_id=task_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/remediation-authority/verification",
    dependencies=[Depends(require_scopes("remediation:write"))],
    response_model=VerificationResponse,
    status_code=201,
)
def create_verification(
    req: CreateVerificationRequest, request: Request
) -> VerificationResponse:
    """Record a verification event against a task."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_verification(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Aggregates: statistics, forecast, risk, search, dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-authority/statistics",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=StatisticsResponse,
)
def get_statistics(request: Request) -> StatisticsResponse:
    """Return aggregate statistics for the tenant."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_statistics()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/forecast",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=ForecastResponse,
)
def get_forecast(
    request: Request,
    horizon_days: int = Query(default=30, ge=1, le=365),
) -> ForecastResponse:
    """Return a deterministic forecast for the tenant."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_forecast(horizon_days=horizon_days)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/risk",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=RiskResponse,
)
def get_risk(request: Request) -> RiskResponse:
    """Return the risk reduction summary for the tenant."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_risk()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/search",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=SearchResponse,
)
def search_tasks(
    request: Request,
    q: str = Query(..., min_length=1, max_length=512),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> SearchResponse:
    """Search remediation tasks by title/description."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.search_tasks(q, offset=offset, limit=limit)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/remediation-authority/dashboard",
    dependencies=[Depends(require_scopes("remediation:read"))],
    response_model=DashboardResponse,
)
def get_dashboard(request: Request) -> DashboardResponse:
    """Return the portfolio-wide dashboard for the tenant."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = RemediationAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_dashboard()
        except Exception as exc:
            raise _map_domain_error(exc)
