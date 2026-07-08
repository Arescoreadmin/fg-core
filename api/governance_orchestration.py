# api/governance_orchestration.py
"""Continuous Governance Orchestration Authority API - PR 18.4.

All routes are tenant-scoped except ``/governance-orchestration/health``.
Tenant is resolved from auth context only (never from request body).

Security invariants:
  - ``tenant_id`` always from ``require_bound_tenant(request)``.
  - Every handler calls ``set_tenant_context(db, tenant_id)`` immediately
    after opening the session so RLS is bound before any engine call.
  - No direct ORM access — everything routes through
    ``GovernanceOrchestrationEngine``.
  - Caller (this router) owns ``db.commit()``.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine, set_tenant_context
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.schemas import (
    ApprovalListResponse,
    ApprovalResponse,
    ApproveRequest,
    ChangeDetectionListResponse,
    ChangeDetectionResponse,
    CreateChangeDetectionRequest,
    CreateMaintenanceWindowRequest,
    CreatePlaybookRequest,
    CreatePolicyRequest,
    CreateReassessmentRequest,
    CreateSimulationRequest,
    CreateTriggerRequest,
    CreateWorkflowRequest,
    DashboardResponse,
    GovernanceOrchestrationApprovalError,
    GovernanceOrchestrationConflict,
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationPolicyViolation,
    GovernanceOrchestrationSimulationError,
    GovernanceOrchestrationTenantViolation,
    GovernanceOrchestrationValidationError,
    GovernanceOrchestrationWorkflowError,
    HealthResponse,
    HistoryResponse,
    ImpactAnalysisResponse,
    MaintenanceWindowListResponse,
    MaintenanceWindowResponse,
    PlaybookListResponse,
    PlaybookResponse,
    PolicyListResponse,
    PolicyResponse,
    ReassessmentListResponse,
    ReassessmentResponse,
    SearchResponse,
    SimulationListResponse,
    SimulationResponse,
    StatisticsResponse,
    TimelineResponse,
    TriggerListResponse,
    TriggerResponse,
    UpdatePolicyRequest,
    WorkflowListResponse,
    WorkflowResponse,
)


router = APIRouter(tags=["governance-orchestration"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _map_domain_error(exc: Exception) -> HTTPException:
    if isinstance(exc, GovernanceOrchestrationNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationTenantViolation):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationInvalidTransition):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationPolicyViolation):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationApprovalError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationWorkflowError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationSimulationError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, GovernanceOrchestrationValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Health (public)
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/health",
    response_model=HealthResponse,
)
def governance_orchestration_health() -> HealthResponse:
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, "__health__")
        svc = GovernanceOrchestrationEngine(db, tenant_id="__health__")
        return svc.health()


# ---------------------------------------------------------------------------
# Dashboard / statistics / search / timeline / history / impact
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=DashboardResponse,
)
def get_dashboard(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> DashboardResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_dashboard()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/statistics",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=StatisticsResponse,
)
def get_statistics(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> StatisticsResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_statistics()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/search",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SearchResponse,
)
def search(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    q: str = Query(..., min_length=1, max_length=512),
) -> SearchResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.search(q)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/timeline",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TimelineResponse,
)
def get_timeline(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    entity_type: Optional[str] = Query(default=None),
    entity_id: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> TimelineResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_timeline(
                entity_type=entity_type,
                entity_id=entity_id,
                offset=offset,
                limit=limit,
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/history",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=HistoryResponse,
)
def get_history(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    entity_type: str = Query(..., min_length=1),
    entity_id: str = Query(..., min_length=1),
) -> HistoryResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_history(entity_type, entity_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/impact-analysis",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ImpactAnalysisResponse,
)
def get_impact_analysis(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    change_type: str = Query(..., min_length=1, max_length=64),
) -> ImpactAnalysisResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_impact_analysis(change_type=change_type, change_data={})
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Triggers
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/triggers",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TriggerListResponse,
)
def list_triggers(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    trigger_type: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> TriggerListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_triggers(
                trigger_type=trigger_type, offset=offset, limit=limit
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/triggers",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TriggerResponse,
    status_code=201,
)
def create_trigger(
    req: CreateTriggerRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> TriggerResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_trigger(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/triggers/{trigger_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TriggerResponse,
)
def get_trigger(
    trigger_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> TriggerResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_trigger(trigger_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/policies",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyListResponse,
)
def list_policies(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    active: Optional[bool] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> PolicyListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_policies(active=active, offset=offset, limit=limit)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/policies",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=PolicyResponse,
    status_code=201,
)
def create_policy(
    req: CreatePolicyRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> PolicyResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_policy(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/policies/{policy_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyResponse,
)
def get_policy(
    policy_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> PolicyResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_policy(policy_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.patch(
    "/governance-orchestration/policies/{policy_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=PolicyResponse,
)
def update_policy(
    policy_id: str,
    req: UpdatePolicyRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> PolicyResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.update_policy(policy_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/playbooks",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PlaybookListResponse,
)
def list_playbooks(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    playbook_type: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> PlaybookListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_playbooks(
                playbook_type=playbook_type, offset=offset, limit=limit
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/playbooks",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=PlaybookResponse,
    status_code=201,
)
def create_playbook(
    req: CreatePlaybookRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> PlaybookResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_playbook(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/playbooks/templates/{playbook_type}",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_playbook_template_route(
    playbook_type: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_playbook_template(playbook_type)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/playbooks/{playbook_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PlaybookResponse,
)
def get_playbook(
    playbook_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> PlaybookResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_playbook(playbook_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/workflows",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=WorkflowListResponse,
)
def list_workflows(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    workflow_state: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> WorkflowListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_workflows(
                workflow_state=workflow_state, offset=offset, limit=limit
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/workflows",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=WorkflowResponse,
    status_code=201,
)
def create_workflow(
    req: CreateWorkflowRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> WorkflowResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_workflow(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/workflows/{workflow_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=WorkflowResponse,
)
def get_workflow(
    workflow_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> WorkflowResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_workflow(workflow_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/workflows/{workflow_id}/advance",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=WorkflowResponse,
)
def advance_workflow(
    workflow_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    event: str = Query(..., min_length=1, max_length=64),
) -> WorkflowResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.advance_workflow(workflow_id, event, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/workflows/{workflow_id}/pause",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=WorkflowResponse,
)
def pause_workflow(
    workflow_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> WorkflowResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.pause_workflow(workflow_id, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/workflows/{workflow_id}/cancel",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=WorkflowResponse,
)
def cancel_workflow(
    workflow_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> WorkflowResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.cancel_workflow(workflow_id, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Reassessments
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/reassessments",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ReassessmentListResponse,
)
def list_reassessments(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    reassessment_state: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> ReassessmentListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_reassessments(
                reassessment_state=reassessment_state,
                offset=offset,
                limit=limit,
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/reassessments",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ReassessmentResponse,
    status_code=201,
)
def create_reassessment(
    req: CreateReassessmentRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> ReassessmentResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_reassessment(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/reassessments/{reassessment_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ReassessmentResponse,
)
def get_reassessment(
    reassessment_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> ReassessmentResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_reassessment(reassessment_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/reassessments/{reassessment_id}/schedule",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ReassessmentResponse,
)
def schedule_reassessment(
    reassessment_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    scheduled_at: str = Query(..., min_length=1, max_length=64),
) -> ReassessmentResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.schedule_reassessment(
                reassessment_id, scheduled_at, actor_id=actor
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/reassessments/{reassessment_id}/complete",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ReassessmentResponse,
)
def complete_reassessment(
    reassessment_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
    outcome: str = Query(..., min_length=1, max_length=1024),
) -> ReassessmentResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.complete_reassessment(reassessment_id, outcome, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Simulations
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/simulations",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SimulationListResponse,
)
def list_simulations(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> SimulationListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_simulations(offset=offset, limit=limit)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/simulations",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=SimulationResponse,
    status_code=201,
)
def create_simulation(
    req: CreateSimulationRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("scan.trigger")),
) -> SimulationResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_simulation(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/simulations/{simulation_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SimulationResponse,
)
def get_simulation(
    simulation_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> SimulationResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_simulation(simulation_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/change-detection",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ChangeDetectionListResponse,
)
def list_change_detection(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    change_type: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> ChangeDetectionListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_change_detections(
                change_type=change_type, offset=offset, limit=limit
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/change-detection",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ChangeDetectionResponse,
    status_code=201,
)
def create_change_detection(
    req: CreateChangeDetectionRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("scan.trigger")),
) -> ChangeDetectionResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_change_detection(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Maintenance windows
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/maintenance-windows",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=MaintenanceWindowListResponse,
)
def list_maintenance_windows(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    window_state: Optional[str] = Query(default=None),
) -> MaintenanceWindowListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_maintenance_windows(window_state=window_state)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/maintenance-windows",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=MaintenanceWindowResponse,
    status_code=201,
)
def create_maintenance_window(
    req: CreateMaintenanceWindowRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> MaintenanceWindowResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_maintenance_window(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/governance-orchestration/maintenance-windows/{window_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=MaintenanceWindowResponse,
)
def get_maintenance_window(
    window_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> MaintenanceWindowResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_maintenance_window(window_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/maintenance-windows/{window_id}/open",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=MaintenanceWindowResponse,
)
def open_maintenance_window(
    window_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> MaintenanceWindowResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.open_maintenance_window(window_id, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/maintenance-windows/{window_id}/close",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=MaintenanceWindowResponse,
)
def close_maintenance_window(
    window_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> MaintenanceWindowResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            result = svc.close_maintenance_window(window_id, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


@router.get(
    "/governance-orchestration/approvals",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ApprovalListResponse,
)
def list_approvals(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
    workflow_id: Optional[str] = Query(default=None),
    approval_state: Optional[str] = Query(default=None),
) -> ApprovalListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_approvals(
                workflow_id=workflow_id, approval_state=approval_state
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/approvals/{approval_id}/approve",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ApprovalResponse,
)
def approve_approval(
    approval_id: str,
    req: ApproveRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.promote")),
) -> ApprovalResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        # Force decision=APPROVE
        approve_req = ApproveRequest(
            decision="APPROVE",
            reason=req.reason,
            delegated_to=None,
        )
        try:
            result = svc.approve_approval(approval_id, approve_req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/approvals/{approval_id}/reject",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ApprovalResponse,
)
def reject_approval(
    approval_id: str,
    req: ApproveRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.promote")),
) -> ApprovalResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        reject_req = ApproveRequest(
            decision="REJECT",
            reason=req.reason,
            delegated_to=None,
        )
        try:
            result = svc.approve_approval(approval_id, reject_req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/governance-orchestration/approvals/{approval_id}/delegate",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ApprovalResponse,
)
def delegate_approval(
    approval_id: str,
    req: ApproveRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.promote")),
) -> ApprovalResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceOrchestrationEngine(db, tenant_id=tenant_id)
        if not req.delegated_to:
            raise HTTPException(status_code=400, detail="delegated_to is required")
        delegate_req = ApproveRequest(
            decision="DELEGATE",
            reason=req.reason,
            delegated_to=req.delegated_to,
        )
        try:
            result = svc.approve_approval(approval_id, delegate_req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)
