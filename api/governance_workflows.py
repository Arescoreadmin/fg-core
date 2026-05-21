"""Autonomous Governance Workflow Engine API.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Deterministic workflow lifecycle management — no AI-generated workflows.
Every workflow is created from a named template. Routing, state transitions,
and evidence requirements are all deterministic.

Routes:
  POST  /governance/workflows                       — governance:write — create
  GET   /governance/workflows                       — governance:read  — list
  PATCH /governance/workflows/{id}/transition       — governance:write — advance state
  POST  /governance/workflows/{id}/evidence         — governance:write — attach evidence
  GET   /governance/workflows/{id}/audit            — governance:read  — audit trail

Scopes:
  governance:read  — all read endpoints
  governance:write — create, transition, evidence
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.governance_workflows import engine as wf_engine
from services.governance_workflows.evidence import (
    InvalidEvidenceType,
    WorkflowEvidenceDuplicate,
    attach_workflow_evidence,
    get_evidence_for_workflow,
)
from services.governance_workflows.templates import list_templates

log = logging.getLogger("frostgate.api.governance_workflows")

router = APIRouter(
    prefix="/governance/workflows",
    tags=["governance-workflows"],
)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _resolve_caller_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tid = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tid)


def _resolve_caller_actor(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    return getattr(auth, "email", None) or getattr(auth, "sub", None) or "api"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CreateWorkflowBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement_id: str = Field(..., min_length=1, max_length=64)
    template_name: str = Field(..., min_length=1, max_length=64)
    context_ref_type: str = Field(..., min_length=1, max_length=64)
    context_ref_id: str = Field(..., min_length=1, max_length=512)
    severity: str = Field("medium", min_length=1, max_length=32)
    title: str | None = Field(None, max_length=512)
    description: str | None = Field(None, max_length=4096)


class TransitionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: str = Field(..., min_length=1, max_length=32)
    reason: str = Field(..., min_length=1, max_length=1024)


class AttachEvidenceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_type: str = Field(..., min_length=1, max_length=64)
    reference: str = Field(..., min_length=1, max_length=2048)


class WorkflowResponse(BaseModel):
    id: str
    tenant_id: str
    engagement_id: str
    template_name: str
    title: str
    description: str
    state: str
    priority: str
    assigned_to_role: str
    context_ref_type: str
    context_ref_id: str
    due_at: str
    created_by: str
    created_at: str
    updated_at: str
    resolved_at: str | None
    archived_at: str | None
    schema_version: str


class EvidenceResponse(BaseModel):
    id: str
    workflow_id: str
    evidence_type: str
    reference: str
    submitted_by: str
    created_at: str


class AuditEventResponse(BaseModel):
    id: str
    event_type: str
    actor: str
    reason_code: str
    payload: dict[str, Any]
    created_at: str


class TemplateResponse(BaseModel):
    name: str
    description: str
    required_evidence_types: list[str]
    default_priority: str
    escalation_after_days: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wf_to_response(wf: Any) -> WorkflowResponse:
    return WorkflowResponse(
        id=wf.id,
        tenant_id=wf.tenant_id,
        engagement_id=wf.engagement_id,
        template_name=wf.template_name,
        title=wf.title,
        description=wf.description,
        state=wf.state,
        priority=wf.priority,
        assigned_to_role=wf.assigned_to_role,
        context_ref_type=wf.context_ref_type,
        context_ref_id=wf.context_ref_id,
        due_at=wf.due_at,
        created_by=wf.created_by,
        created_at=wf.created_at,
        updated_at=wf.updated_at,
        resolved_at=wf.resolved_at,
        archived_at=wf.archived_at,
        schema_version=wf.schema_version,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/templates",
    response_model=list[TemplateResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_workflow_templates(request: Request) -> list[TemplateResponse]:
    """List all available workflow templates."""
    _resolve_caller_tenant(request)
    return [
        TemplateResponse(
            name=t.name,
            description=t.description,
            required_evidence_types=list(t.required_evidence_types),
            default_priority=t.default_priority,
            escalation_after_days=t.escalation_after_days,
        )
        for t in list_templates()
    ]


@router.post(
    "",
    response_model=WorkflowResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_workflow(
    body: CreateWorkflowBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> WorkflowResponse:
    """Create a new governance workflow from a named template."""
    tenant_id = _resolve_caller_tenant(request)
    actor = _resolve_caller_actor(request)
    try:
        wf = wf_engine.create_workflow(
            db,
            tenant_id=tenant_id,
            engagement_id=body.engagement_id,
            template_name=body.template_name,
            context_ref_type=body.context_ref_type,
            context_ref_id=body.context_ref_id,
            created_by=actor,
            severity=body.severity,
            title=body.title,
            description=body.description,
        )
        db.commit()
    except wf_engine.UnknownTemplate as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=api_error("UNKNOWN_TEMPLATE", str(exc)),
        )
    return _wf_to_response(wf)


@router.get(
    "",
    response_model=list[WorkflowResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_workflows(
    request: Request,
    engagement_id: str | None = Query(None),
    state: str | None = Query(None),
    limit: int = Query(100, ge=1, le=200),
    db: Session = Depends(auth_ctx_db_session),
) -> list[WorkflowResponse]:
    """List governance workflows for the caller's tenant."""
    tenant_id = _resolve_caller_tenant(request)
    workflows = wf_engine.list_workflows(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        state=state,
        limit=limit,
    )
    return [_wf_to_response(wf) for wf in workflows]


@router.patch(
    "/{workflow_id}/transition",
    response_model=WorkflowResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def transition_workflow(
    workflow_id: str,
    body: TransitionBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> WorkflowResponse:
    """Advance a workflow's state through the state machine."""
    tenant_id = _resolve_caller_tenant(request)
    actor = _resolve_caller_actor(request)
    try:
        wf = wf_engine.transition_workflow(
            db,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            to_state=body.to_state,
            actor=actor,
            reason=body.reason,
        )
        db.commit()
    except wf_engine.WorkflowNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=api_error("WORKFLOW_NOT_FOUND", str(exc)),
        )
    except wf_engine.WorkflowTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=api_error("WORKFLOW_TRANSITION_ERROR", str(exc)),
        )
    except wf_engine.WorkflowEvidenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=api_error("WORKFLOW_EVIDENCE_REQUIRED", str(exc)),
        )
    return _wf_to_response(wf)


@router.post(
    "/{workflow_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def attach_evidence(
    workflow_id: str,
    body: AttachEvidenceBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> EvidenceResponse:
    """Attach completion evidence to a workflow via FaEvidenceLink."""
    tenant_id = _resolve_caller_tenant(request)
    actor = _resolve_caller_actor(request)

    wf = wf_engine.get_workflow(db, workflow_id=workflow_id, tenant_id=tenant_id)
    if wf is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=api_error(
                "WORKFLOW_NOT_FOUND", f"workflow {workflow_id!r} not found"
            ),
        )

    try:
        link = attach_workflow_evidence(
            db,
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            engagement_id=wf.engagement_id,
            evidence_type=body.evidence_type,
            reference=body.reference,
            submitted_by=actor,
        )
        db.commit()
    except InvalidEvidenceType as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=api_error("INVALID_EVIDENCE_TYPE", str(exc)),
        )
    except WorkflowEvidenceDuplicate as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=api_error("EVIDENCE_DUPLICATE", str(exc)),
        )

    submitted_by = link.link_metadata.get("submitted_by", actor)
    return EvidenceResponse(
        id=link.id,
        workflow_id=workflow_id,
        evidence_type=link.evidence_entity_type,
        reference=link.evidence_entity_id,
        submitted_by=submitted_by,
        created_at=link.created_at,
    )


@router.get(
    "/{workflow_id}/evidence",
    response_model=list[EvidenceResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_evidence(
    workflow_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[EvidenceResponse]:
    """List all evidence attached to a workflow."""
    tenant_id = _resolve_caller_tenant(request)
    wf = wf_engine.get_workflow(db, workflow_id=workflow_id, tenant_id=tenant_id)
    if wf is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=api_error(
                "WORKFLOW_NOT_FOUND", f"workflow {workflow_id!r} not found"
            ),
        )
    links = get_evidence_for_workflow(
        db,
        workflow_id=workflow_id,
        tenant_id=tenant_id,
        engagement_id=wf.engagement_id,
    )
    return [
        EvidenceResponse(
            id=link.id,
            workflow_id=workflow_id,
            evidence_type=link.evidence_entity_type,
            reference=link.evidence_entity_id,
            submitted_by=link.link_metadata.get("submitted_by", ""),
            created_at=link.created_at,
        )
        for link in links
    ]


@router.get(
    "/{workflow_id}/audit",
    response_model=list[AuditEventResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_workflow_audit(
    workflow_id: str,
    request: Request,
    limit: int = Query(200, ge=1, le=500),
    db: Session = Depends(auth_ctx_db_session),
) -> list[AuditEventResponse]:
    """Return the full audit trail for a workflow (transitions from FaEngagementAuditEvent)."""
    tenant_id = _resolve_caller_tenant(request)
    wf = wf_engine.get_workflow(db, workflow_id=workflow_id, tenant_id=tenant_id)
    if wf is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=api_error(
                "WORKFLOW_NOT_FOUND", f"workflow {workflow_id!r} not found"
            ),
        )
    events = wf_engine.get_workflow_audit(
        db, workflow_id=workflow_id, tenant_id=tenant_id, limit=limit
    )
    return [
        AuditEventResponse(
            id=e.id,
            event_type=e.event_type,
            actor=e.actor,
            reason_code=e.reason_code,
            payload=e.payload,
            created_at=e.created_at,
        )
        for e in events
    ]
