"""Provisioning Manager API — operator-safe tenant provisioning lifecycle endpoints.

All routes require control-plane:read (read) or control-plane:admin (write).
Tenant isolation: tenant_id is always resolved from auth context, never from
the request body. Platform-level records (tenant_id=None) are readable by any
sufficiently-scoped operator.

Routes are under /control-plane/provisioning/ — covered by the existing
"control" plane route prefix and its governance gates.

Security invariants:
- No secrets, credentials, or infrastructure topology in any response.
- tenant_id from auth context only (never from request body).
- All mutations are audit-logged (ProvisioningAuditEventRecord) before returning.
- State transitions validated against VALID_ORG_TRANSITIONS before DB write.
- Activation gate enforced: all preconditions checked atomically.
- All list endpoints are page-capped at 200 rows.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.provisioning import (
    ComplianceClassification,
    DeploymentTier,
    FailureCategory,
    OrgLifecycleStatus,
    ProvisioningStore,
)
from services.provisioning.store import (
    ActivationPreconditionFailed,
    ConcurrentModificationError,
    DuplicateSlug,
    InvalidOrgTransition,
    OrgNotFound,
    ProvisioningStoreError,
    WorkflowNotFound,
    WorkflowTransitionError,
)

log = logging.getLogger("frostgate.provisioning")
router = APIRouter(tags=["provisioning"])

_store = ProvisioningStore()

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

ERR_ORG_NOT_FOUND = "PROV-API-001"
ERR_WORKFLOW_NOT_FOUND = "PROV-API-002"
ERR_INVALID_TRANSITION = "PROV-API-003"
ERR_ACTIVATION_BLOCKED = "PROV-API-004"
ERR_INVALID_INPUT = "PROV-API-005"
ERR_FORBIDDEN = "PROV-API-006"
ERR_CONCURRENT_MODIFICATION = "PROV-API-007"
ERR_DUPLICATE_SLUG = "PROV-API-008"
ERR_DUPLICATE_IDEMPOTENCY = "PROV-API-009"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tenant_from_auth(request: Request) -> Optional[str]:
    """Resolve tenant_id from auth context. Never from request body."""
    auth = getattr(getattr(request, "state", None), "auth", None)
    return getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )


def _actor_from_request(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    prefix = getattr(auth, "key_prefix", None)
    return str(prefix) if prefix else "unknown"


def _handle_store_error(exc: ProvisioningStoreError) -> HTTPException:
    if isinstance(exc, OrgNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_ORG_NOT_FOUND, exc.message)
        )
    if isinstance(exc, WorkflowNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_WORKFLOW_NOT_FOUND, exc.message)
        )
    if isinstance(exc, InvalidOrgTransition):
        return HTTPException(
            status_code=409, detail=api_error(ERR_INVALID_TRANSITION, exc.message)
        )
    if isinstance(exc, WorkflowTransitionError):
        return HTTPException(
            status_code=409, detail=api_error(ERR_INVALID_TRANSITION, exc.message)
        )
    if isinstance(exc, ActivationPreconditionFailed):
        return HTTPException(
            status_code=422, detail=api_error(ERR_ACTIVATION_BLOCKED, exc.message)
        )
    if isinstance(exc, ConcurrentModificationError):
        return HTTPException(
            status_code=409,
            detail=api_error(ERR_CONCURRENT_MODIFICATION, exc.message),
        )
    if isinstance(exc, DuplicateSlug):
        return HTTPException(
            status_code=409, detail=api_error(ERR_DUPLICATE_SLUG, exc.message)
        )
    return HTTPException(
        status_code=500,
        detail=api_error("PROV-API-500", "Internal provisioning error"),
    )


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

_ORG_NAME_MAX = 256
_SLUG_MAX = 128
_REASON_MAX = 512
_META_KEYS_MAX = 20
_SLUG_PATTERN = r"^[a-z0-9][a-z0-9\-]{0,126}[a-z0-9]$|^[a-z0-9]$"


class CreateOrgRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_name: str = Field(..., min_length=1, max_length=_ORG_NAME_MAX)
    slug: str = Field(..., min_length=1, max_length=_SLUG_MAX, pattern=_SLUG_PATTERN)
    compliance_classification: ComplianceClassification = (
        ComplianceClassification.STANDARD
    )
    deployment_tier: DeploymentTier = DeploymentTier.SHARED
    region: Optional[str] = Field(default=None, max_length=128)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _meta_bounded(cls, v: dict) -> dict:
        if len(v) > _META_KEYS_MAX:
            raise ValueError(f"metadata may not exceed {_META_KEYS_MAX} keys")
        return v


class StartProvisioningRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    env_target: Optional[str] = Field(default=None, max_length=128)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _meta_bounded(cls, v: dict) -> dict:
        if len(v) > _META_KEYS_MAX:
            raise ValueError(f"metadata may not exceed {_META_KEYS_MAX} keys")
        return v


class CompleteWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_results: dict[str, Any] = Field(default_factory=dict)

    @field_validator("validation_results")
    @classmethod
    def _results_bounded(cls, v: dict) -> dict:
        if len(v) > _META_KEYS_MAX:
            raise ValueError(f"validation_results may not exceed {_META_KEYS_MAX} keys")
        return v


class FailWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    failure_reason: str = Field(..., min_length=1, max_length=_REASON_MAX)
    failure_category: FailureCategory = FailureCategory.TERMINAL


class RetryWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    env_target: Optional[str] = Field(default=None, max_length=128)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)


class SuspendOrgRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Optional[str] = Field(default=None, max_length=_REASON_MAX)


class AssignEnvironmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    env_assignment_id: str = Field(..., min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# Response serializers
# ---------------------------------------------------------------------------


def _org_response(org: Any) -> dict[str, Any]:
    """Shared serializer for org records. No secrets exposed."""
    return {
        "organization_id": org.organization_id,
        "org_name": org.org_name,
        "slug": org.slug,
        "lifecycle_status": org.lifecycle_status.value,
        "compliance_classification": org.compliance_classification.value,
        "deployment_tier": org.deployment_tier.value,
        "onboarding_state": org.onboarding_state.value,
        "tenant_id": org.tenant_id,
        "env_assignment_id": org.env_assignment_id,
        "region": org.region,
        "state_version": org.state_version,
        "created_by": org.created_by,
        "created_at": org.created_at.isoformat(),
        "updated_at": org.updated_at.isoformat(),
        "activated_at": org.activated_at.isoformat() if org.activated_at else None,
        "suspended_at": org.suspended_at.isoformat() if org.suspended_at else None,
        "archived_at": org.archived_at.isoformat() if org.archived_at else None,
    }


def _workflow_response(wf: Any) -> dict[str, Any]:
    """Shared serializer for workflow records. No secrets exposed."""
    return {
        "provisioning_id": wf.provisioning_id,
        "organization_id": wf.organization_id,
        "tenant_id": wf.tenant_id,
        "workflow_state": wf.workflow_state.value,
        "current_step": wf.current_step,
        "env_target": wf.env_target,
        "retry_count": wf.retry_count,
        "max_retries": wf.max_retries,
        "failure_reason": wf.failure_reason,
        "failure_category": wf.failure_category.value if wf.failure_category else None,
        "state_version": wf.state_version,
        "initiated_by": wf.initiated_by,
        "started_at": wf.started_at.isoformat(),
        "completed_at": wf.completed_at.isoformat() if wf.completed_at else None,
        "last_updated_at": wf.last_updated_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Organization endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/provisioning/organizations",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_organizations(
    request: Request,
    lifecycle_status: Optional[OrgLifecycleStatus] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    orgs = _store.list_organizations(
        db,
        tenant_id=tenant_id,
        lifecycle_status=lifecycle_status,
        limit=limit,
        offset=offset,
    )
    return {
        "organizations": [_org_response(o) for o in orgs],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/provisioning/organizations",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def create_organization(
    request: Request,
    body: CreateOrgRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        org = _store.create_organization(
            db,
            org_name=body.org_name,
            slug=body.slug,
            compliance_classification=body.compliance_classification,
            deployment_tier=body.deployment_tier,
            created_by=actor,
            tenant_id=tenant_id,
            region=body.region,
            idempotency_key=body.idempotency_key,
            metadata=body.metadata,
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _org_response(org)


@router.get(
    "/control-plane/provisioning/organizations/{org_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_organization(
    request: Request,
    org_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        org = _store.get_organization(db, org_id=org_id, tenant_id=tenant_id)
    except OrgNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_ORG_NOT_FOUND, exc.message)
        ) from exc

    result = _org_response(org)
    result["metadata"] = org.metadata
    return result


@router.post(
    "/control-plane/provisioning/organizations/{org_id}/provision",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def start_provisioning_workflow(
    request: Request,
    org_id: str,
    body: StartProvisioningRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        wf = _store.start_provisioning_workflow(
            db,
            org_id=org_id,
            initiated_by=actor,
            env_target=body.env_target,
            tenant_id=tenant_id,
            idempotency_key=body.idempotency_key,
            metadata=body.metadata,
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _workflow_response(wf)


@router.post(
    "/control-plane/provisioning/organizations/{org_id}/activate",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def activate_organization(
    request: Request,
    org_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        org = _store.activate_organization(
            db, org_id=org_id, actor=actor, tenant_id=tenant_id
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _org_response(org)


@router.post(
    "/control-plane/provisioning/organizations/{org_id}/suspend",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def suspend_organization(
    request: Request,
    org_id: str,
    body: SuspendOrgRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        org = _store.suspend_organization(
            db,
            org_id=org_id,
            actor=actor,
            tenant_id=tenant_id,
            reason=body.reason,
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _org_response(org)


@router.post(
    "/control-plane/provisioning/organizations/{org_id}/environment",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def assign_environment(
    request: Request,
    org_id: str,
    body: AssignEnvironmentRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        org = _store.assign_environment(
            db,
            org_id=org_id,
            env_assignment_id=body.env_assignment_id,
            actor=actor,
            tenant_id=tenant_id,
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _org_response(org)


@router.get(
    "/control-plane/provisioning/organizations/{org_id}/onboarding",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_onboarding_state(
    request: Request,
    org_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        org = _store.get_organization(db, org_id=org_id, tenant_id=tenant_id)
    except OrgNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_ORG_NOT_FOUND, exc.message)
        ) from exc

    return {
        "organization_id": org.organization_id,
        "lifecycle_status": org.lifecycle_status.value,
        "onboarding_state": org.onboarding_state.value,
        "env_assignment_id": org.env_assignment_id,
        "activated_at": org.activated_at.isoformat() if org.activated_at else None,
        "suspended_at": org.suspended_at.isoformat() if org.suspended_at else None,
    }


@router.get(
    "/control-plane/provisioning/organizations/{org_id}/history",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_org_history(
    request: Request,
    org_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        events = _store.list_audit_events(
            db,
            org_id=org_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
    except OrgNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_ORG_NOT_FOUND, exc.message)
        ) from exc

    return {
        "organization_id": org_id,
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "actor": e.actor,
                "outcome": e.outcome,
                "timestamp": e.timestamp.isoformat(),
                "provisioning_id": e.provisioning_id,
                "workflow_state": e.workflow_state,
                "failure_reason": e.failure_reason,
                "details": e.details,
                "event_hash": e.event_hash,
                "previous_event_hash": e.previous_event_hash,
            }
            for e in events
        ],
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# Workflow endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/provisioning/workflows",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_workflows(
    request: Request,
    org_id: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    workflows = _store.list_workflows(
        db,
        org_id=org_id,
        tenant_id=tenant_id,
        limit=limit,
        offset=offset,
    )
    return {
        "workflows": [_workflow_response(w) for w in workflows],
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/control-plane/provisioning/workflows/{provisioning_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_workflow(
    request: Request,
    provisioning_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        wf = _store.get_workflow(
            db, provisioning_id=provisioning_id, tenant_id=tenant_id
        )
    except WorkflowNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_WORKFLOW_NOT_FOUND, exc.message)
        ) from exc

    return _workflow_response(wf)


@router.post(
    "/control-plane/provisioning/workflows/{provisioning_id}/complete",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def complete_workflow(
    request: Request,
    provisioning_id: str,
    body: CompleteWorkflowRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        wf = _store.complete_provisioning_workflow(
            db,
            provisioning_id=provisioning_id,
            actor=actor,
            tenant_id=tenant_id,
            validation_results=body.validation_results,
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _workflow_response(wf)


@router.post(
    "/control-plane/provisioning/workflows/{provisioning_id}/fail",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def fail_workflow(
    request: Request,
    provisioning_id: str,
    body: FailWorkflowRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        wf = _store.fail_provisioning_workflow(
            db,
            provisioning_id=provisioning_id,
            actor=actor,
            failure_reason=body.failure_reason,
            failure_category=body.failure_category,
            tenant_id=tenant_id,
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _workflow_response(wf)


@router.post(
    "/control-plane/provisioning/workflows/{provisioning_id}/retry",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def retry_workflow(
    request: Request,
    provisioning_id: str,
    body: RetryWorkflowRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)

    try:
        original_wf = _store.get_workflow(
            db, provisioning_id=provisioning_id, tenant_id=tenant_id
        )
    except WorkflowNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_WORKFLOW_NOT_FOUND, exc.message)
        ) from exc

    try:
        new_wf = _store.retry_provisioning_workflow(
            db,
            org_id=original_wf.organization_id,
            initiated_by=actor,
            env_target=body.env_target,
            tenant_id=tenant_id,
            idempotency_key=body.idempotency_key,
        )
        db.commit()
    except ProvisioningStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return _workflow_response(new_wf)
