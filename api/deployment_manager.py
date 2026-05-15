"""Deployment Manager API — operator-safe deployment lifecycle endpoints.

All routes require control-plane:read (read) or control-plane:admin (write).
Tenant isolation: tenant_id is always resolved from auth context, never from
the request body. Platform-level records (tenant_id=None) are readable by any
sufficiently-scoped operator.

Routes are under /control-plane/deployments/ — covered by the existing
"control" plane route prefix and its governance gates.

Security invariants:
- No secrets, credentials, or infrastructure topology in any response.
- Tenant_id from auth context only (never from request body).
- All mutations are audit-logged (DeploymentEventRecord) before returning.
- State transitions validated against VALID_TRANSITIONS before DB write.
- Approval gate enforced: production/regulated deployments block at deploying
  until approval_granted_by is set.
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
from services.deployment import (
    ComplianceClassification,
    DeploymentState,
    DeploymentStore,
    DeploymentStrategy,
    EnvironmentLifecycleState,
    EnvironmentType,
    HealthResult,
)
from services.deployment.store import (
    ApprovalRequired,
    DeploymentNotFound,
    DeploymentStoreError,
    EnvironmentNotFound,
    InvalidStateTransition,
)

log = logging.getLogger("frostgate.deployment")
router = APIRouter(tags=["deployment"])

_store = DeploymentStore()

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

ERR_DEPLOY_NOT_FOUND = "DEPLOY-API-001"
ERR_ENV_NOT_FOUND = "DEPLOY-API-002"
ERR_INVALID_TRANSITION = "DEPLOY-API-003"
ERR_APPROVAL_REQUIRED = "DEPLOY-API-004"
ERR_INVALID_INPUT = "DEPLOY-API-005"
ERR_FORBIDDEN = "DEPLOY-API-006"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tenant_from_request(request: Request) -> Optional[str]:
    """Resolve tenant_id from auth context. Never from request body."""
    auth = getattr(getattr(request, "state", None), "auth", None)
    return getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )


def _actor_from_request(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    prefix = getattr(auth, "key_prefix", None)
    return str(prefix) if prefix else "unknown"


def _trace_id_from_request(request: Request) -> Optional[str]:
    state = getattr(request, "state", None)
    return getattr(state, "trace_id", None) or getattr(state, "request_id", None)


def _handle_store_error(exc: DeploymentStoreError) -> HTTPException:
    if isinstance(exc, DeploymentNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_DEPLOY_NOT_FOUND, exc.message)
        )
    if isinstance(exc, EnvironmentNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_ENV_NOT_FOUND, exc.message)
        )
    if isinstance(exc, InvalidStateTransition):
        return HTTPException(
            status_code=409, detail=api_error(ERR_INVALID_TRANSITION, exc.message)
        )
    if isinstance(exc, ApprovalRequired):
        return HTTPException(
            status_code=403, detail=api_error(ERR_APPROVAL_REQUIRED, exc.message)
        )
    return HTTPException(
        status_code=500, detail=api_error("DEPLOY-API-500", "Internal deployment error")
    )


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

_VERSION_REF_MAX = 256
_REGION_MAX = 128
_REASON_MAX = 512
_POLICY_KEYS_MAX = 20


class CreateEnvironmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    env_type: EnvironmentType
    region: str = Field(..., min_length=1, max_length=_REGION_MAX)
    compliance_classification: ComplianceClassification = (
        ComplianceClassification.STANDARD
    )
    deployment_policy: dict[str, Any] = Field(default_factory=dict)

    @field_validator("deployment_policy")
    @classmethod
    def _policy_bounded(cls, v: dict) -> dict:
        if len(v) > _POLICY_KEYS_MAX:
            raise ValueError(
                f"deployment_policy may not exceed {_POLICY_KEYS_MAX} keys"
            )
        return v


class CreateDeploymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    env_id: str = Field(..., min_length=1, max_length=64)
    version_ref: str = Field(..., min_length=1, max_length=_VERSION_REF_MAX)
    strategy: DeploymentStrategy = DeploymentStrategy.ROLLING
    artifact_hash: Optional[str] = Field(
        default=None,
        max_length=128,
        pattern=r"^[0-9a-fA-F]{64}$|^$",
        description="SHA-256 hex digest of the deployment artifact. Empty string or omit if not yet resolved.",
    )
    rollback_from_id: Optional[str] = Field(default=None, max_length=64)
    rollback_reason: Optional[str] = Field(default=None, max_length=_REASON_MAX)
    deployment_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("artifact_hash", mode="before")
    @classmethod
    def _empty_to_none(cls, v: Any) -> Any:
        if v == "":
            return None
        return v

    @field_validator("deployment_metadata")
    @classmethod
    def _meta_bounded(cls, v: dict) -> dict:
        if len(v) > _POLICY_KEYS_MAX:
            raise ValueError(
                f"deployment_metadata may not exceed {_POLICY_KEYS_MAX} keys"
            )
        return v


class TransitionStateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: DeploymentState
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def _details_bounded(cls, v: dict) -> dict:
        if len(v) > _POLICY_KEYS_MAX:
            raise ValueError(f"details may not exceed {_POLICY_KEYS_MAX} keys")
        return v


class RecordHealthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    readiness_result: HealthResult
    liveness_result: HealthResult
    smoke_test_result: HealthResult = HealthResult.UNKNOWN
    validation_result: HealthResult = HealthResult.UNKNOWN
    rollback_trigger_reason: Optional[str] = Field(default=None, max_length=_REASON_MAX)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool


# ---------------------------------------------------------------------------
# Environment endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/deployments/environments",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_environments(
    request: Request,
    env_type: Optional[EnvironmentType] = Query(default=None),
    lifecycle_state: Optional[EnvironmentLifecycleState] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    envs = _store.list_environments(
        db,
        tenant_id=tenant_id,
        env_type=env_type,
        lifecycle_state=lifecycle_state,
        limit=limit,
        offset=offset,
    )
    return {
        "environments": [
            {
                "env_id": e.env_id,
                "env_type": e.env_type.value,
                "region": e.region,
                "lifecycle_state": e.lifecycle_state.value,
                "compliance_classification": e.compliance_classification.value,
                "tenant_id": e.tenant_id,
                "requires_approval": e.requires_approval(),
                "created_by": e.created_by,
                "created_at": e.created_at.isoformat(),
            }
            for e in envs
        ],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/deployments/environments",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def create_environment(
    request: Request,
    body: CreateEnvironmentRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    actor = _actor_from_request(request)
    trace_id = _trace_id_from_request(request)

    try:
        env = _store.create_environment(
            db,
            env_type=body.env_type,
            region=body.region,
            compliance_classification=body.compliance_classification,
            created_by=actor,
            tenant_id=tenant_id,
            deployment_policy=body.deployment_policy,
            trace_id=trace_id,
        )
        db.commit()
    except DeploymentStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return {
        "env_id": env.env_id,
        "env_type": env.env_type.value,
        "region": env.region,
        "lifecycle_state": env.lifecycle_state.value,
        "compliance_classification": env.compliance_classification.value,
        "tenant_id": env.tenant_id,
        "requires_approval": env.requires_approval(),
        "created_by": env.created_by,
        "created_at": env.created_at.isoformat(),
    }


@router.get(
    "/control-plane/deployments/environments/{env_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_environment(
    request: Request,
    env_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    try:
        env = _store.get_environment(db, env_id=env_id, tenant_id=tenant_id)
    except EnvironmentNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_ENV_NOT_FOUND, exc.message)
        ) from exc

    return {
        "env_id": env.env_id,
        "env_type": env.env_type.value,
        "region": env.region,
        "lifecycle_state": env.lifecycle_state.value,
        "compliance_classification": env.compliance_classification.value,
        "tenant_id": env.tenant_id,
        "requires_approval": env.requires_approval(),
        "deployment_policy": env.deployment_policy,
        "created_by": env.created_by,
        "created_at": env.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Deployment record endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/deployments",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_deployments(
    request: Request,
    env_id: Optional[str] = Query(default=None, max_length=64),
    state: Optional[DeploymentState] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    deployments = _store.list_deployments(
        db,
        tenant_id=tenant_id,
        env_id=env_id,
        state=state,
        limit=limit,
        offset=offset,
    )
    return {
        "deployments": [
            {
                "deployment_id": d.deployment_id,
                "env_id": d.env_id,
                "version_ref": d.version_ref,
                "strategy": d.strategy.value,
                "state": d.state.value,
                "initiated_by": d.initiated_by,
                "initiated_at": d.initiated_at.isoformat(),
                "completed_at": d.completed_at.isoformat() if d.completed_at else None,
                "tenant_id": d.tenant_id,
                "artifact_hash": d.artifact_hash,
                "approval_required": d.approval_required,
                "approval_granted_by": d.approval_granted_by,
                "rollback_from_id": d.rollback_from_id,
            }
            for d in deployments
        ],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/deployments",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def create_deployment(
    request: Request,
    body: CreateDeploymentRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    actor = _actor_from_request(request)
    trace_id = _trace_id_from_request(request)

    try:
        dep = _store.create_deployment(
            db,
            env_id=body.env_id,
            version_ref=body.version_ref,
            strategy=body.strategy,
            initiated_by=actor,
            tenant_id=tenant_id,
            artifact_hash=body.artifact_hash,
            rollback_from_id=body.rollback_from_id,
            rollback_reason=body.rollback_reason,
            deployment_metadata=body.deployment_metadata,
            trace_id=trace_id,
        )
        db.commit()
    except DeploymentStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return {
        "deployment_id": dep.deployment_id,
        "env_id": dep.env_id,
        "version_ref": dep.version_ref,
        "strategy": dep.strategy.value,
        "state": dep.state.value,
        "initiated_by": dep.initiated_by,
        "initiated_at": dep.initiated_at.isoformat(),
        "tenant_id": dep.tenant_id,
        "artifact_hash": dep.artifact_hash,
        "approval_required": dep.approval_required,
        "rollback_from_id": dep.rollback_from_id,
    }


@router.get(
    "/control-plane/deployments/{deployment_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_deployment(
    request: Request,
    deployment_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    try:
        dep = _store.get_deployment(
            db, deployment_id=deployment_id, tenant_id=tenant_id
        )
    except DeploymentNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_DEPLOY_NOT_FOUND, exc.message)
        ) from exc

    return {
        "deployment_id": dep.deployment_id,
        "env_id": dep.env_id,
        "version_ref": dep.version_ref,
        "strategy": dep.strategy.value,
        "state": dep.state.value,
        "initiated_by": dep.initiated_by,
        "initiated_at": dep.initiated_at.isoformat(),
        "completed_at": dep.completed_at.isoformat() if dep.completed_at else None,
        "tenant_id": dep.tenant_id,
        "artifact_hash": dep.artifact_hash,
        "approval_required": dep.approval_required,
        "approval_granted_by": dep.approval_granted_by,
        "rollback_from_id": dep.rollback_from_id,
        "rollback_reason": dep.rollback_reason,
        "deployment_metadata": dep.deployment_metadata,
    }


@router.post(
    "/control-plane/deployments/{deployment_id}/transition",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_deployment_state(
    request: Request,
    deployment_id: str,
    body: TransitionStateRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    actor = _actor_from_request(request)
    trace_id = _trace_id_from_request(request)

    try:
        dep = _store.transition_state(
            db,
            deployment_id=deployment_id,
            to_state=body.to_state,
            actor=actor,
            tenant_id=tenant_id,
            details=body.details or None,
            trace_id=trace_id,
        )
        db.commit()
    except DeploymentStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return {
        "deployment_id": dep.deployment_id,
        "state": dep.state.value,
        "completed_at": dep.completed_at.isoformat() if dep.completed_at else None,
    }


@router.post(
    "/control-plane/deployments/{deployment_id}/approval",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def record_deployment_approval(
    request: Request,
    deployment_id: str,
    body: ApprovalRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    actor = _actor_from_request(request)
    trace_id = _trace_id_from_request(request)

    try:
        dep = _store.record_approval(
            db,
            deployment_id=deployment_id,
            approved=body.approved,
            actor=actor,
            tenant_id=tenant_id,
            trace_id=trace_id,
        )
        db.commit()
    except DeploymentStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return {
        "deployment_id": dep.deployment_id,
        "approval_required": dep.approval_required,
        "approval_granted_by": dep.approval_granted_by,
    }


# ---------------------------------------------------------------------------
# Deployment history
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/deployments/{deployment_id}/history",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_deployment_history(
    request: Request,
    deployment_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    try:
        events = _store.list_events(
            db,
            deployment_id=deployment_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
    except DeploymentNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_DEPLOY_NOT_FOUND, exc.message)
        ) from exc

    return {
        "deployment_id": deployment_id,
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "actor": e.actor,
                "timestamp": e.timestamp.isoformat(),
                "from_state": e.from_state.value if e.from_state else None,
                "to_state": e.to_state.value if e.to_state else None,
                "details": e.details,
            }
            for e in events
        ],
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# Deployment health
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/deployments/{deployment_id}/health",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def record_deployment_health(
    request: Request,
    deployment_id: str,
    body: RecordHealthRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    actor = _actor_from_request(request)
    trace_id = _trace_id_from_request(request)

    try:
        record = _store.record_health(
            db,
            deployment_id=deployment_id,
            readiness_result=body.readiness_result,
            liveness_result=body.liveness_result,
            smoke_test_result=body.smoke_test_result,
            validation_result=body.validation_result,
            checked_by=actor,
            tenant_id=tenant_id,
            rollback_trigger_reason=body.rollback_trigger_reason,
            trace_id=trace_id,
        )
        db.commit()
    except DeploymentStoreError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc

    return {
        "record_id": record.record_id,
        "deployment_id": record.deployment_id,
        "readiness_result": record.readiness_result.value,
        "liveness_result": record.liveness_result.value,
        "smoke_test_result": record.smoke_test_result.value,
        "validation_result": record.validation_result.value,
        "checked_by": record.checked_by,
        "checked_at": record.checked_at.isoformat(),
        "rollback_trigger_reason": record.rollback_trigger_reason,
    }


@router.get(
    "/control-plane/deployments/{deployment_id}/health",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_deployment_health(
    request: Request,
    deployment_id: str,
    limit: int = Query(default=10, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    try:
        records = _store.list_health_records(
            db,
            deployment_id=deployment_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
    except DeploymentNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_DEPLOY_NOT_FOUND, exc.message)
        ) from exc

    return {
        "deployment_id": deployment_id,
        "health_records": [
            {
                "record_id": r.record_id,
                "readiness_result": r.readiness_result.value,
                "liveness_result": r.liveness_result.value,
                "smoke_test_result": r.smoke_test_result.value,
                "validation_result": r.validation_result.value,
                "checked_by": r.checked_by,
                "checked_at": r.checked_at.isoformat(),
                "rollback_trigger_reason": r.rollback_trigger_reason,
            }
            for r in records
        ],
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# Rollback lineage
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/deployments/{deployment_id}/rollback-lineage",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_rollback_lineage(
    request: Request,
    deployment_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_request(request)
    try:
        chain = _store.get_rollback_lineage(
            db, deployment_id=deployment_id, tenant_id=tenant_id
        )
    except DeploymentNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error(ERR_DEPLOY_NOT_FOUND, exc.message)
        ) from exc

    return {
        "deployment_id": deployment_id,
        "lineage": [
            {
                "deployment_id": d.deployment_id,
                "version_ref": d.version_ref,
                "state": d.state.value,
                "initiated_at": d.initiated_at.isoformat(),
                "completed_at": d.completed_at.isoformat() if d.completed_at else None,
                "rollback_from_id": d.rollback_from_id,
                "rollback_reason": d.rollback_reason,
            }
            for d in chain
        ],
    }
