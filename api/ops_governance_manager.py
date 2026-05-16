"""Operational Governance Manager API — environments, secrets, retention, export & recovery.

All routes require control-plane:read (read) or control-plane:admin (write).
Tenant isolation: tenant_id is always resolved from auth context, never from
the request body. Platform-level records (tenant_id=None) are readable by any
sufficiently-scoped operator.

Routes are under /control-plane/ops/ — covered by the existing
"control" plane route prefix and its governance gates.

Security invariants:
- No secrets, credentials, raw key material, or infrastructure topology in any response.
- tenant_id from auth context only (never from request body).
- All mutations are audit-logged (OpsGovernanceAuditEventRecord) before returning.
- State transitions validated against VALID_*_TRANSITIONS before DB write.
- LegalHoldViolation blocks deletion-path transitions.
- ValidationTokenRequired gates failed_recovery → active environment transitions.
- All list endpoints are page-capped at 200 rows.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.ops_governance import (
    BackupScope,
    ComplianceClassification,
    EnvironmentLifecycleState,
    EnvironmentType,
    ExportClassification,
    ExportScope,
    ExportState,
    IsolationLevel,
    OpsGovernanceStore,
    RecoveryReadiness,
    RecoveryState,
    RecoveryType,
    ResidencyClassification,
    RestoreScope,
    RetentionClassification,
    RetentionState,
    RotationOutcome,
    SecretClassification,
    SecretLifecycleState,
    SecretType,
)
from services.ops_governance.store import (
    BackupRecordNotFound,
    ConcurrentModificationError,
    DuplicateSlug,
    EnvironmentNotFound,
    ExportRequestNotFound,
    InvalidStateTransition,
    LegalHoldViolation,
    OpsGovernanceError,
    RecoveryRecordNotFound,
    RestoreRecordNotFound,
    RetentionPolicyNotFound,
    RotationScheduleNotFound,
    SecretGovernanceNotFound,
    ValidationTokenRequired,
)

log = logging.getLogger("frostgate.ops_governance")
router = APIRouter(tags=["ops_governance"])

_store = OpsGovernanceStore()

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

ERR_ENV_NOT_FOUND = "OPS-API-001"
ERR_SECRET_NOT_FOUND = "OPS-API-002"
ERR_RETENTION_NOT_FOUND = "OPS-API-003"
ERR_EXPORT_NOT_FOUND = "OPS-API-004"
ERR_BACKUP_NOT_FOUND = "OPS-API-005"
ERR_RESTORE_NOT_FOUND = "OPS-API-006"
ERR_RECOVERY_NOT_FOUND = "OPS-API-007"
ERR_ROTATION_NOT_FOUND = "OPS-API-008"
ERR_INVALID_TRANSITION = "OPS-API-009"
ERR_CONCURRENT_MODIFICATION = "OPS-API-010"
ERR_DUPLICATE_SLUG = "OPS-API-011"
ERR_LEGAL_HOLD = "OPS-API-012"
ERR_VALIDATION_TOKEN_REQUIRED = "OPS-API-013"
ERR_INVALID_INPUT = "OPS-API-014"

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


def _handle_store_error(exc: OpsGovernanceError) -> HTTPException:
    if isinstance(exc, EnvironmentNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_ENV_NOT_FOUND, exc.message)
        )
    if isinstance(exc, SecretGovernanceNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_SECRET_NOT_FOUND, exc.message)
        )
    if isinstance(exc, RetentionPolicyNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_RETENTION_NOT_FOUND, exc.message)
        )
    if isinstance(exc, ExportRequestNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_EXPORT_NOT_FOUND, exc.message)
        )
    if isinstance(exc, BackupRecordNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_BACKUP_NOT_FOUND, exc.message)
        )
    if isinstance(exc, RestoreRecordNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_RESTORE_NOT_FOUND, exc.message)
        )
    if isinstance(exc, RecoveryRecordNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_RECOVERY_NOT_FOUND, exc.message)
        )
    if isinstance(exc, RotationScheduleNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_ROTATION_NOT_FOUND, exc.message)
        )
    if isinstance(exc, InvalidStateTransition):
        return HTTPException(
            status_code=409, detail=api_error(ERR_INVALID_TRANSITION, exc.message)
        )
    if isinstance(exc, ConcurrentModificationError):
        return HTTPException(
            status_code=409, detail=api_error(ERR_CONCURRENT_MODIFICATION, exc.message)
        )
    if isinstance(exc, DuplicateSlug):
        return HTTPException(
            status_code=409, detail=api_error(ERR_DUPLICATE_SLUG, exc.message)
        )
    if isinstance(exc, LegalHoldViolation):
        return HTTPException(
            status_code=409, detail=api_error(ERR_LEGAL_HOLD, exc.message)
        )
    if isinstance(exc, ValidationTokenRequired):
        return HTTPException(
            status_code=422,
            detail=api_error(ERR_VALIDATION_TOKEN_REQUIRED, exc.message),
        )
    return HTTPException(
        status_code=500,
        detail=api_error("OPS-API-500", "Internal ops governance error"),
    )


# ---------------------------------------------------------------------------
# Response serializers — explicit field allowlist, no secrets, no infra paths
# ---------------------------------------------------------------------------


def _env_response(env: Any) -> dict[str, Any]:
    return {
        "environment_id": env.environment_id,
        "tenant_id": env.tenant_id,
        "env_name": env.env_name,
        "slug": env.slug,
        "lifecycle_state": env.lifecycle_state.value
        if hasattr(env.lifecycle_state, "value")
        else env.lifecycle_state,
        "env_type": env.env_type.value
        if hasattr(env.env_type, "value")
        else env.env_type,
        "compliance_classification": env.compliance_classification.value
        if hasattr(env.compliance_classification, "value")
        else env.compliance_classification,
        "isolation_level": env.isolation_level.value
        if hasattr(env.isolation_level, "value")
        else env.isolation_level,
        "residency_classification": env.residency_classification.value
        if hasattr(env.residency_classification, "value")
        else env.residency_classification,
        "recovery_readiness": env.recovery_readiness.value
        if hasattr(env.recovery_readiness, "value")
        else env.recovery_readiness,
        "region": env.region,
        "created_by": env.created_by,
        "created_at": env.created_at.isoformat() if env.created_at else None,
        "updated_at": env.updated_at.isoformat() if env.updated_at else None,
        "archived_at": env.archived_at.isoformat() if env.archived_at else None,
        "state_version": env.state_version,
    }


def _secret_response(s: Any) -> dict[str, Any]:
    return {
        "secret_governance_id": s.secret_governance_id,
        "tenant_id": s.tenant_id,
        "environment_id": s.environment_id,
        "secret_name": s.secret_name,
        "secret_classification": s.secret_classification.value
        if hasattr(s.secret_classification, "value")
        else s.secret_classification,
        "secret_type": s.secret_type.value
        if hasattr(s.secret_type, "value")
        else s.secret_type,
        "lifecycle_state": s.lifecycle_state.value
        if hasattr(s.lifecycle_state, "value")
        else s.lifecycle_state,
        "external_provider": s.external_provider,
        "owner_scope": s.owner_scope,
        "rotation_state": s.rotation_state.value
        if hasattr(s.rotation_state, "value")
        else s.rotation_state,
        "rotation_policy_days": s.rotation_policy_days,
        "last_rotated_at": s.last_rotated_at.isoformat() if s.last_rotated_at else None,
        "next_rotation_due_at": s.next_rotation_due_at.isoformat()
        if s.next_rotation_due_at
        else None,
        "expires_at": s.expires_at.isoformat() if s.expires_at else None,
        "created_by": s.created_by,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        "state_version": s.state_version,
    }


def _rotation_response(r: Any) -> dict[str, Any]:
    return {
        "rotation_id": r.rotation_id,
        "secret_governance_id": r.secret_governance_id,
        "tenant_id": r.tenant_id,
        "rotation_state": r.rotation_state.value
        if hasattr(r.rotation_state, "value")
        else r.rotation_state,
        "scheduled_at": r.scheduled_at.isoformat() if r.scheduled_at else None,
        "initiated_at": r.initiated_at.isoformat() if r.initiated_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "failure_reason": r.failure_reason,
        "compliance_override": r.compliance_override,
        "override_reason": r.override_reason,
        "override_approved_by": r.override_approved_by,
        "emergency_rotation": r.emergency_rotation,
        "waiver_reference": r.waiver_reference,
        "initiated_by": r.initiated_by,
        "outcome": r.outcome.value
        if r.outcome and hasattr(r.outcome, "value")
        else r.outcome,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "state_version": r.state_version,
    }


def _retention_response(p: Any) -> dict[str, Any]:
    return {
        "retention_policy_id": p.retention_policy_id,
        "tenant_id": p.tenant_id,
        "environment_id": p.environment_id,
        "policy_name": p.policy_name,
        "retention_classification": p.retention_classification.value
        if hasattr(p.retention_classification, "value")
        else p.retention_classification,
        "retention_state": p.retention_state.value
        if hasattr(p.retention_state, "value")
        else p.retention_state,
        "retention_days": p.retention_days,
        "archive_after_days": p.archive_after_days,
        "deletion_scheduled_at": p.deletion_scheduled_at.isoformat()
        if p.deletion_scheduled_at
        else None,
        "archived_at": p.archived_at.isoformat() if p.archived_at else None,
        "legal_hold": p.legal_hold,
        "legal_hold_reason": p.legal_hold_reason,
        "legal_hold_set_by": p.legal_hold_set_by,
        "legal_hold_set_at": p.legal_hold_set_at.isoformat()
        if p.legal_hold_set_at
        else None,
        "export_restricted": p.export_restricted,
        "compliance_policy_ref": p.compliance_policy_ref,
        "created_by": p.created_by,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        "state_version": p.state_version,
    }


def _export_response(e: Any) -> dict[str, Any]:
    return {
        "export_id": e.export_id,
        "tenant_id": e.tenant_id,
        "environment_id": e.environment_id,
        "export_state": e.export_state.value
        if hasattr(e.export_state, "value")
        else e.export_state,
        "export_scope": e.export_scope.value
        if hasattr(e.export_scope, "value")
        else e.export_scope,
        "export_classification": e.export_classification.value
        if hasattr(e.export_classification, "value")
        else e.export_classification,
        "export_purpose": e.export_purpose,
        "requested_by": e.requested_by,
        "approved_by": e.approved_by,
        "rejected_by": e.rejected_by,
        "approval_reason": e.approval_reason,
        "rejection_reason": e.rejection_reason,
        "legal_hold_validated": e.legal_hold_validated,
        "residency_validated": e.residency_validated,
        "retention_validated": e.retention_validated,
        "expires_at": e.expires_at.isoformat() if e.expires_at else None,
        "completed_at": e.completed_at.isoformat() if e.completed_at else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        "state_version": e.state_version,
    }


def _backup_response(b: Any) -> dict[str, Any]:
    return {
        "backup_id": b.backup_id,
        "tenant_id": b.tenant_id,
        "environment_id": b.environment_id,
        "backup_scope": b.backup_scope.value
        if hasattr(b.backup_scope, "value")
        else b.backup_scope,
        "backup_classification": b.backup_classification.value
        if hasattr(b.backup_classification, "value")
        else b.backup_classification,
        "backup_state": b.backup_state.value
        if hasattr(b.backup_state, "value")
        else b.backup_state,
        "retention_policy_id": b.retention_policy_id,
        "backup_size_bytes": b.backup_size_bytes,
        "checksum_ref": b.checksum_ref,
        "initiated_by": b.initiated_by,
        "started_at": b.started_at.isoformat() if b.started_at else None,
        "completed_at": b.completed_at.isoformat() if b.completed_at else None,
        "expires_at": b.expires_at.isoformat() if b.expires_at else None,
        "failure_reason": b.failure_reason,
        "created_at": b.created_at.isoformat() if b.created_at else None,
        "state_version": b.state_version,
    }


def _restore_response(r: Any) -> dict[str, Any]:
    return {
        "restore_id": r.restore_id,
        "tenant_id": r.tenant_id,
        "source_backup_id": r.source_backup_id,
        "target_environment_id": r.target_environment_id,
        "restore_state": r.restore_state.value
        if hasattr(r.restore_state, "value")
        else r.restore_state,
        "restore_scope": r.restore_scope.value
        if hasattr(r.restore_scope, "value")
        else r.restore_scope,
        "point_in_time_ref": r.point_in_time_ref,
        "validation_state": r.validation_state.value
        if hasattr(r.validation_state, "value")
        else r.validation_state,
        "initiated_by": r.initiated_by,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "failure_reason": r.failure_reason,
        "recovery_lineage_id": r.recovery_lineage_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "state_version": r.state_version,
    }


def _recovery_response(r: Any) -> dict[str, Any]:
    return {
        "recovery_id": r.recovery_id,
        "tenant_id": r.tenant_id,
        "environment_id": r.environment_id,
        "recovery_state": r.recovery_state.value
        if hasattr(r.recovery_state, "value")
        else r.recovery_state,
        "recovery_type": r.recovery_type.value
        if hasattr(r.recovery_type, "value")
        else r.recovery_type,
        "recovery_trigger": r.recovery_trigger,
        "validation_state": r.validation_state.value
        if hasattr(r.validation_state, "value")
        else r.validation_state,
        "readiness_classification": r.readiness_classification.value
        if hasattr(r.readiness_classification, "value")
        else r.readiness_classification,
        "initiated_by": r.initiated_by,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "validated_at": r.validated_at.isoformat() if r.validated_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "failure_reason": r.failure_reason,
        "failure_count": r.failure_count,
        "drill_mode": r.drill_mode,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "state_version": r.state_version,
    }


def _audit_response(e: Any) -> dict[str, Any]:
    return {
        "event_id": e.event_id,
        "tenant_id": e.tenant_id,
        "environment_id": e.environment_id,
        "resource_type": e.resource_type,
        "resource_id": e.resource_id,
        "event_type": e.event_type,
        "actor": e.actor,
        "outcome": e.outcome,
        "policy_state": e.policy_state,
        "operational_context": e.operational_context,
        "failure_reason": e.failure_reason,
        "event_hash": e.event_hash,
        "previous_event_hash": e.previous_event_hash,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
    }


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateEnvironmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    env_name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=80, pattern=r"^[a-z0-9-]+$")
    env_type: EnvironmentType = EnvironmentType.SHARED
    compliance_classification: ComplianceClassification = (
        ComplianceClassification.STANDARD
    )
    isolation_level: IsolationLevel = IsolationLevel.STANDARD
    residency_classification: ResidencyClassification = (
        ResidencyClassification.UNRESTRICTED
    )
    region: Optional[str] = None
    idempotency_key: Optional[str] = Field(default=None, max_length=255)
    metadata: Optional[dict[str, Any]] = None


class TransitionEnvironmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: EnvironmentLifecycleState
    validation_token: Optional[str] = None
    recovery_readiness: Optional[RecoveryReadiness] = None


class IssueValidationTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_token: str = Field(..., min_length=8, max_length=512)


class RegisterSecretGovernanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_name: str = Field(..., min_length=1, max_length=255)
    secret_classification: SecretClassification = SecretClassification.STANDARD
    secret_type: SecretType = SecretType.API_KEY
    environment_id: Optional[str] = None
    external_provider: Optional[str] = None
    external_reference_id: Optional[str] = None
    owner_scope: Optional[str] = None
    rotation_policy_days: Optional[int] = Field(default=None, ge=1, le=3650)
    expires_at: Optional[datetime] = None
    governance_policy: Optional[dict[str, Any]] = None
    idempotency_key: Optional[str] = Field(default=None, max_length=255)


class TransitionSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: SecretLifecycleState


class ScheduleRotationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheduled_at: datetime
    emergency_rotation: bool = False
    compliance_override: bool = False
    override_reason: Optional[str] = None
    override_approved_by: Optional[str] = None
    waiver_reference: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class RecordRotationOutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: RotationOutcome
    failure_reason: Optional[str] = None


class CreateRetentionPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_name: str = Field(..., min_length=1, max_length=255)
    retention_days: int = Field(..., ge=1, le=36500)
    retention_classification: RetentionClassification = RetentionClassification.STANDARD
    environment_id: Optional[str] = None
    archive_after_days: Optional[int] = Field(default=None, ge=1, le=36500)
    export_restricted: bool = False
    compliance_policy_ref: Optional[str] = None
    idempotency_key: Optional[str] = Field(default=None, max_length=255)


class TransitionRetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: RetentionState
    override_reason: Optional[str] = None


class SetLegalHoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=1024)


class CreateExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export_scope: ExportScope = ExportScope.TENANT
    export_classification: ExportClassification = ExportClassification.STANDARD
    export_purpose: Optional[str] = None
    environment_id: Optional[str] = None
    idempotency_key: Optional[str] = Field(default=None, max_length=255)


class TransitionExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: ExportState
    approval_reason: Optional[str] = None
    rejection_reason: Optional[str] = None


class InitiateBackupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment_id: Optional[str] = None
    backup_scope: BackupScope = BackupScope.FULL
    backup_classification: ComplianceClassification = ComplianceClassification.STANDARD
    retention_policy_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class InitiateRestoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_backup_id: str
    target_environment_id: Optional[str] = None
    restore_scope: RestoreScope = RestoreScope.FULL
    point_in_time_ref: Optional[str] = None


class InitiateRecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment_id: Optional[str] = None
    recovery_type: RecoveryType
    recovery_trigger: Optional[str] = None
    drill_mode: bool = False
    metadata: Optional[dict[str, Any]] = None


class TransitionRecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: RecoveryState
    failure_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Environment routes
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/ops/environments",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_environments(
    request: Request,
    lifecycle_state: Optional[EnvironmentLifecycleState] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    envs = _store.list_environments(
        db,
        tenant_id=tenant_id,
        lifecycle_state=lifecycle_state,
        limit=limit,
        offset=offset,
    )
    return {
        "environments": [_env_response(e) for e in envs],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/ops/environments",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def create_environment(
    request: Request,
    body: CreateEnvironmentRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        env = _store.create_environment(
            db,
            env_name=body.env_name,
            slug=body.slug,
            created_by=actor,
            tenant_id=tenant_id,
            env_type=body.env_type,
            compliance_classification=body.compliance_classification,
            isolation_level=body.isolation_level,
            residency_classification=body.residency_classification,
            region=body.region,
            idempotency_key=body.idempotency_key,
            metadata=body.metadata,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _env_response(env)


@router.get(
    "/control-plane/ops/environments/{env_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_environment(
    request: Request,
    env_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        env = _store.get_environment(db, env_id=env_id, tenant_id=tenant_id)
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return _env_response(env)


@router.post(
    "/control-plane/ops/environments/{env_id}/transition",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_environment(
    request: Request,
    env_id: str,
    body: TransitionEnvironmentRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        env = _store.transition_environment_state(
            db,
            env_id=env_id,
            to_state=body.to_state,
            actor=actor,
            tenant_id=tenant_id,
            validation_token=body.validation_token,
            recovery_readiness=body.recovery_readiness,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _env_response(env)


@router.post(
    "/control-plane/ops/environments/{env_id}/validation-token",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def issue_environment_validation_token(
    request: Request,
    env_id: str,
    body: IssueValidationTokenRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        env = _store.set_environment_validation_token(
            db,
            env_id=env_id,
            actor=actor,
            validation_token=body.validation_token,
            tenant_id=tenant_id,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _env_response(env)


@router.get(
    "/control-plane/ops/environments/{env_id}/history",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_environment_history(
    request: Request,
    env_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        events = _store.list_environment_history(
            db, env_id=env_id, tenant_id=tenant_id, limit=limit, offset=offset
        )
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return {
        "events": [_audit_response(e) for e in events],
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# Secret governance routes
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/ops/secrets",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_secret_governance(
    request: Request,
    environment_id: Optional[str] = Query(default=None),
    lifecycle_state: Optional[SecretLifecycleState] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    secrets = _store.list_secret_governance(
        db,
        tenant_id=tenant_id,
        environment_id=environment_id,
        lifecycle_state=lifecycle_state,
        limit=limit,
        offset=offset,
    )
    return {
        "secrets": [_secret_response(s) for s in secrets],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/ops/secrets",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def register_secret_governance(
    request: Request,
    body: RegisterSecretGovernanceRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        secret = _store.register_secret_governance(
            db,
            secret_name=body.secret_name,
            secret_classification=body.secret_classification,
            secret_type=body.secret_type,
            created_by=actor,
            tenant_id=tenant_id,
            environment_id=body.environment_id,
            external_provider=body.external_provider,
            external_reference_id=body.external_reference_id,
            owner_scope=body.owner_scope,
            rotation_policy_days=body.rotation_policy_days,
            expires_at=body.expires_at,
            governance_policy=body.governance_policy,
            idempotency_key=body.idempotency_key,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _secret_response(secret)


@router.get(
    "/control-plane/ops/secrets/{secret_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_secret_governance(
    request: Request,
    secret_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        secret = _store.get_secret_governance(
            db, secret_id=secret_id, tenant_id=tenant_id
        )
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return _secret_response(secret)


@router.post(
    "/control-plane/ops/secrets/{secret_id}/transition",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_secret_state(
    request: Request,
    secret_id: str,
    body: TransitionSecretRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        secret = _store.transition_secret_state(
            db,
            secret_id=secret_id,
            to_state=body.to_state,
            actor=actor,
            tenant_id=tenant_id,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _secret_response(secret)


@router.post(
    "/control-plane/ops/secrets/{secret_id}/rotations",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def schedule_key_rotation(
    request: Request,
    secret_id: str,
    body: ScheduleRotationRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        rotation = _store.schedule_key_rotation(
            db,
            secret_id=secret_id,
            scheduled_at=body.scheduled_at,
            actor=actor,
            tenant_id=tenant_id,
            emergency_rotation=body.emergency_rotation,
            compliance_override=body.compliance_override,
            override_reason=body.override_reason,
            override_approved_by=body.override_approved_by,
            waiver_reference=body.waiver_reference,
            metadata=body.metadata,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _rotation_response(rotation)


@router.post(
    "/control-plane/ops/rotations/{rotation_id}/outcome",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def record_rotation_outcome(
    request: Request,
    rotation_id: str,
    body: RecordRotationOutcomeRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        rotation = _store.record_rotation_outcome(
            db,
            rotation_id=rotation_id,
            outcome=body.outcome,
            actor=actor,
            tenant_id=tenant_id,
            failure_reason=body.failure_reason,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _rotation_response(rotation)


# ---------------------------------------------------------------------------
# Retention policy routes
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/ops/retention-policies",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_retention_policies(
    request: Request,
    environment_id: Optional[str] = Query(default=None),
    retention_state: Optional[RetentionState] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    policies = _store.list_retention_policies(
        db,
        tenant_id=tenant_id,
        environment_id=environment_id,
        retention_state=retention_state,
        limit=limit,
        offset=offset,
    )
    return {
        "policies": [_retention_response(p) for p in policies],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/ops/retention-policies",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def create_retention_policy(
    request: Request,
    body: CreateRetentionPolicyRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        policy = _store.create_retention_policy(
            db,
            policy_name=body.policy_name,
            retention_days=body.retention_days,
            created_by=actor,
            tenant_id=tenant_id,
            environment_id=body.environment_id,
            retention_classification=body.retention_classification,
            archive_after_days=body.archive_after_days,
            export_restricted=body.export_restricted,
            compliance_policy_ref=body.compliance_policy_ref,
            idempotency_key=body.idempotency_key,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _retention_response(policy)


@router.get(
    "/control-plane/ops/retention-policies/{policy_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_retention_policy(
    request: Request,
    policy_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        policy = _store.get_retention_policy(
            db, policy_id=policy_id, tenant_id=tenant_id
        )
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return _retention_response(policy)


@router.post(
    "/control-plane/ops/retention-policies/{policy_id}/transition",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_retention_policy(
    request: Request,
    policy_id: str,
    body: TransitionRetentionRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        policy = _store.transition_retention_state(
            db,
            policy_id=policy_id,
            to_state=body.to_state,
            actor=actor,
            tenant_id=tenant_id,
            override_reason=body.override_reason,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _retention_response(policy)


@router.post(
    "/control-plane/ops/retention-policies/{policy_id}/legal-hold",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def set_legal_hold(
    request: Request,
    policy_id: str,
    body: SetLegalHoldRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        policy = _store.set_legal_hold(
            db,
            policy_id=policy_id,
            actor=actor,
            reason=body.reason,
            tenant_id=tenant_id,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _retention_response(policy)


# ---------------------------------------------------------------------------
# Export request routes
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/ops/exports",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_export_requests(
    request: Request,
    environment_id: Optional[str] = Query(default=None),
    export_state: Optional[ExportState] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    exports = _store.list_export_requests(
        db,
        tenant_id=tenant_id,
        environment_id=environment_id,
        export_state=export_state,
        limit=limit,
        offset=offset,
    )
    return {
        "exports": [_export_response(e) for e in exports],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/ops/exports",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def create_export_request(
    request: Request,
    body: CreateExportRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        export = _store.create_export_request(
            db,
            export_scope=body.export_scope,
            export_classification=body.export_classification,
            requested_by=actor,
            tenant_id=tenant_id,
            environment_id=body.environment_id,
            export_purpose=body.export_purpose,
            idempotency_key=body.idempotency_key,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _export_response(export)


@router.get(
    "/control-plane/ops/exports/{export_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_export_request(
    request: Request,
    export_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        export = _store.get_export_request(db, export_id=export_id, tenant_id=tenant_id)
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return _export_response(export)


@router.post(
    "/control-plane/ops/exports/{export_id}/transition",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_export_request(
    request: Request,
    export_id: str,
    body: TransitionExportRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        export = _store.transition_export_state(
            db,
            export_id=export_id,
            to_state=body.to_state,
            actor=actor,
            tenant_id=tenant_id,
            approval_reason=body.approval_reason,
            rejection_reason=body.rejection_reason,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _export_response(export)


# ---------------------------------------------------------------------------
# Backup routes
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/ops/backups",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_backup_records(
    request: Request,
    environment_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    backups = _store.list_backup_records(
        db,
        tenant_id=tenant_id,
        environment_id=environment_id,
        limit=limit,
        offset=offset,
    )
    return {
        "backups": [_backup_response(b) for b in backups],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/ops/backups",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def initiate_backup(
    request: Request,
    body: InitiateBackupRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        backup = _store.record_backup(
            db,
            initiated_by=actor,
            tenant_id=tenant_id,
            environment_id=body.environment_id,
            backup_scope=body.backup_scope,
            backup_classification=body.backup_classification,
            retention_policy_id=body.retention_policy_id,
            metadata=body.metadata,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _backup_response(backup)


@router.get(
    "/control-plane/ops/backups/{backup_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_backup_record(
    request: Request,
    backup_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        backup = _store.get_backup_record(db, backup_id=backup_id, tenant_id=tenant_id)
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return _backup_response(backup)


# ---------------------------------------------------------------------------
# Restore routes
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/ops/restores",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_restore_records(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    restores = _store.list_restore_records(
        db,
        tenant_id=tenant_id,
        limit=limit,
        offset=offset,
    )
    return {
        "restores": [_restore_response(r) for r in restores],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/ops/restores",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def initiate_restore(
    request: Request,
    body: InitiateRestoreRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        restore = _store.record_restore_attempt(
            db,
            source_backup_id=body.source_backup_id,
            initiated_by=actor,
            tenant_id=tenant_id,
            target_environment_id=body.target_environment_id,
            restore_scope=body.restore_scope,
            point_in_time_ref=body.point_in_time_ref,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _restore_response(restore)


@router.get(
    "/control-plane/ops/restores/{restore_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_restore_record(
    request: Request,
    restore_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        restore = _store.get_restore_record(
            db, restore_id=restore_id, tenant_id=tenant_id
        )
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return _restore_response(restore)


# ---------------------------------------------------------------------------
# Recovery routes
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/ops/recoveries",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_recovery_records(
    request: Request,
    environment_id: Optional[str] = Query(default=None),
    recovery_state: Optional[RecoveryState] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    records = _store.list_recovery_records(
        db,
        tenant_id=tenant_id,
        environment_id=environment_id,
        recovery_state=recovery_state,
        limit=limit,
        offset=offset,
    )
    return {
        "recoveries": [_recovery_response(r) for r in records],
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/control-plane/ops/recoveries",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    status_code=201,
)
def initiate_recovery(
    request: Request,
    body: InitiateRecoveryRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        record = _store.initiate_recovery(
            db,
            recovery_type=body.recovery_type,
            initiated_by=actor,
            tenant_id=tenant_id,
            environment_id=body.environment_id,
            recovery_trigger=body.recovery_trigger,
            drill_mode=body.drill_mode,
            metadata=body.metadata,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _recovery_response(record)


@router.get(
    "/control-plane/ops/recoveries/{recovery_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_recovery_record(
    request: Request,
    recovery_id: str,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    try:
        record = _store.get_recovery_record(
            db, recovery_id=recovery_id, tenant_id=tenant_id
        )
    except OpsGovernanceError as exc:
        raise _handle_store_error(exc) from exc
    return _recovery_response(record)


@router.post(
    "/control-plane/ops/recoveries/{recovery_id}/transition",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_recovery(
    request: Request,
    recovery_id: str,
    body: TransitionRecoveryRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    actor = _actor_from_request(request)
    try:
        record = _store.transition_recovery_state(
            db,
            recovery_id=recovery_id,
            to_state=body.to_state,
            actor=actor,
            tenant_id=tenant_id,
            failure_reason=body.failure_reason,
        )
        db.commit()
    except OpsGovernanceError as exc:
        db.rollback()
        raise _handle_store_error(exc) from exc
    return _recovery_response(record)
