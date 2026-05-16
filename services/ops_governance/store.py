"""Operational Governance persistence layer (SQLAlchemy).

All queries are tenant-scoped. Platform-level records (tenant_id=None) are
readable by any operator with sufficient scope; tenant-linked records are
only visible within the owning tenant's context.

No mutable module-level state. OpsGovernanceStore is stateless and receives
a Session at call time. All mutations emit an OpsGovernanceAuditEvent before
returning. Optimistic locking (state_version) on all mutable records.

SECURITY: No raw secrets are stored, passed, returned, or logged anywhere.
"""

from __future__ import annotations

import json as _json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from api.db_models import (
    OpsBackupRecord as OpsBackupORM,
    OpsEnvironmentRecord,
    OpsExportRequestRecord,
    OpsGovernanceAuditEventRecord,
    OpsKeyRotationScheduleRecord,
    OpsRecoveryRecord as OpsRecoveryORM,
    OpsRestoreRecord as OpsRestoreORM,
    OpsRetentionPolicyRecord,
    OpsSecretGovernanceRecord,
)
from services.ops_governance.audit import (
    _get_previous_event_hash,
    compute_governance_event_hash,
    emit_governance_event,
)
from services.ops_governance.models import (
    BackupScope,
    BackupState,
    ComplianceClassification,
    EnvironmentLifecycleState,
    EnvironmentType,
    ExportClassification,
    ExportScope,
    ExportState,
    IsolationLevel,
    OpsBackupRecord,
    OpsEnvironment,
    OpsExportRequest,
    OpsGovernanceAuditEvent,
    OpsKeyRotationSchedule,
    OpsRecoveryRecord,
    OpsRestoreRecord,
    OpsRetentionPolicy,
    OpsSecretGovernance,
    RecoveryReadiness,
    RecoveryState,
    RecoveryType,
    ResidencyClassification,
    RestoreScope,
    RestoreState,
    RetentionClassification,
    RetentionState,
    RotationOutcome,
    RotationScheduleState,
    SecretClassification,
    SecretLifecycleState,
    SecretRotationState,
    SecretType,
    ValidationState,
    validate_env_transition,
    validate_export_transition,
    validate_recovery_transition,
    validate_retention_transition,
    validate_secret_transition,
)

log = logging.getLogger("frostgate.ops_governance.store")

_MAX_PAGE = 200
_DEFAULT_PAGE = 50


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class OpsGovernanceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class EnvironmentNotFound(OpsGovernanceError):
    def __init__(self, env_id: str) -> None:
        super().__init__("OPS-001", f"Environment not found: {env_id}")


class SecretGovernanceNotFound(OpsGovernanceError):
    def __init__(self, secret_id: str) -> None:
        super().__init__("OPS-002", f"Secret governance record not found: {secret_id}")


class RetentionPolicyNotFound(OpsGovernanceError):
    def __init__(self, policy_id: str) -> None:
        super().__init__("OPS-003", f"Retention policy not found: {policy_id}")


class ExportRequestNotFound(OpsGovernanceError):
    def __init__(self, export_id: str) -> None:
        super().__init__("OPS-004", f"Export request not found: {export_id}")


class BackupRecordNotFound(OpsGovernanceError):
    def __init__(self, backup_id: str) -> None:
        super().__init__("OPS-005", f"Backup record not found: {backup_id}")


class RestoreRecordNotFound(OpsGovernanceError):
    def __init__(self, restore_id: str) -> None:
        super().__init__("OPS-006", f"Restore record not found: {restore_id}")


class RecoveryRecordNotFound(OpsGovernanceError):
    def __init__(self, recovery_id: str) -> None:
        super().__init__("OPS-007", f"Recovery record not found: {recovery_id}")


class RotationScheduleNotFound(OpsGovernanceError):
    def __init__(self, rotation_id: str) -> None:
        super().__init__("OPS-008", f"Rotation schedule not found: {rotation_id}")


class InvalidStateTransition(OpsGovernanceError):
    def __init__(self, from_state: str, to_state: str, resource: str) -> None:
        super().__init__(
            "OPS-009",
            f"Invalid {resource} transition: {from_state!r} → {to_state!r}",
        )


class ConcurrentModificationError(OpsGovernanceError):
    def __init__(self, resource_id: str) -> None:
        super().__init__(
            "OPS-010",
            f"Resource {resource_id} was modified concurrently — retry the operation",
        )


class DuplicateSlug(OpsGovernanceError):
    def __init__(self, slug: str) -> None:
        super().__init__("OPS-011", f"Environment slug already in use: {slug}")


class LegalHoldViolation(OpsGovernanceError):
    def __init__(self, policy_id: str) -> None:
        super().__init__(
            "OPS-012",
            f"Retention policy {policy_id} is under legal hold — transition blocked",
        )


class ValidationTokenRequired(OpsGovernanceError):
    def __init__(self, env_id: str) -> None:
        super().__init__(
            "OPS-013",
            f"Environment {env_id}: validation_token required for failed_recovery → active transition",
        )


# ---------------------------------------------------------------------------
# ORM → domain converters
# ---------------------------------------------------------------------------


def _env_orm_to_domain(row: OpsEnvironmentRecord) -> OpsEnvironment:
    meta: dict = {}
    if row.metadata_json:
        try:
            meta = _json.loads(row.metadata_json)
        except (ValueError, TypeError):
            meta = {}
    return OpsEnvironment(
        environment_id=row.environment_id,
        tenant_id=row.tenant_id,
        env_name=row.env_name,
        slug=row.slug,
        lifecycle_state=EnvironmentLifecycleState(row.lifecycle_state),
        env_type=EnvironmentType(row.env_type),
        compliance_classification=ComplianceClassification(
            row.compliance_classification
        ),
        isolation_level=IsolationLevel(row.isolation_level),
        residency_classification=ResidencyClassification(row.residency_classification),
        recovery_readiness=RecoveryReadiness(row.recovery_readiness),
        region=row.region,
        validation_token=row.validation_token,
        idempotency_key=row.idempotency_key,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        archived_at=row.archived_at,
        state_version=getattr(row, "state_version", 0) or 0,
        metadata=meta,
    )


def _secret_orm_to_domain(row: OpsSecretGovernanceRecord) -> OpsSecretGovernance:
    policy: dict = {}
    if row.governance_policy_json:
        try:
            policy = _json.loads(row.governance_policy_json)
        except (ValueError, TypeError):
            policy = {}
    return OpsSecretGovernance(
        secret_governance_id=row.secret_governance_id,
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        secret_name=row.secret_name,
        secret_classification=SecretClassification(row.secret_classification),
        secret_type=SecretType(row.secret_type),
        lifecycle_state=SecretLifecycleState(row.lifecycle_state),
        external_provider=row.external_provider,
        external_reference_id=row.external_reference_id,
        owner_scope=row.owner_scope,
        rotation_state=SecretRotationState(row.rotation_state),
        rotation_policy_days=row.rotation_policy_days,
        last_rotated_at=row.last_rotated_at,
        next_rotation_due_at=row.next_rotation_due_at,
        expires_at=row.expires_at,
        idempotency_key=row.idempotency_key,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        state_version=getattr(row, "state_version", 0) or 0,
        governance_policy=policy,
    )


def _rotation_orm_to_domain(
    row: OpsKeyRotationScheduleRecord,
) -> OpsKeyRotationSchedule:
    meta: dict = {}
    if row.metadata_json:
        try:
            meta = _json.loads(row.metadata_json)
        except (ValueError, TypeError):
            meta = {}
    outcome = None
    if row.outcome:
        try:
            outcome = RotationOutcome(row.outcome)
        except ValueError:
            outcome = None
    return OpsKeyRotationSchedule(
        rotation_id=row.rotation_id,
        secret_governance_id=row.secret_governance_id,
        tenant_id=row.tenant_id,
        rotation_state=RotationScheduleState(row.rotation_state),
        scheduled_at=row.scheduled_at,
        initiated_at=row.initiated_at,
        completed_at=row.completed_at,
        failure_reason=row.failure_reason,
        compliance_override=bool(row.compliance_override),
        override_reason=row.override_reason,
        override_approved_by=row.override_approved_by,
        emergency_rotation=bool(row.emergency_rotation),
        waiver_reference=row.waiver_reference,
        initiated_by=row.initiated_by,
        outcome=outcome,
        created_at=row.created_at,
        updated_at=row.updated_at,
        state_version=getattr(row, "state_version", 0) or 0,
        metadata=meta,
    )


def _retention_orm_to_domain(row: OpsRetentionPolicyRecord) -> OpsRetentionPolicy:
    return OpsRetentionPolicy(
        retention_policy_id=row.retention_policy_id,
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        policy_name=row.policy_name,
        retention_classification=RetentionClassification(row.retention_classification),
        retention_state=RetentionState(row.retention_state),
        retention_days=row.retention_days,
        archive_after_days=row.archive_after_days,
        deletion_scheduled_at=row.deletion_scheduled_at,
        archived_at=row.archived_at,
        legal_hold=bool(row.legal_hold),
        legal_hold_reason=row.legal_hold_reason,
        legal_hold_set_by=row.legal_hold_set_by,
        legal_hold_set_at=row.legal_hold_set_at,
        export_restricted=bool(row.export_restricted),
        compliance_policy_ref=row.compliance_policy_ref,
        override_reason=row.override_reason,
        idempotency_key=row.idempotency_key,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        state_version=getattr(row, "state_version", 0) or 0,
    )


def _export_orm_to_domain(row: OpsExportRequestRecord) -> OpsExportRequest:
    flags: dict = {}
    if row.export_restriction_flags:
        try:
            flags = _json.loads(row.export_restriction_flags)
        except (ValueError, TypeError):
            flags = {}
    return OpsExportRequest(
        export_id=row.export_id,
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        export_state=ExportState(row.export_state),
        export_scope=ExportScope(row.export_scope),
        export_classification=ExportClassification(row.export_classification),
        export_purpose=row.export_purpose,
        requested_by=row.requested_by,
        approved_by=row.approved_by,
        rejected_by=row.rejected_by,
        approval_reason=row.approval_reason,
        rejection_reason=row.rejection_reason,
        legal_hold_validated=bool(row.legal_hold_validated),
        residency_validated=bool(row.residency_validated),
        retention_validated=bool(row.retention_validated),
        export_restriction_flags=flags,
        expires_at=row.expires_at,
        completed_at=row.completed_at,
        idempotency_key=row.idempotency_key,
        created_at=row.created_at,
        updated_at=row.updated_at,
        state_version=getattr(row, "state_version", 0) or 0,
    )


def _backup_orm_to_domain(row: OpsBackupORM) -> OpsBackupRecord:
    meta: dict = {}
    if row.metadata_json:
        try:
            meta = _json.loads(row.metadata_json)
        except (ValueError, TypeError):
            meta = {}
    return OpsBackupRecord(
        backup_id=row.backup_id,
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        backup_scope=BackupScope(row.backup_scope),
        backup_classification=ComplianceClassification(row.backup_classification),
        backup_state=BackupState(row.backup_state),
        backup_reference=row.backup_reference,
        retention_policy_id=row.retention_policy_id,
        backup_size_bytes=row.backup_size_bytes,
        checksum_ref=row.checksum_ref,
        initiated_by=row.initiated_by,
        started_at=row.started_at,
        completed_at=row.completed_at,
        expires_at=row.expires_at,
        failure_reason=row.failure_reason,
        created_at=row.created_at,
        state_version=getattr(row, "state_version", 0) or 0,
        metadata=meta,
    )


def _restore_orm_to_domain(row: OpsRestoreORM) -> OpsRestoreRecord:
    meta: dict = {}
    if row.metadata_json:
        try:
            meta = _json.loads(row.metadata_json)
        except (ValueError, TypeError):
            meta = {}
    return OpsRestoreRecord(
        restore_id=row.restore_id,
        tenant_id=row.tenant_id,
        source_backup_id=row.source_backup_id,
        target_environment_id=row.target_environment_id,
        restore_state=RestoreState(row.restore_state),
        restore_scope=RestoreScope(row.restore_scope),
        point_in_time_ref=row.point_in_time_ref,
        validation_state=ValidationState(row.validation_state),
        validation_token=row.validation_token,
        initiated_by=row.initiated_by,
        started_at=row.started_at,
        completed_at=row.completed_at,
        failure_reason=row.failure_reason,
        recovery_lineage_id=row.recovery_lineage_id,
        created_at=row.created_at,
        state_version=getattr(row, "state_version", 0) or 0,
        metadata=meta,
    )


def _recovery_orm_to_domain(row: OpsRecoveryORM) -> OpsRecoveryRecord:
    meta: dict = {}
    if row.metadata_json:
        try:
            meta = _json.loads(row.metadata_json)
        except (ValueError, TypeError):
            meta = {}
    return OpsRecoveryRecord(
        recovery_id=row.recovery_id,
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        recovery_state=RecoveryState(row.recovery_state),
        recovery_type=RecoveryType(row.recovery_type),
        recovery_trigger=row.recovery_trigger,
        validation_state=ValidationState(row.validation_state),
        readiness_classification=RecoveryReadiness(row.readiness_classification),
        initiated_by=row.initiated_by,
        started_at=row.started_at,
        validated_at=row.validated_at,
        completed_at=row.completed_at,
        failure_reason=row.failure_reason,
        failure_count=row.failure_count or 0,
        drill_mode=bool(row.drill_mode),
        created_at=row.created_at,
        state_version=getattr(row, "state_version", 0) or 0,
        metadata=meta,
    )


def _audit_orm_to_domain(row: OpsGovernanceAuditEventRecord) -> OpsGovernanceAuditEvent:
    details: dict = {}
    if row.details_json:
        try:
            details = _json.loads(row.details_json)
        except (ValueError, TypeError):
            details = {}
    return OpsGovernanceAuditEvent(
        event_id=row.event_id,
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        event_type=row.event_type,
        actor=row.actor,
        outcome=row.outcome,
        policy_state=row.policy_state,
        operational_context=row.operational_context,
        failure_reason=row.failure_reason,
        details=details,
        event_hash=getattr(row, "event_hash", None),
        previous_event_hash=getattr(row, "previous_event_hash", None),
        timestamp=row.timestamp,
    )


# ---------------------------------------------------------------------------
# Idempotency helpers
# ---------------------------------------------------------------------------


def _idem_filter(q: Any, model: Any, tenant_id: Optional[str], key: str) -> Any:
    q = q.filter(model.idempotency_key == key)
    if tenant_id is not None:
        q = q.filter(model.tenant_id == tenant_id)
    else:
        q = q.filter(model.tenant_id.is_(None))
    return q


def _tenant_filter(q: Any, model: Any, tenant_id: Optional[str]) -> Any:
    if tenant_id is not None:
        q = q.filter((model.tenant_id == tenant_id) | (model.tenant_id.is_(None)))
    return q


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class OpsGovernanceStore:
    """Persistence operations for operational governance domains.

    Stateless; receives a SQLAlchemy Session at each call.
    All mutations emit an OpsGovernanceAuditEvent before returning.
    """

    # -----------------------------------------------------------------------
    # Environments
    # -----------------------------------------------------------------------

    def create_environment(
        self,
        db: Session,
        *,
        env_name: str,
        slug: str,
        created_by: str,
        tenant_id: Optional[str] = None,
        env_type: EnvironmentType = EnvironmentType.SHARED,
        compliance_classification: ComplianceClassification = ComplianceClassification.STANDARD,
        isolation_level: IsolationLevel = IsolationLevel.STANDARD,
        residency_classification: ResidencyClassification = ResidencyClassification.UNRESTRICTED,
        region: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> OpsEnvironment:
        if idempotency_key is not None:
            existing = _idem_filter(
                db.query(OpsEnvironmentRecord),
                OpsEnvironmentRecord,
                tenant_id,
                idempotency_key,
            ).first()
            if existing is not None:
                return _env_orm_to_domain(existing)

        slug_conflict = (
            db.query(OpsEnvironmentRecord)
            .filter(OpsEnvironmentRecord.slug == slug)
            .first()
        )
        if slug_conflict is not None:
            raise DuplicateSlug(slug)

        env_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        row = OpsEnvironmentRecord(
            environment_id=env_id,
            tenant_id=tenant_id,
            env_name=env_name,
            slug=slug,
            lifecycle_state=EnvironmentLifecycleState.PROVISIONING.value,
            env_type=env_type.value,
            compliance_classification=compliance_classification.value,
            isolation_level=isolation_level.value,
            residency_classification=residency_classification.value,
            recovery_readiness=RecoveryReadiness.UNKNOWN.value,
            region=region,
            idempotency_key=idempotency_key,
            metadata_json=_json.dumps(metadata or {}, sort_keys=True),
            created_by=created_by,
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()
        self._emit(
            db,
            resource_type="environment",
            resource_id=env_id,
            event_type="environment_created",
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            environment_id=env_id,
            now_iso=now_iso,
            details={
                "lifecycle_state": EnvironmentLifecycleState.PROVISIONING.value,
                "env_type": env_type.value,
                "compliance_classification": compliance_classification.value,
                "isolation_level": isolation_level.value,
            },
        )
        return _env_orm_to_domain(row)

    def get_environment(
        self,
        db: Session,
        *,
        env_id: str,
        tenant_id: Optional[str] = None,
    ) -> OpsEnvironment:
        q = _tenant_filter(
            db.query(OpsEnvironmentRecord).filter(
                OpsEnvironmentRecord.environment_id == env_id
            ),
            OpsEnvironmentRecord,
            tenant_id,
        )
        row = q.first()
        if row is None:
            raise EnvironmentNotFound(env_id)
        return _env_orm_to_domain(row)

    def list_environments(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        lifecycle_state: Optional[EnvironmentLifecycleState] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsEnvironment]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(OpsEnvironmentRecord)
        q = _tenant_filter(q, OpsEnvironmentRecord, tenant_id)
        if lifecycle_state is not None:
            q = q.filter(OpsEnvironmentRecord.lifecycle_state == lifecycle_state.value)
        rows = (
            q.order_by(OpsEnvironmentRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_env_orm_to_domain(r) for r in rows]

    def transition_environment_state(
        self,
        db: Session,
        *,
        env_id: str,
        to_state: EnvironmentLifecycleState,
        actor: str,
        tenant_id: Optional[str] = None,
        validation_token: Optional[str] = None,
        recovery_readiness: Optional[RecoveryReadiness] = None,
    ) -> OpsEnvironment:
        env = self.get_environment(db, env_id=env_id, tenant_id=tenant_id)
        from_state = env.lifecycle_state
        try:
            validate_env_transition(from_state, to_state)
        except ValueError as exc:
            raise InvalidStateTransition(
                from_state.value, to_state.value, "environment"
            ) from exc

        # failed_recovery -> active requires validation token.
        if (
            from_state == EnvironmentLifecycleState.FAILED_RECOVERY
            and to_state == EnvironmentLifecycleState.ACTIVE
        ):
            stored_token = env.validation_token
            if not stored_token or validation_token != stored_token:
                raise ValidationTokenRequired(env_id)

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = env.state_version
        updates: dict[str, Any] = {
            "lifecycle_state": to_state.value,
            "state_version": current_version + 1,
            "updated_at": now,
        }
        if to_state == EnvironmentLifecycleState.ARCHIVED:
            updates["archived_at"] = now
        if recovery_readiness is not None:
            updates["recovery_readiness"] = recovery_readiness.value
        if (
            to_state == EnvironmentLifecycleState.ACTIVE
            and from_state == EnvironmentLifecycleState.FAILED_RECOVERY
        ):
            updates["validation_token"] = None  # consumed

        rows_affected = (
            db.query(OpsEnvironmentRecord)
            .filter(
                OpsEnvironmentRecord.environment_id == env_id,
                OpsEnvironmentRecord.state_version == current_version,
            )
            .update(updates, synchronize_session="evaluate")  # type: ignore[arg-type]
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(env_id)
        db.flush()

        row = (
            db.query(OpsEnvironmentRecord)
            .filter(OpsEnvironmentRecord.environment_id == env_id)
            .first()
        )
        self._emit(
            db,
            resource_type="environment",
            resource_id=env_id,
            event_type="environment_state_changed",
            actor=actor,
            outcome="success",
            tenant_id=env.tenant_id,
            environment_id=env_id,
            now_iso=now_iso,
            details={"from_state": from_state.value, "to_state": to_state.value},
        )
        return _env_orm_to_domain(row) if row else env

    def set_environment_validation_token(
        self,
        db: Session,
        *,
        env_id: str,
        actor: str,
        validation_token: str,
        tenant_id: Optional[str] = None,
    ) -> OpsEnvironment:
        """Issue a validation token to allow failed_recovery → active transition."""
        env = self.get_environment(db, env_id=env_id, tenant_id=tenant_id)
        if env.lifecycle_state != EnvironmentLifecycleState.FAILED_RECOVERY:
            raise InvalidStateTransition(
                env.lifecycle_state.value,
                "validation_token_issue",
                "environment",
            )
        now = _utcnow()
        current_version = env.state_version
        rows_affected = (
            db.query(OpsEnvironmentRecord)
            .filter(
                OpsEnvironmentRecord.environment_id == env_id,
                OpsEnvironmentRecord.state_version == current_version,
            )
            .update(
                {
                    "validation_token": validation_token,
                    "state_version": current_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(env_id)
        db.flush()
        row = (
            db.query(OpsEnvironmentRecord)
            .filter(OpsEnvironmentRecord.environment_id == env_id)
            .first()
        )
        self._emit(
            db,
            resource_type="environment",
            resource_id=env_id,
            event_type="environment_validation_token_issued",
            actor=actor,
            outcome="success",
            tenant_id=env.tenant_id,
            environment_id=env_id,
            now_iso=now.isoformat(),
            details={"lifecycle_state": env.lifecycle_state.value},
        )
        return _env_orm_to_domain(row) if row else env

    def list_environment_history(
        self,
        db: Session,
        *,
        env_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsGovernanceAuditEvent]:
        self.get_environment(db, env_id=env_id, tenant_id=tenant_id)
        limit = min(limit, _MAX_PAGE)
        rows = (
            db.query(OpsGovernanceAuditEventRecord)
            .filter(
                OpsGovernanceAuditEventRecord.resource_type == "environment",
                OpsGovernanceAuditEventRecord.resource_id == env_id,
            )
            .order_by(OpsGovernanceAuditEventRecord.timestamp.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_audit_orm_to_domain(r) for r in rows]

    # -----------------------------------------------------------------------
    # Secret governance
    # -----------------------------------------------------------------------

    def register_secret_governance(
        self,
        db: Session,
        *,
        secret_name: str,
        secret_classification: SecretClassification,
        secret_type: SecretType,
        created_by: str,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        external_provider: Optional[str] = None,
        external_reference_id: Optional[str] = None,
        owner_scope: Optional[str] = None,
        rotation_policy_days: Optional[int] = None,
        expires_at: Optional[datetime] = None,
        governance_policy: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
    ) -> OpsSecretGovernance:
        if idempotency_key is not None:
            existing = _idem_filter(
                db.query(OpsSecretGovernanceRecord),
                OpsSecretGovernanceRecord,
                tenant_id,
                idempotency_key,
            ).first()
            if existing is not None:
                return _secret_orm_to_domain(existing)

        secret_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        row = OpsSecretGovernanceRecord(
            secret_governance_id=secret_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            secret_name=secret_name,
            secret_classification=secret_classification.value,
            secret_type=secret_type.value,
            lifecycle_state=SecretLifecycleState.ACTIVE.value,
            external_provider=external_provider,
            external_reference_id=external_reference_id,
            owner_scope=owner_scope,
            rotation_state=SecretRotationState.NOT_SCHEDULED.value,
            rotation_policy_days=rotation_policy_days,
            expires_at=expires_at,
            governance_policy_json=_json.dumps(governance_policy or {}, sort_keys=True),
            idempotency_key=idempotency_key,
            created_by=created_by,
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()
        self._emit(
            db,
            resource_type="secret_governance",
            resource_id=secret_id,
            event_type="secret_governance_registered",
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            environment_id=environment_id,
            now_iso=now_iso,
            details={
                "secret_classification": secret_classification.value,
                "secret_type": secret_type.value,
                "lifecycle_state": SecretLifecycleState.ACTIVE.value,
            },
        )
        return _secret_orm_to_domain(row)

    def get_secret_governance(
        self,
        db: Session,
        *,
        secret_id: str,
        tenant_id: Optional[str] = None,
    ) -> OpsSecretGovernance:
        q = _tenant_filter(
            db.query(OpsSecretGovernanceRecord).filter(
                OpsSecretGovernanceRecord.secret_governance_id == secret_id
            ),
            OpsSecretGovernanceRecord,
            tenant_id,
        )
        row = q.first()
        if row is None:
            raise SecretGovernanceNotFound(secret_id)
        return _secret_orm_to_domain(row)

    def list_secret_governance(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        lifecycle_state: Optional[SecretLifecycleState] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsSecretGovernance]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(OpsSecretGovernanceRecord)
        q = _tenant_filter(q, OpsSecretGovernanceRecord, tenant_id)
        if environment_id is not None:
            q = q.filter(OpsSecretGovernanceRecord.environment_id == environment_id)
        if lifecycle_state is not None:
            q = q.filter(
                OpsSecretGovernanceRecord.lifecycle_state == lifecycle_state.value
            )
        rows = (
            q.order_by(OpsSecretGovernanceRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_secret_orm_to_domain(r) for r in rows]

    def transition_secret_state(
        self,
        db: Session,
        *,
        secret_id: str,
        to_state: SecretLifecycleState,
        actor: str,
        tenant_id: Optional[str] = None,
    ) -> OpsSecretGovernance:
        secret = self.get_secret_governance(
            db, secret_id=secret_id, tenant_id=tenant_id
        )
        from_state = secret.lifecycle_state
        try:
            validate_secret_transition(from_state, to_state)
        except ValueError as exc:
            raise InvalidStateTransition(
                from_state.value, to_state.value, "secret"
            ) from exc

        now = _utcnow()
        current_version = secret.state_version
        rows_affected = (
            db.query(OpsSecretGovernanceRecord)
            .filter(
                OpsSecretGovernanceRecord.secret_governance_id == secret_id,
                OpsSecretGovernanceRecord.state_version == current_version,
            )
            .update(
                {
                    "lifecycle_state": to_state.value,
                    "state_version": current_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(secret_id)
        db.flush()
        row = (
            db.query(OpsSecretGovernanceRecord)
            .filter(OpsSecretGovernanceRecord.secret_governance_id == secret_id)
            .first()
        )
        self._emit(
            db,
            resource_type="secret_governance",
            resource_id=secret_id,
            event_type="secret_state_changed",
            actor=actor,
            outcome="success",
            tenant_id=secret.tenant_id,
            environment_id=secret.environment_id,
            now_iso=now.isoformat(),
            details={"from_state": from_state.value, "to_state": to_state.value},
        )
        return _secret_orm_to_domain(row) if row else secret

    def schedule_key_rotation(
        self,
        db: Session,
        *,
        secret_id: str,
        scheduled_at: datetime,
        actor: str,
        tenant_id: Optional[str] = None,
        emergency_rotation: bool = False,
        compliance_override: bool = False,
        override_reason: Optional[str] = None,
        override_approved_by: Optional[str] = None,
        waiver_reference: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> OpsKeyRotationSchedule:
        secret = self.get_secret_governance(
            db, secret_id=secret_id, tenant_id=tenant_id
        )
        rotation_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        state = (
            RotationScheduleState.EMERGENCY
            if emergency_rotation
            else RotationScheduleState.SCHEDULED
        )
        row = OpsKeyRotationScheduleRecord(
            rotation_id=rotation_id,
            secret_governance_id=secret_id,
            tenant_id=secret.tenant_id,
            rotation_state=state.value,
            scheduled_at=scheduled_at,
            compliance_override=compliance_override,
            override_reason=override_reason,
            override_approved_by=override_approved_by,
            emergency_rotation=emergency_rotation,
            waiver_reference=waiver_reference,
            metadata_json=_json.dumps(metadata or {}, sort_keys=True),
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        # Advance secret rotation_state.
        now2 = _utcnow()
        new_rotation_state = (
            SecretRotationState.EMERGENCY
            if emergency_rotation
            else SecretRotationState.SCHEDULED
        )
        db.query(OpsSecretGovernanceRecord).filter(
            OpsSecretGovernanceRecord.secret_governance_id == secret_id
        ).update(
            {
                "rotation_state": new_rotation_state.value,
                "next_rotation_due_at": scheduled_at,
                "updated_at": now2,
                "state_version": secret.state_version + 1,
            },
            synchronize_session="evaluate",
        )
        db.flush()
        self._emit(
            db,
            resource_type="key_rotation",
            resource_id=rotation_id,
            event_type="key_rotation_scheduled",
            actor=actor,
            outcome="success",
            tenant_id=secret.tenant_id,
            now_iso=now_iso,
            details={
                "rotation_state": state.value,
                "secret_type": secret.secret_type.value,
            },
        )
        return _rotation_orm_to_domain(row)

    def record_rotation_outcome(
        self,
        db: Session,
        *,
        rotation_id: str,
        outcome: RotationOutcome,
        actor: str,
        tenant_id: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ) -> OpsKeyRotationSchedule:
        q = db.query(OpsKeyRotationScheduleRecord).filter(
            OpsKeyRotationScheduleRecord.rotation_id == rotation_id
        )
        if tenant_id is not None:
            q = q.filter(
                (OpsKeyRotationScheduleRecord.tenant_id == tenant_id)
                | (OpsKeyRotationScheduleRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise RotationScheduleNotFound(rotation_id)

        now = _utcnow()
        current_version = getattr(row, "state_version", 0) or 0
        new_state = (
            RotationScheduleState.COMPLETED
            if outcome == RotationOutcome.SUCCESS
            else RotationScheduleState.FAILED
        )
        rows_affected = (
            db.query(OpsKeyRotationScheduleRecord)
            .filter(
                OpsKeyRotationScheduleRecord.rotation_id == rotation_id,
                OpsKeyRotationScheduleRecord.state_version == current_version,
            )
            .update(
                {
                    "rotation_state": new_state.value,
                    "outcome": outcome.value,
                    "completed_at": now,
                    "failure_reason": failure_reason,
                    "updated_at": now,
                    "state_version": current_version + 1,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(rotation_id)

        # Update parent secret rotation metadata.
        if outcome == RotationOutcome.SUCCESS:
            db.query(OpsSecretGovernanceRecord).filter(
                OpsSecretGovernanceRecord.secret_governance_id
                == row.secret_governance_id
            ).update(
                {
                    "rotation_state": SecretRotationState.COMPLETED.value,
                    "last_rotated_at": now,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        else:
            db.query(OpsSecretGovernanceRecord).filter(
                OpsSecretGovernanceRecord.secret_governance_id
                == row.secret_governance_id
            ).update(
                {"rotation_state": SecretRotationState.FAILED.value, "updated_at": now},
                synchronize_session="evaluate",
            )
        db.flush()
        updated = (
            db.query(OpsKeyRotationScheduleRecord)
            .filter(OpsKeyRotationScheduleRecord.rotation_id == rotation_id)
            .first()
        )
        self._emit(
            db,
            resource_type="key_rotation",
            resource_id=rotation_id,
            event_type="key_rotation_outcome_recorded",
            actor=actor,
            outcome="success" if outcome == RotationOutcome.SUCCESS else "failure",
            tenant_id=row.tenant_id,
            now_iso=now.isoformat(),
            details={"rotation_state": new_state.value},
        )
        return (
            _rotation_orm_to_domain(updated)
            if updated
            else _rotation_orm_to_domain(row)
        )

    # -----------------------------------------------------------------------
    # Retention policies
    # -----------------------------------------------------------------------

    def create_retention_policy(
        self,
        db: Session,
        *,
        policy_name: str,
        retention_days: int,
        created_by: str,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        retention_classification: RetentionClassification = RetentionClassification.STANDARD,
        archive_after_days: Optional[int] = None,
        export_restricted: bool = False,
        compliance_policy_ref: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> OpsRetentionPolicy:
        if idempotency_key is not None:
            existing = _idem_filter(
                db.query(OpsRetentionPolicyRecord),
                OpsRetentionPolicyRecord,
                tenant_id,
                idempotency_key,
            ).first()
            if existing is not None:
                return _retention_orm_to_domain(existing)

        policy_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        row = OpsRetentionPolicyRecord(
            retention_policy_id=policy_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            policy_name=policy_name,
            retention_classification=retention_classification.value,
            retention_state=RetentionState.ACTIVE.value,
            retention_days=retention_days,
            archive_after_days=archive_after_days,
            legal_hold=False,
            export_restricted=export_restricted,
            compliance_policy_ref=compliance_policy_ref,
            idempotency_key=idempotency_key,
            created_by=created_by,
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()
        self._emit(
            db,
            resource_type="retention_policy",
            resource_id=policy_id,
            event_type="retention_policy_created",
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            environment_id=environment_id,
            now_iso=now_iso,
            details={
                "retention_state": RetentionState.ACTIVE.value,
                "retention_classification": retention_classification.value,
            },
        )
        return _retention_orm_to_domain(row)

    def get_retention_policy(
        self,
        db: Session,
        *,
        policy_id: str,
        tenant_id: Optional[str] = None,
    ) -> OpsRetentionPolicy:
        q = _tenant_filter(
            db.query(OpsRetentionPolicyRecord).filter(
                OpsRetentionPolicyRecord.retention_policy_id == policy_id
            ),
            OpsRetentionPolicyRecord,
            tenant_id,
        )
        row = q.first()
        if row is None:
            raise RetentionPolicyNotFound(policy_id)
        return _retention_orm_to_domain(row)

    def list_retention_policies(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        retention_state: Optional[RetentionState] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsRetentionPolicy]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(OpsRetentionPolicyRecord)
        q = _tenant_filter(q, OpsRetentionPolicyRecord, tenant_id)
        if environment_id is not None:
            q = q.filter(OpsRetentionPolicyRecord.environment_id == environment_id)
        if retention_state is not None:
            q = q.filter(
                OpsRetentionPolicyRecord.retention_state == retention_state.value
            )
        rows = (
            q.order_by(OpsRetentionPolicyRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_retention_orm_to_domain(r) for r in rows]

    def transition_retention_state(
        self,
        db: Session,
        *,
        policy_id: str,
        to_state: RetentionState,
        actor: str,
        tenant_id: Optional[str] = None,
        deletion_scheduled_at: Optional[datetime] = None,
        override_reason: Optional[str] = None,
    ) -> OpsRetentionPolicy:
        policy = self.get_retention_policy(db, policy_id=policy_id, tenant_id=tenant_id)

        # Legal hold blocks all deletion-path transitions.
        if policy.legal_hold and to_state in (
            RetentionState.SCHEDULED_FOR_DELETION,
            RetentionState.SCHEDULED_FOR_ARCHIVE,
        ):
            raise LegalHoldViolation(policy_id)

        from_state = policy.retention_state
        try:
            validate_retention_transition(from_state, to_state)
        except ValueError as exc:
            raise InvalidStateTransition(
                from_state.value, to_state.value, "retention"
            ) from exc

        now = _utcnow()
        current_version = policy.state_version
        updates: dict[str, Any] = {
            "retention_state": to_state.value,
            "state_version": current_version + 1,
            "updated_at": now,
        }
        if to_state == RetentionState.ARCHIVED:
            updates["archived_at"] = now
        if to_state == RetentionState.SCHEDULED_FOR_DELETION and deletion_scheduled_at:
            updates["deletion_scheduled_at"] = deletion_scheduled_at
        if to_state == RetentionState.LEGAL_HOLD:
            updates["legal_hold"] = True
        if override_reason:
            updates["override_reason"] = override_reason

        rows_affected = (
            db.query(OpsRetentionPolicyRecord)
            .filter(
                OpsRetentionPolicyRecord.retention_policy_id == policy_id,
                OpsRetentionPolicyRecord.state_version == current_version,
            )
            .update(updates, synchronize_session="evaluate")  # type: ignore[arg-type]
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(policy_id)
        db.flush()
        row = (
            db.query(OpsRetentionPolicyRecord)
            .filter(OpsRetentionPolicyRecord.retention_policy_id == policy_id)
            .first()
        )
        self._emit(
            db,
            resource_type="retention_policy",
            resource_id=policy_id,
            event_type="retention_state_changed",
            actor=actor,
            outcome="success",
            tenant_id=policy.tenant_id,
            environment_id=policy.environment_id,
            now_iso=now.isoformat(),
            details={"from_state": from_state.value, "to_state": to_state.value},
        )
        return _retention_orm_to_domain(row) if row else policy

    def set_legal_hold(
        self,
        db: Session,
        *,
        policy_id: str,
        actor: str,
        reason: str,
        tenant_id: Optional[str] = None,
    ) -> OpsRetentionPolicy:
        policy = self.get_retention_policy(db, policy_id=policy_id, tenant_id=tenant_id)
        now = _utcnow()
        current_version = policy.state_version
        rows_affected = (
            db.query(OpsRetentionPolicyRecord)
            .filter(
                OpsRetentionPolicyRecord.retention_policy_id == policy_id,
                OpsRetentionPolicyRecord.state_version == current_version,
            )
            .update(
                {
                    "legal_hold": True,
                    "legal_hold_reason": reason,
                    "legal_hold_set_by": actor,
                    "legal_hold_set_at": now,
                    "retention_state": RetentionState.LEGAL_HOLD.value,
                    "state_version": current_version + 1,
                    "updated_at": now,
                },
                synchronize_session="evaluate",
            )
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(policy_id)
        db.flush()
        row = (
            db.query(OpsRetentionPolicyRecord)
            .filter(OpsRetentionPolicyRecord.retention_policy_id == policy_id)
            .first()
        )
        self._emit(
            db,
            resource_type="retention_policy",
            resource_id=policy_id,
            event_type="legal_hold_set",
            actor=actor,
            outcome="success",
            tenant_id=policy.tenant_id,
            environment_id=policy.environment_id,
            now_iso=now.isoformat(),
            details={
                "retention_state": RetentionState.LEGAL_HOLD.value,
                "legal_hold": True,
            },
        )
        return _retention_orm_to_domain(row) if row else policy

    # -----------------------------------------------------------------------
    # Export requests
    # -----------------------------------------------------------------------

    def create_export_request(
        self,
        db: Session,
        *,
        export_scope: ExportScope,
        export_classification: ExportClassification,
        requested_by: str,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        export_purpose: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        idempotency_key: Optional[str] = None,
    ) -> OpsExportRequest:
        if idempotency_key is not None:
            existing = _idem_filter(
                db.query(OpsExportRequestRecord),
                OpsExportRequestRecord,
                tenant_id,
                idempotency_key,
            ).first()
            if existing is not None:
                return _export_orm_to_domain(existing)

        export_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        row = OpsExportRequestRecord(
            export_id=export_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            export_state=ExportState.REQUESTED.value,
            export_scope=export_scope.value,
            export_classification=export_classification.value,
            export_purpose=export_purpose,
            requested_by=requested_by,
            legal_hold_validated=False,
            residency_validated=False,
            retention_validated=False,
            export_restriction_flags=_json.dumps({}),
            expires_at=expires_at,
            idempotency_key=idempotency_key,
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()
        self._emit(
            db,
            resource_type="export_request",
            resource_id=export_id,
            event_type="export_requested",
            actor=requested_by,
            outcome="success",
            tenant_id=tenant_id,
            environment_id=environment_id,
            now_iso=now_iso,
            details={
                "export_state": ExportState.REQUESTED.value,
                "export_scope": export_scope.value,
                "export_classification": export_classification.value,
            },
        )
        return _export_orm_to_domain(row)

    def get_export_request(
        self,
        db: Session,
        *,
        export_id: str,
        tenant_id: Optional[str] = None,
    ) -> OpsExportRequest:
        q = _tenant_filter(
            db.query(OpsExportRequestRecord).filter(
                OpsExportRequestRecord.export_id == export_id
            ),
            OpsExportRequestRecord,
            tenant_id,
        )
        row = q.first()
        if row is None:
            raise ExportRequestNotFound(export_id)
        return _export_orm_to_domain(row)

    def list_export_requests(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        export_state: Optional[ExportState] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsExportRequest]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(OpsExportRequestRecord)
        q = _tenant_filter(q, OpsExportRequestRecord, tenant_id)
        if environment_id is not None:
            q = q.filter(OpsExportRequestRecord.environment_id == environment_id)
        if export_state is not None:
            q = q.filter(OpsExportRequestRecord.export_state == export_state.value)
        rows = (
            q.order_by(OpsExportRequestRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_export_orm_to_domain(r) for r in rows]

    def transition_export_state(
        self,
        db: Session,
        *,
        export_id: str,
        to_state: ExportState,
        actor: str,
        tenant_id: Optional[str] = None,
        approval_reason: Optional[str] = None,
        rejection_reason: Optional[str] = None,
        legal_hold_validated: Optional[bool] = None,
        residency_validated: Optional[bool] = None,
        retention_validated: Optional[bool] = None,
    ) -> OpsExportRequest:
        export = self.get_export_request(db, export_id=export_id, tenant_id=tenant_id)
        from_state = export.export_state
        try:
            validate_export_transition(from_state, to_state)
        except ValueError as exc:
            raise InvalidStateTransition(
                from_state.value, to_state.value, "export"
            ) from exc

        now = _utcnow()
        current_version = export.state_version
        updates: dict[str, Any] = {
            "export_state": to_state.value,
            "state_version": current_version + 1,
            "updated_at": now,
        }
        if to_state == ExportState.APPROVED:
            updates["approved_by"] = actor
            updates["approval_reason"] = approval_reason
        if to_state == ExportState.REJECTED:
            updates["rejected_by"] = actor
            updates["rejection_reason"] = rejection_reason
        if to_state == ExportState.COMPLETED:
            updates["completed_at"] = now
        if legal_hold_validated is not None:
            updates["legal_hold_validated"] = legal_hold_validated
        if residency_validated is not None:
            updates["residency_validated"] = residency_validated
        if retention_validated is not None:
            updates["retention_validated"] = retention_validated

        rows_affected = (
            db.query(OpsExportRequestRecord)
            .filter(
                OpsExportRequestRecord.export_id == export_id,
                OpsExportRequestRecord.state_version == current_version,
            )
            .update(updates, synchronize_session="evaluate")  # type: ignore[arg-type]
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(export_id)
        db.flush()
        row = (
            db.query(OpsExportRequestRecord)
            .filter(OpsExportRequestRecord.export_id == export_id)
            .first()
        )
        self._emit(
            db,
            resource_type="export_request",
            resource_id=export_id,
            event_type="export_state_changed",
            actor=actor,
            outcome="success",
            tenant_id=export.tenant_id,
            environment_id=export.environment_id,
            now_iso=now.isoformat(),
            details={
                "from_state": from_state.value,
                "to_state": to_state.value,
                "export_scope": export.export_scope.value,
            },
        )
        return _export_orm_to_domain(row) if row else export

    # -----------------------------------------------------------------------
    # Backup records
    # -----------------------------------------------------------------------

    def record_backup(
        self,
        db: Session,
        *,
        backup_scope: BackupScope,
        backup_classification: ComplianceClassification,
        initiated_by: str,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        backup_reference: Optional[str] = None,
        retention_policy_id: Optional[str] = None,
        backup_size_bytes: Optional[int] = None,
        checksum_ref: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[dict] = None,
    ) -> OpsBackupRecord:
        backup_id = str(uuid.uuid4())
        now = _utcnow()
        row = OpsBackupORM(
            backup_id=backup_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            backup_scope=backup_scope.value,
            backup_classification=backup_classification.value,
            backup_state=BackupState.INITIATED.value,
            backup_reference=backup_reference,
            retention_policy_id=retention_policy_id,
            backup_size_bytes=backup_size_bytes,
            checksum_ref=checksum_ref,
            initiated_by=initiated_by,
            started_at=now,
            expires_at=expires_at,
            metadata_json=_json.dumps(metadata or {}, sort_keys=True),
            created_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()
        self._emit(
            db,
            resource_type="backup",
            resource_id=backup_id,
            event_type="backup_initiated",
            actor=initiated_by,
            outcome="success",
            tenant_id=tenant_id,
            environment_id=environment_id,
            now_iso=now.isoformat(),
            details={
                "backup_scope": backup_scope.value,
                "backup_state": BackupState.INITIATED.value,
                "backup_classification": backup_classification.value,
            },
        )
        return _backup_orm_to_domain(row)

    def get_backup_record(
        self,
        db: Session,
        *,
        backup_id: str,
        tenant_id: Optional[str] = None,
    ) -> OpsBackupRecord:
        q = _tenant_filter(
            db.query(OpsBackupORM).filter(OpsBackupORM.backup_id == backup_id),
            OpsBackupORM,
            tenant_id,
        )
        row = q.first()
        if row is None:
            raise BackupRecordNotFound(backup_id)
        return _backup_orm_to_domain(row)

    def list_backup_records(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsBackupRecord]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(OpsBackupORM)
        q = _tenant_filter(q, OpsBackupORM, tenant_id)
        if environment_id is not None:
            q = q.filter(OpsBackupORM.environment_id == environment_id)
        rows = (
            q.order_by(OpsBackupORM.started_at.desc()).offset(offset).limit(limit).all()
        )
        return [_backup_orm_to_domain(r) for r in rows]

    # -----------------------------------------------------------------------
    # Restore records
    # -----------------------------------------------------------------------

    def record_restore_attempt(
        self,
        db: Session,
        *,
        initiated_by: str,
        restore_scope: RestoreScope = RestoreScope.FULL,
        tenant_id: Optional[str] = None,
        source_backup_id: Optional[str] = None,
        target_environment_id: Optional[str] = None,
        point_in_time_ref: Optional[str] = None,
        validation_token: Optional[str] = None,
        recovery_lineage_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> OpsRestoreRecord:
        restore_id = str(uuid.uuid4())
        now = _utcnow()
        row = OpsRestoreORM(
            restore_id=restore_id,
            tenant_id=tenant_id,
            source_backup_id=source_backup_id,
            target_environment_id=target_environment_id,
            restore_state=RestoreState.INITIATED.value,
            restore_scope=restore_scope.value,
            point_in_time_ref=point_in_time_ref,
            validation_state=ValidationState.PENDING.value,
            validation_token=validation_token,
            initiated_by=initiated_by,
            started_at=now,
            recovery_lineage_id=recovery_lineage_id,
            metadata_json=_json.dumps(metadata or {}, sort_keys=True),
            created_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()
        self._emit(
            db,
            resource_type="restore",
            resource_id=restore_id,
            event_type="restore_initiated",
            actor=initiated_by,
            outcome="success",
            tenant_id=tenant_id,
            now_iso=now.isoformat(),
            details={
                "restore_state": RestoreState.INITIATED.value,
                "restore_scope": restore_scope.value,
            },
        )
        return _restore_orm_to_domain(row)

    def get_restore_record(
        self,
        db: Session,
        *,
        restore_id: str,
        tenant_id: Optional[str] = None,
    ) -> OpsRestoreRecord:
        q = _tenant_filter(
            db.query(OpsRestoreORM).filter(OpsRestoreORM.restore_id == restore_id),
            OpsRestoreORM,
            tenant_id,
        )
        row = q.first()
        if row is None:
            raise RestoreRecordNotFound(restore_id)
        return _restore_orm_to_domain(row)

    def list_restore_records(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsRestoreRecord]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(OpsRestoreORM)
        q = _tenant_filter(q, OpsRestoreORM, tenant_id)
        if environment_id is not None:
            q = q.filter(OpsRestoreORM.target_environment_id == environment_id)
        rows = (
            q.order_by(OpsRestoreORM.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_restore_orm_to_domain(r) for r in rows]

    # -----------------------------------------------------------------------
    # Recovery records
    # -----------------------------------------------------------------------

    def initiate_recovery(
        self,
        db: Session,
        *,
        initiated_by: str,
        recovery_type: RecoveryType = RecoveryType.STANDARD,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        recovery_trigger: Optional[str] = None,
        drill_mode: bool = False,
        metadata: Optional[dict] = None,
    ) -> OpsRecoveryRecord:
        recovery_id = str(uuid.uuid4())
        now = _utcnow()
        row = OpsRecoveryORM(
            recovery_id=recovery_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            recovery_state=RecoveryState.INITIATED.value,
            recovery_type=recovery_type.value,
            recovery_trigger=recovery_trigger,
            validation_state=ValidationState.PENDING.value,
            readiness_classification=RecoveryReadiness.UNKNOWN.value,
            initiated_by=initiated_by,
            started_at=now,
            failure_count=0,
            drill_mode=drill_mode,
            metadata_json=_json.dumps(metadata or {}, sort_keys=True),
            created_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()
        self._emit(
            db,
            resource_type="recovery",
            resource_id=recovery_id,
            event_type="recovery_initiated",
            actor=initiated_by,
            outcome="success",
            tenant_id=tenant_id,
            environment_id=environment_id,
            now_iso=now.isoformat(),
            details={
                "recovery_state": RecoveryState.INITIATED.value,
                "recovery_type": recovery_type.value,
                "drill_mode": drill_mode,
            },
        )
        return _recovery_orm_to_domain(row)

    def get_recovery_record(
        self,
        db: Session,
        *,
        recovery_id: str,
        tenant_id: Optional[str] = None,
    ) -> OpsRecoveryRecord:
        q = _tenant_filter(
            db.query(OpsRecoveryORM).filter(OpsRecoveryORM.recovery_id == recovery_id),
            OpsRecoveryORM,
            tenant_id,
        )
        row = q.first()
        if row is None:
            raise RecoveryRecordNotFound(recovery_id)
        return _recovery_orm_to_domain(row)

    def list_recovery_records(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        recovery_state: Optional[RecoveryState] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[OpsRecoveryRecord]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(OpsRecoveryORM)
        q = _tenant_filter(q, OpsRecoveryORM, tenant_id)
        if environment_id is not None:
            q = q.filter(OpsRecoveryORM.environment_id == environment_id)
        if recovery_state is not None:
            q = q.filter(OpsRecoveryORM.recovery_state == recovery_state.value)
        rows = (
            q.order_by(OpsRecoveryORM.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_recovery_orm_to_domain(r) for r in rows]

    def transition_recovery_state(
        self,
        db: Session,
        *,
        recovery_id: str,
        to_state: RecoveryState,
        actor: str,
        tenant_id: Optional[str] = None,
        validation_state: Optional[ValidationState] = None,
        readiness_classification: Optional[RecoveryReadiness] = None,
        failure_reason: Optional[str] = None,
    ) -> OpsRecoveryRecord:
        record = self.get_recovery_record(
            db, recovery_id=recovery_id, tenant_id=tenant_id
        )
        from_state = record.recovery_state
        try:
            validate_recovery_transition(from_state, to_state)
        except ValueError as exc:
            raise InvalidStateTransition(
                from_state.value, to_state.value, "recovery"
            ) from exc

        now = _utcnow()
        current_version = record.state_version
        updates: dict[str, Any] = {
            "recovery_state": to_state.value,
            "state_version": current_version + 1,
            "updated_at": now,
        }
        if to_state == RecoveryState.VALIDATED:
            updates["validated_at"] = now
        if to_state in (
            RecoveryState.COMPLETED,
            RecoveryState.FAILED,
            RecoveryState.ABANDONED,
        ):
            updates["completed_at"] = now
        if to_state == RecoveryState.FAILED:
            updates["failure_count"] = (record.failure_count or 0) + 1
            updates["failure_reason"] = failure_reason
        if validation_state is not None:
            updates["validation_state"] = validation_state.value
        if readiness_classification is not None:
            updates["readiness_classification"] = readiness_classification.value

        rows_affected = (
            db.query(OpsRecoveryORM)
            .filter(
                OpsRecoveryORM.recovery_id == recovery_id,
                OpsRecoveryORM.state_version == current_version,
            )
            .update(updates, synchronize_session="evaluate")  # type: ignore[arg-type]
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(recovery_id)
        db.flush()
        row = (
            db.query(OpsRecoveryORM)
            .filter(OpsRecoveryORM.recovery_id == recovery_id)
            .first()
        )
        self._emit(
            db,
            resource_type="recovery",
            resource_id=recovery_id,
            event_type="recovery_state_changed",
            actor=actor,
            outcome="success" if to_state != RecoveryState.FAILED else "failure",
            tenant_id=record.tenant_id,
            environment_id=record.environment_id,
            now_iso=now.isoformat(),
            details={
                "from_state": from_state.value,
                "to_state": to_state.value,
                "recovery_type": record.recovery_type.value,
            },
        )
        return _recovery_orm_to_domain(row) if row else record

    # -----------------------------------------------------------------------
    # Internal audit emission
    # -----------------------------------------------------------------------

    def _emit(
        self,
        db: Session,
        *,
        resource_type: str,
        resource_id: str,
        event_type: str,
        actor: str,
        outcome: str,
        now_iso: str,
        tenant_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        policy_state: Optional[str] = None,
        operational_context: Optional[str] = None,
        failure_reason: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        event_id = str(uuid.uuid4())
        details_json = _json.dumps(details or {}, sort_keys=True)
        previous_hash = _get_previous_event_hash(db, resource_id)
        event_hash = compute_governance_event_hash(
            event_id=event_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type=event_type,
            actor=actor,
            timestamp_iso=now_iso,
            outcome=outcome,
            previous_event_hash=previous_hash,
        )
        event_row = OpsGovernanceAuditEventRecord(
            event_id=event_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type=event_type,
            actor=actor,
            outcome=outcome,
            policy_state=policy_state,
            operational_context=operational_context,
            failure_reason=failure_reason,
            details_json=details_json,
            event_hash=event_hash,
            previous_event_hash=previous_hash,
            timestamp=_utcnow(),
        )
        db.add(event_row)
        db.flush()
        emit_governance_event(
            event_id=event_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type=event_type,
            actor=actor,
            timestamp_iso=now_iso,
            outcome=outcome,
            tenant_id=tenant_id,
            environment_id=environment_id,
            policy_state=policy_state,
            operational_context=operational_context,
            failure_reason=failure_reason,
            details=details,
            event_hash=event_hash,
            previous_event_hash=previous_hash,
        )
