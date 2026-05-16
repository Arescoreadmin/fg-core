"""Operational Governance domain models — pure Python, no I/O, no SQLAlchemy.

All identifiers are immutable after creation. State transitions are gated by
VALID_*_TRANSITIONS and must be recorded as OpsGovernanceAuditEvents.
No mutable module-level state. No raw secrets stored or passed through any model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Environment enumerations
# ---------------------------------------------------------------------------


class EnvironmentLifecycleState(str, Enum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    RESTRICTED = "restricted"
    ARCHIVED = "archived"
    FAILED_RECOVERY = "failed_recovery"


class EnvironmentType(str, Enum):
    SHARED = "shared"
    DEDICATED = "dedicated"
    REGULATED_DEDICATED = "regulated_dedicated"
    SOVEREIGN = "sovereign"
    DR_STANDBY = "dr_standby"


class IsolationLevel(str, Enum):
    STANDARD = "standard"
    NETWORK_ISOLATED = "network_isolated"
    PROCESS_ISOLATED = "process_isolated"
    HARDWARE_ISOLATED = "hardware_isolated"


class ResidencyClassification(str, Enum):
    UNRESTRICTED = "unrestricted"
    REGIONAL = "regional"
    SOVEREIGN = "sovereign"
    AIR_GAPPED = "air_gapped"


class RecoveryReadiness(str, Enum):
    UNKNOWN = "unknown"
    NOT_READY = "not_ready"
    PARTIAL = "partial"
    READY = "ready"
    VALIDATED = "validated"


# ---------------------------------------------------------------------------
# Environment FSM
# ---------------------------------------------------------------------------

VALID_ENV_TRANSITIONS: dict[
    EnvironmentLifecycleState, frozenset[EnvironmentLifecycleState]
] = {
    EnvironmentLifecycleState.PROVISIONING: frozenset(
        {
            EnvironmentLifecycleState.ACTIVE,
            EnvironmentLifecycleState.FAILED_RECOVERY,
        }
    ),
    EnvironmentLifecycleState.ACTIVE: frozenset(
        {
            EnvironmentLifecycleState.MAINTENANCE,
            EnvironmentLifecycleState.RESTRICTED,
            EnvironmentLifecycleState.ARCHIVED,
        }
    ),
    EnvironmentLifecycleState.MAINTENANCE: frozenset(
        {
            EnvironmentLifecycleState.ACTIVE,
            EnvironmentLifecycleState.FAILED_RECOVERY,
        }
    ),
    EnvironmentLifecycleState.RESTRICTED: frozenset(
        {
            EnvironmentLifecycleState.MAINTENANCE,
            EnvironmentLifecycleState.ARCHIVED,
        }
    ),
    # failed_recovery -> active requires validation_token; blocked at store layer.
    EnvironmentLifecycleState.FAILED_RECOVERY: frozenset(
        {
            EnvironmentLifecycleState.ACTIVE,
            EnvironmentLifecycleState.ARCHIVED,
        }
    ),
    EnvironmentLifecycleState.ARCHIVED: frozenset(),  # terminal
}


def validate_env_transition(
    from_state: EnvironmentLifecycleState,
    to_state: EnvironmentLifecycleState,
) -> None:
    allowed = VALID_ENV_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid environment transition: {from_state.value!r} → {to_state.value!r}"
        )


# ---------------------------------------------------------------------------
# Secret governance enumerations
# ---------------------------------------------------------------------------


class SecretLifecycleState(str, Enum):
    ACTIVE = "active"
    PENDING_ROTATION = "pending_rotation"
    EXPIRED = "expired"
    REVOKED = "revoked"
    COMPROMISED = "compromised"
    ARCHIVED = "archived"


class SecretClassification(str, Enum):
    STANDARD = "standard"
    RESTRICTED = "restricted"
    CRITICAL = "critical"
    REGULATED = "regulated"
    HIPAA = "hipaa"
    FEDRAMP = "fedramp"


class SecretType(str, Enum):
    GENERIC = "generic"
    API_KEY = "api_key"
    TLS_CERT = "tls_cert"
    DB_CREDENTIAL = "db_credential"
    OAUTH_TOKEN = "oauth_token"
    SIGNING_KEY = "signing_key"
    ENCRYPTION_KEY = "encryption_key"
    HMAC_KEY = "hmac_key"


class SecretRotationState(str, Enum):
    NOT_SCHEDULED = "not_scheduled"
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    OVERRIDDEN = "overridden"
    EMERGENCY = "emergency"


class ExternalSecretProvider(str, Enum):
    VAULT = "vault"
    AWS_KMS = "aws_kms"
    AZURE_KV = "azure_kv"
    GCP_SM = "gcp_sm"
    HSM = "hsm"
    CUSTOM = "custom"


VALID_SECRET_TRANSITIONS: dict[
    SecretLifecycleState, frozenset[SecretLifecycleState]
] = {
    SecretLifecycleState.ACTIVE: frozenset(
        {
            SecretLifecycleState.PENDING_ROTATION,
            SecretLifecycleState.EXPIRED,
            SecretLifecycleState.REVOKED,
            SecretLifecycleState.COMPROMISED,
        }
    ),
    SecretLifecycleState.PENDING_ROTATION: frozenset(
        {
            SecretLifecycleState.ACTIVE,
            SecretLifecycleState.EXPIRED,
            SecretLifecycleState.REVOKED,
            SecretLifecycleState.COMPROMISED,
        }
    ),
    SecretLifecycleState.EXPIRED: frozenset(
        {
            SecretLifecycleState.ARCHIVED,
            SecretLifecycleState.REVOKED,
        }
    ),
    SecretLifecycleState.REVOKED: frozenset(
        {
            SecretLifecycleState.ARCHIVED,
        }
    ),
    SecretLifecycleState.COMPROMISED: frozenset(
        {
            SecretLifecycleState.ARCHIVED,
        }
    ),
    SecretLifecycleState.ARCHIVED: frozenset(),  # terminal
}


def validate_secret_transition(
    from_state: SecretLifecycleState,
    to_state: SecretLifecycleState,
) -> None:
    allowed = VALID_SECRET_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid secret transition: {from_state.value!r} → {to_state.value!r}"
        )


# ---------------------------------------------------------------------------
# Rotation schedule enumerations
# ---------------------------------------------------------------------------


class RotationScheduleState(str, Enum):
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    OVERRIDDEN = "overridden"
    EMERGENCY = "emergency"


class RotationOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"
    OVERRIDDEN = "overridden"


VALID_ROTATION_TRANSITIONS: dict[
    RotationScheduleState, frozenset[RotationScheduleState]
] = {
    RotationScheduleState.SCHEDULED: frozenset(
        {
            RotationScheduleState.IN_PROGRESS,
            RotationScheduleState.CANCELLED,
            RotationScheduleState.OVERRIDDEN,
            RotationScheduleState.EMERGENCY,
        }
    ),
    RotationScheduleState.IN_PROGRESS: frozenset(
        {
            RotationScheduleState.COMPLETED,
            RotationScheduleState.FAILED,
            RotationScheduleState.OVERRIDDEN,
        }
    ),
    RotationScheduleState.EMERGENCY: frozenset(
        {
            RotationScheduleState.COMPLETED,
            RotationScheduleState.FAILED,
        }
    ),
    RotationScheduleState.COMPLETED: frozenset(),  # terminal
    RotationScheduleState.FAILED: frozenset(),  # terminal
    RotationScheduleState.CANCELLED: frozenset(),  # terminal
    RotationScheduleState.OVERRIDDEN: frozenset(),  # terminal
}


# ---------------------------------------------------------------------------
# Retention governance enumerations
# ---------------------------------------------------------------------------


class RetentionState(str, Enum):
    ACTIVE = "active"
    SCHEDULED_FOR_ARCHIVE = "scheduled_for_archive"
    ARCHIVED = "archived"
    SCHEDULED_FOR_DELETION = "scheduled_for_deletion"
    DELETION_BLOCKED = "deletion_blocked"
    LEGAL_HOLD = "legal_hold"


class RetentionClassification(str, Enum):
    STANDARD = "standard"
    EXTENDED = "extended"
    REGULATED = "regulated"
    HIPAA = "hipaa"
    FEDRAMP = "fedramp"
    LEGAL = "legal"


VALID_RETENTION_TRANSITIONS: dict[RetentionState, frozenset[RetentionState]] = {
    RetentionState.ACTIVE: frozenset(
        {
            RetentionState.SCHEDULED_FOR_ARCHIVE,
            RetentionState.SCHEDULED_FOR_DELETION,
            RetentionState.LEGAL_HOLD,
        }
    ),
    RetentionState.SCHEDULED_FOR_ARCHIVE: frozenset(
        {
            RetentionState.ARCHIVED,
            RetentionState.DELETION_BLOCKED,
            RetentionState.LEGAL_HOLD,
            RetentionState.ACTIVE,  # operator cancels schedule
        }
    ),
    RetentionState.ARCHIVED: frozenset(
        {
            RetentionState.SCHEDULED_FOR_DELETION,
            RetentionState.DELETION_BLOCKED,
            RetentionState.LEGAL_HOLD,
        }
    ),
    RetentionState.SCHEDULED_FOR_DELETION: frozenset(
        {
            RetentionState.DELETION_BLOCKED,
            RetentionState.LEGAL_HOLD,
        }
    ),
    RetentionState.DELETION_BLOCKED: frozenset(
        {
            RetentionState.SCHEDULED_FOR_DELETION,
            RetentionState.LEGAL_HOLD,
            RetentionState.ARCHIVED,
        }
    ),
    # Legal hold can transition to deletion-eligible states only when explicitly lifted.
    RetentionState.LEGAL_HOLD: frozenset(
        {
            RetentionState.ARCHIVED,
            RetentionState.DELETION_BLOCKED,
        }
    ),
}


def validate_retention_transition(
    from_state: RetentionState,
    to_state: RetentionState,
) -> None:
    allowed = VALID_RETENTION_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid retention transition: {from_state.value!r} → {to_state.value!r}"
        )


# ---------------------------------------------------------------------------
# Export governance enumerations
# ---------------------------------------------------------------------------


class ExportState(str, Enum):
    REQUESTED = "requested"
    VALIDATING = "validating"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    COMPLETED = "completed"


class ExportScope(str, Enum):
    TENANT = "tenant"
    ENVIRONMENT = "environment"
    AUDIT = "audit"
    COMPLIANCE = "compliance"
    LEGAL = "legal"
    FORENSIC = "forensic"
    PORTABILITY = "portability"
    OFFBOARDING = "offboarding"


class ExportClassification(str, Enum):
    STANDARD = "standard"
    RESTRICTED = "restricted"
    REGULATED = "regulated"
    LEGAL = "legal"
    FORENSIC = "forensic"


VALID_EXPORT_TRANSITIONS: dict[ExportState, frozenset[ExportState]] = {
    ExportState.REQUESTED: frozenset(
        {
            ExportState.VALIDATING,
            ExportState.REJECTED,
            ExportState.EXPIRED,
        }
    ),
    ExportState.VALIDATING: frozenset(
        {
            ExportState.APPROVED,
            ExportState.REJECTED,
            ExportState.EXPIRED,
        }
    ),
    ExportState.APPROVED: frozenset(
        {
            ExportState.COMPLETED,
            ExportState.EXPIRED,
        }
    ),
    ExportState.REJECTED: frozenset(),  # terminal
    ExportState.EXPIRED: frozenset(),  # terminal
    ExportState.COMPLETED: frozenset(),  # terminal
}


def validate_export_transition(
    from_state: ExportState,
    to_state: ExportState,
) -> None:
    allowed = VALID_EXPORT_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid export transition: {from_state.value!r} → {to_state.value!r}"
        )


# ---------------------------------------------------------------------------
# Backup enumerations
# ---------------------------------------------------------------------------


class BackupScope(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"
    AUDIT_TRAIL = "audit_trail"
    CONFIG_ONLY = "config_only"


class BackupState(str, Enum):
    INITIATED = "initiated"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"
    ARCHIVED = "archived"


# ---------------------------------------------------------------------------
# Restore enumerations
# ---------------------------------------------------------------------------


class RestoreState(str, Enum):
    INITIATED = "initiated"
    VALIDATING = "validating"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


class RestoreScope(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    AUDIT_TRAIL = "audit_trail"
    CONFIG_ONLY = "config_only"
    POINT_IN_TIME = "point_in_time"


class ValidationState(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    WAIVED = "waived"


# ---------------------------------------------------------------------------
# Recovery enumerations
# ---------------------------------------------------------------------------


class RecoveryState(str, Enum):
    INITIATED = "initiated"
    VALIDATING = "validating"
    VALIDATED = "validated"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


class RecoveryType(str, Enum):
    STANDARD = "standard"
    DISASTER_RECOVERY = "disaster_recovery"
    FAILOVER = "failover"
    DRILL = "drill"
    QUARANTINE_EXIT = "quarantine_exit"
    STAGED = "staged"


VALID_RECOVERY_TRANSITIONS: dict[RecoveryState, frozenset[RecoveryState]] = {
    RecoveryState.INITIATED: frozenset(
        {
            RecoveryState.VALIDATING,
            RecoveryState.ABANDONED,
        }
    ),
    RecoveryState.VALIDATING: frozenset(
        {
            RecoveryState.VALIDATED,
            RecoveryState.FAILED,
            RecoveryState.ABANDONED,
        }
    ),
    RecoveryState.VALIDATED: frozenset(
        {
            RecoveryState.IN_PROGRESS,
            RecoveryState.ABANDONED,
        }
    ),
    RecoveryState.IN_PROGRESS: frozenset(
        {
            RecoveryState.COMPLETED,
            RecoveryState.FAILED,
        }
    ),
    RecoveryState.COMPLETED: frozenset(),  # terminal
    RecoveryState.FAILED: frozenset(),  # terminal
    RecoveryState.ABANDONED: frozenset(),  # terminal
}


def validate_recovery_transition(
    from_state: RecoveryState,
    to_state: RecoveryState,
) -> None:
    allowed = VALID_RECOVERY_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid recovery transition: {from_state.value!r} → {to_state.value!r}"
        )


# ---------------------------------------------------------------------------
# Compliance classification (re-exported to avoid schema duplication)
# ---------------------------------------------------------------------------

from services.deployment.models import ComplianceClassification  # noqa: E402


# ---------------------------------------------------------------------------
# Domain dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpsEnvironment:
    environment_id: str
    env_name: str
    slug: str
    lifecycle_state: EnvironmentLifecycleState
    env_type: EnvironmentType
    compliance_classification: ComplianceClassification
    isolation_level: IsolationLevel
    residency_classification: ResidencyClassification
    recovery_readiness: RecoveryReadiness
    created_by: str
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None
    region: Optional[str] = None
    validation_token: Optional[str] = None
    idempotency_key: Optional[str] = None
    archived_at: Optional[datetime] = None
    state_version: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpsSecretGovernance:
    """Governance metadata for a managed secret. No raw secret value is stored."""

    secret_governance_id: str
    secret_name: str
    secret_classification: SecretClassification
    secret_type: SecretType
    lifecycle_state: SecretLifecycleState
    rotation_state: SecretRotationState
    created_by: str
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None
    environment_id: Optional[str] = None
    external_provider: Optional[str] = None
    external_reference_id: Optional[str] = None  # provider path/ARN — NOT the secret
    owner_scope: Optional[str] = None
    rotation_policy_days: Optional[int] = None
    last_rotated_at: Optional[datetime] = None
    next_rotation_due_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    idempotency_key: Optional[str] = None
    state_version: int = 0
    governance_policy: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpsKeyRotationSchedule:
    rotation_id: str
    secret_governance_id: str
    rotation_state: RotationScheduleState
    scheduled_at: datetime
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None
    initiated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    compliance_override: bool = False
    override_reason: Optional[str] = None
    override_approved_by: Optional[str] = None
    emergency_rotation: bool = False
    waiver_reference: Optional[str] = None
    initiated_by: Optional[str] = None
    outcome: Optional[RotationOutcome] = None
    state_version: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpsRetentionPolicy:
    retention_policy_id: str
    policy_name: str
    retention_classification: RetentionClassification
    retention_state: RetentionState
    retention_days: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None
    environment_id: Optional[str] = None
    archive_after_days: Optional[int] = None
    deletion_scheduled_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None
    legal_hold: bool = False
    legal_hold_reason: Optional[str] = None
    legal_hold_set_by: Optional[str] = None
    legal_hold_set_at: Optional[datetime] = None
    export_restricted: bool = False
    compliance_policy_ref: Optional[str] = None
    override_reason: Optional[str] = None
    idempotency_key: Optional[str] = None
    state_version: int = 0


@dataclass(frozen=True)
class OpsExportRequest:
    export_id: str
    export_state: ExportState
    export_scope: ExportScope
    export_classification: ExportClassification
    requested_by: str
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None
    environment_id: Optional[str] = None
    export_purpose: Optional[str] = None
    approved_by: Optional[str] = None
    rejected_by: Optional[str] = None
    approval_reason: Optional[str] = None
    rejection_reason: Optional[str] = None
    legal_hold_validated: bool = False
    residency_validated: bool = False
    retention_validated: bool = False
    export_restriction_flags: dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    idempotency_key: Optional[str] = None
    state_version: int = 0


@dataclass(frozen=True)
class OpsBackupRecord:
    backup_id: str
    backup_scope: BackupScope
    backup_classification: ComplianceClassification
    backup_state: BackupState
    initiated_by: str
    started_at: datetime
    created_at: datetime
    tenant_id: Optional[str] = None
    environment_id: Optional[str] = None
    backup_reference: Optional[str] = None  # opaque reference, not contents
    retention_policy_id: Optional[str] = None
    backup_size_bytes: Optional[int] = None
    checksum_ref: Optional[str] = None  # hash of artifact, not contents
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    state_version: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpsRestoreRecord:
    restore_id: str
    restore_state: RestoreState
    restore_scope: RestoreScope
    validation_state: ValidationState
    initiated_by: str
    started_at: datetime
    created_at: datetime
    tenant_id: Optional[str] = None
    source_backup_id: Optional[str] = None
    target_environment_id: Optional[str] = None
    point_in_time_ref: Optional[str] = None  # opaque PiT marker, not a secret
    validation_token: Optional[str] = None
    completed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    recovery_lineage_id: Optional[str] = None
    state_version: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpsRecoveryRecord:
    recovery_id: str
    recovery_state: RecoveryState
    recovery_type: RecoveryType
    validation_state: ValidationState
    readiness_classification: RecoveryReadiness
    initiated_by: str
    started_at: datetime
    created_at: datetime
    tenant_id: Optional[str] = None
    environment_id: Optional[str] = None
    recovery_trigger: Optional[str] = None
    validated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    failure_count: int = 0
    drill_mode: bool = False
    state_version: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OpsGovernanceAuditEvent:
    event_id: str
    resource_type: str
    resource_id: str
    event_type: str
    actor: str
    outcome: str
    timestamp: datetime
    tenant_id: Optional[str] = None
    environment_id: Optional[str] = None
    policy_state: Optional[str] = None
    operational_context: Optional[str] = None
    failure_reason: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    event_hash: Optional[str] = None
    previous_event_hash: Optional[str] = None
