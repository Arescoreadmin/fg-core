"""Deployment domain models — pure Python, no I/O, no SQLAlchemy.

All identifiers are immutable after creation. State transitions are gated by
VALID_TRANSITIONS and must be recorded as DeploymentEvents (append-only).
No mutable module-level state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EnvironmentType(str, Enum):
    LOCAL = "local"
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"
    TENANT_DEDICATED = "tenant-dedicated"
    REGULATED = "regulated"


class EnvironmentLifecycleState(str, Enum):
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"


class ComplianceClassification(str, Enum):
    STANDARD = "standard"
    REGULATED = "regulated"
    HIPAA = "hipaa"
    FEDRAMP = "fedramp"
    GOVCON = "govcon"


class DeploymentStrategy(str, Enum):
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    DIRECT = "direct"


class DeploymentState(str, Enum):
    PENDING = "pending"
    VALIDATING = "validating"
    DEPLOYING = "deploying"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DeploymentEventType(str, Enum):
    CREATED = "created"
    STATE_TRANSITION = "state_transition"
    HEALTH_RECORDED = "health_recorded"
    ROLLBACK_INITIATED = "rollback_initiated"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    METADATA_UPDATED = "metadata_updated"


class HealthResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Valid state transitions (deterministic state machine)
# ---------------------------------------------------------------------------

#: Maps each state to the set of states it may transition to.
#: Failed and rolled_back are terminal — no outbound transitions.
VALID_TRANSITIONS: dict[DeploymentState, frozenset[DeploymentState]] = {
    DeploymentState.PENDING: frozenset(
        {DeploymentState.VALIDATING, DeploymentState.FAILED}
    ),
    DeploymentState.VALIDATING: frozenset(
        {DeploymentState.DEPLOYING, DeploymentState.FAILED}
    ),
    DeploymentState.DEPLOYING: frozenset(
        {
            DeploymentState.HEALTHY,
            DeploymentState.DEGRADED,
            DeploymentState.FAILED,
        }
    ),
    DeploymentState.HEALTHY: frozenset(
        {DeploymentState.DEGRADED, DeploymentState.ROLLED_BACK}
    ),
    DeploymentState.DEGRADED: frozenset(
        {
            DeploymentState.HEALTHY,
            DeploymentState.FAILED,
            DeploymentState.ROLLED_BACK,
        }
    ),
    # Terminal states
    DeploymentState.FAILED: frozenset(),
    DeploymentState.ROLLED_BACK: frozenset(),
}


def validate_transition(from_state: DeploymentState, to_state: DeploymentState) -> None:
    """Raise ValueError if the transition is not permitted."""
    allowed = VALID_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid deployment state transition: {from_state!r} → {to_state!r}. "
            f"Allowed: {sorted(s.value for s in allowed) or 'none (terminal state)'}"
        )


# ---------------------------------------------------------------------------
# Domain dataclasses (export-safe: no secrets, no credentials)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeploymentEnvironment:
    """Immutable deployment environment descriptor.

    tenant_id=None denotes a platform-level (multi-tenant) environment.
    tenant_id set denotes a tenant-dedicated environment.
    """

    env_id: str
    env_type: EnvironmentType
    region: str
    lifecycle_state: EnvironmentLifecycleState
    compliance_classification: ComplianceClassification
    created_by: str
    created_at: datetime
    tenant_id: Optional[str] = None
    deployment_policy: dict[str, Any] = field(default_factory=dict)

    def is_production_like(self) -> bool:
        return self.env_type in (
            EnvironmentType.PRODUCTION,
            EnvironmentType.REGULATED,
            EnvironmentType.TENANT_DEDICATED,
        )

    def requires_approval(self) -> bool:
        return self.is_production_like() or self.compliance_classification in (
            ComplianceClassification.HIPAA,
            ComplianceClassification.FEDRAMP,
            ComplianceClassification.GOVCON,
        )


@dataclass(frozen=True)
class DeploymentRecord:
    """Snapshot of a single deployment's lifecycle state.

    artifact_hash: SHA-256 of the deployment artifact bundle; None until
    the artifact is resolved during validation.

    rollback_from_id: deployment_id of the deployment being rolled back.
    This forms a linked list for rollback lineage reconstruction.
    """

    deployment_id: str
    env_id: str
    version_ref: str
    strategy: DeploymentStrategy
    state: DeploymentState
    initiated_by: str
    initiated_at: datetime
    tenant_id: Optional[str] = None
    artifact_hash: Optional[str] = None
    completed_at: Optional[datetime] = None
    rollback_from_id: Optional[str] = None
    rollback_reason: Optional[str] = None
    approval_required: bool = False
    approval_granted_by: Optional[str] = None
    deployment_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeploymentEvent:
    """Append-only audit record for a deployment lifecycle event.

    Every state change, health record, and rollback action MUST produce
    a DeploymentEvent. Records are never updated or deleted.
    """

    event_id: str
    deployment_id: str
    env_id: str
    event_type: DeploymentEventType
    actor: str
    timestamp: datetime
    tenant_id: Optional[str] = None
    from_state: Optional[DeploymentState] = None
    to_state: Optional[DeploymentState] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeploymentHealthRecord:
    """Point-in-time health assessment for a deployment.

    rollback_trigger_reason is set when this health check caused or
    recommended a rollback. Never contains secrets or stack traces.
    """

    record_id: str
    deployment_id: str
    env_id: str
    readiness_result: HealthResult
    liveness_result: HealthResult
    smoke_test_result: HealthResult
    validation_result: HealthResult
    checked_by: str
    checked_at: datetime
    tenant_id: Optional[str] = None
    rollback_trigger_reason: Optional[str] = None
