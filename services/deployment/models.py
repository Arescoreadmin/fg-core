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
# Strategy governance — restricts strategies per env_type / classification
# ---------------------------------------------------------------------------

#: Per-strategy governance constraints. Validated at deployment creation time.
#: Enforcement precedes execution engines — governance shapes what is even
#: schedulable before any runtime logic runs.
STRATEGY_GOVERNANCE: dict[DeploymentStrategy, dict[str, Any]] = {
    DeploymentStrategy.DIRECT: {
        # Direct (in-place, no traffic-split) is unsafe in regulated/prod envs.
        "forbidden_env_types": frozenset(
            {EnvironmentType.PRODUCTION, EnvironmentType.REGULATED}
        ),
        "forbidden_classifications": frozenset(
            {
                ComplianceClassification.HIPAA,
                ComplianceClassification.FEDRAMP,
                ComplianceClassification.GOVCON,
            }
        ),
    },
    DeploymentStrategy.ROLLING: {
        "forbidden_env_types": frozenset(),
        "forbidden_classifications": frozenset(),
    },
    DeploymentStrategy.BLUE_GREEN: {
        # Blue/green requires a real environment (not local scratch).
        "forbidden_env_types": frozenset({EnvironmentType.LOCAL}),
        "forbidden_classifications": frozenset(),
    },
    DeploymentStrategy.CANARY: {
        "forbidden_env_types": frozenset({EnvironmentType.LOCAL}),
        "forbidden_classifications": frozenset(),
    },
}


def validate_strategy_for_env(
    strategy: DeploymentStrategy,
    env_type: EnvironmentType,
    compliance_classification: ComplianceClassification,
) -> None:
    """Raise ValueError if strategy is forbidden for the given environment."""
    constraints = STRATEGY_GOVERNANCE.get(strategy, {})
    forbidden_types: frozenset[EnvironmentType] = constraints.get(
        "forbidden_env_types", frozenset()
    )
    forbidden_classes: frozenset[ComplianceClassification] = constraints.get(
        "forbidden_classifications", frozenset()
    )
    if env_type in forbidden_types:
        raise ValueError(
            f"Strategy {strategy.value!r} is not permitted for env_type {env_type.value!r}"
        )
    if compliance_classification in forbidden_classes:
        raise ValueError(
            f"Strategy {strategy.value!r} is not permitted for compliance classification "
            f"{compliance_classification.value!r}"
        )


# ---------------------------------------------------------------------------
# Classification policies — enforcement constraints per compliance tier
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClassificationPolicy:
    """Governance constraints for a compliance classification.

    required_approval_depth: minimum number of approvers required (future multi-stage).
    restricted_strategies: strategies explicitly forbidden for this classification.
    telemetry_restricted: telemetry must flow through policy-filtered pipeline.
    export_restricted: deployment artifacts must not leave the classification boundary.
    deployment_window_restricted: future hook for scheduled maintenance window enforcement.
    """

    required_approval_depth: int
    restricted_strategies: frozenset[DeploymentStrategy]
    telemetry_restricted: bool
    export_restricted: bool
    deployment_window_restricted: bool


CLASSIFICATION_POLICIES: dict[ComplianceClassification, ClassificationPolicy] = {
    ComplianceClassification.STANDARD: ClassificationPolicy(
        required_approval_depth=0,
        restricted_strategies=frozenset(),
        telemetry_restricted=False,
        export_restricted=False,
        deployment_window_restricted=False,
    ),
    ComplianceClassification.REGULATED: ClassificationPolicy(
        required_approval_depth=1,
        restricted_strategies=frozenset({DeploymentStrategy.DIRECT}),
        telemetry_restricted=True,
        export_restricted=False,
        deployment_window_restricted=False,
    ),
    ComplianceClassification.HIPAA: ClassificationPolicy(
        required_approval_depth=1,
        restricted_strategies=frozenset({DeploymentStrategy.DIRECT}),
        telemetry_restricted=True,
        export_restricted=True,
        deployment_window_restricted=False,
    ),
    ComplianceClassification.FEDRAMP: ClassificationPolicy(
        required_approval_depth=2,
        restricted_strategies=frozenset(
            {DeploymentStrategy.DIRECT, DeploymentStrategy.CANARY}
        ),
        telemetry_restricted=True,
        export_restricted=True,
        deployment_window_restricted=True,
    ),
    ComplianceClassification.GOVCON: ClassificationPolicy(
        required_approval_depth=2,
        restricted_strategies=frozenset(
            {DeploymentStrategy.DIRECT, DeploymentStrategy.CANARY}
        ),
        telemetry_restricted=True,
        export_restricted=True,
        deployment_window_restricted=True,
    ),
}


def validate_classification_policy(
    strategy: DeploymentStrategy,
    compliance_classification: ComplianceClassification,
) -> None:
    """Raise ValueError if strategy violates the classification policy."""
    policy = CLASSIFICATION_POLICIES.get(compliance_classification)
    if policy is None:
        return
    if strategy in policy.restricted_strategies:
        raise ValueError(
            f"Strategy {strategy.value!r} is restricted under classification "
            f"{compliance_classification.value!r} policy"
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
class DeploymentSpec:
    """Immutable snapshot of deployment inputs captured at creation time.

    Once captured, these fields are never updated. They form the authoritative
    record of what was intended to deploy — necessary for accurate rollback
    lineage and audit replay.
    """

    image_digest: Optional[str] = None
    commit_sha: Optional[str] = None
    contract_hash: Optional[str] = None
    topology_hash: Optional[str] = None
    policy_bundle_version: Optional[str] = None
    migration_fingerprint: Optional[str] = None


@dataclass(frozen=True)
class DeploymentRecord:
    """Snapshot of a single deployment's lifecycle state.

    artifact_hash: SHA-256 of the deployment artifact bundle; None until
    the artifact is resolved during validation.

    rollback_from_id: deployment_id of the deployment being rolled back.
    This forms a linked list for rollback lineage reconstruction.

    spec: immutable snapshot of deployment inputs captured at creation.
    state_version: optimistic-lock counter; incremented on every state change.
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
    approval_granted_at: Optional[datetime] = None
    approval_reason: Optional[str] = None
    approval_policy_version: Optional[str] = None
    spec: DeploymentSpec = field(default_factory=DeploymentSpec)
    state_version: int = 0
    deployment_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeploymentEvent:
    """Append-only audit record for a deployment lifecycle event.

    Every state change, health record, and rollback action MUST produce
    a DeploymentEvent. Records are never updated or deleted.

    event_hash: SHA-256 of canonical event fields for tamper-evidence.
    previous_event_hash: hash of the prior event for this deployment,
    forming a tamper-evident chain.
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
    event_hash: Optional[str] = None
    previous_event_hash: Optional[str] = None


@dataclass(frozen=True)
class DeploymentHealthRecord:
    """Point-in-time health assessment for a deployment.

    rollback_trigger_reason is set when this health check caused or
    recommended a rollback. Never contains secrets or stack traces.

    expires_at: optional TTL for retention enforcement. Records past
    this timestamp may be archived or purged by the retention job.
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
    expires_at: Optional[datetime] = None


@dataclass(frozen=True)
class TransitionDryRunResult:
    """Result of a dry-run transition validation (no side effects).

    allowed: whether the transition is permitted by the state machine.
    approval_required: whether approval is needed before this transition
    can be executed for real.
    policy_violations: list of classification/strategy policy violations
    that would block the transition.
    missing_approval_granted_by: True if approval_required but not yet granted.
    """

    allowed: bool
    from_state: DeploymentState
    to_state: DeploymentState
    approval_required: bool
    missing_approval_granted_by: bool
    policy_violations: list[str]
    blocked: bool
    block_reasons: list[str]
