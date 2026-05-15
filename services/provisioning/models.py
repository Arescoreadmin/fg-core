"""Provisioning domain models — pure Python, no I/O, no SQLAlchemy.

All identifiers are immutable after creation. State transitions are gated by
VALID_ORG_TRANSITIONS / VALID_WORKFLOW_TRANSITIONS and must be recorded as
ProvisioningAuditEvents (append-only).
No mutable module-level state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

# ComplianceClassification is shared with the deployment subsystem (identical values).
# Re-exported here so provisioning code can import from one place, but the Python
# object is the same — guaranteeing a single OpenAPI schema component reference.
from services.deployment.models import ComplianceClassification as ComplianceClassification  # noqa: F401, PLC0414


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class OrgLifecycleStatus(str, Enum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"
    FAILED = "failed"


class OnboardingState(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PENDING_ACTIVATION = "pending_activation"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkflowState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DeploymentTier(str, Enum):
    SHARED = "shared"
    DEDICATED = "dedicated"
    REGULATED_DEDICATED = "regulated_dedicated"


class OrgEventType(str, Enum):
    ORGANIZATION_CREATED = "organization_created"
    PROVISIONING_STARTED = "provisioning_started"
    PROVISIONING_STEP_COMPLETED = "provisioning_step_completed"
    PROVISIONING_STEP_FAILED = "provisioning_step_failed"
    PROVISIONING_COMPLETED = "provisioning_completed"
    PROVISIONING_FAILED = "provisioning_failed"
    TENANT_ACTIVATED = "tenant_activated"
    TENANT_SUSPENDED = "tenant_suspended"
    TENANT_ARCHIVED = "tenant_archived"
    ONBOARDING_MILESTONE_COMPLETED = "onboarding_milestone_completed"
    ENVIRONMENT_ASSIGNED = "environment_assigned"
    VALIDATION_PASSED = "validation_passed"
    VALIDATION_FAILED = "validation_failed"
    COMPLIANCE_HOOK_TRIGGERED = "compliance_hook_triggered"
    APPROVAL_HOOK_TRIGGERED = "approval_hook_triggered"
    ORG_STATUS_CHANGED = "org_status_changed"


class FailureCategory(str, Enum):
    RETRYABLE = "retryable"
    TERMINAL = "terminal"
    VALIDATION = "validation"
    ORCHESTRATION_INTERRUPTED = "orchestration_interrupted"
    ENV_INCOMPATIBLE = "env_incompatible"
    APPROVAL_FAILURE = "approval_failure"
    COMPLIANCE_FAILURE = "compliance_failure"


# ---------------------------------------------------------------------------
# Valid state transitions (deterministic state machines)
# ---------------------------------------------------------------------------

#: Maps each org status to the set of statuses it may transition to.
#: archived is terminal — no outbound transitions.
VALID_ORG_TRANSITIONS: dict[OrgLifecycleStatus, frozenset[OrgLifecycleStatus]] = {
    OrgLifecycleStatus.PENDING: frozenset(
        {OrgLifecycleStatus.PROVISIONING, OrgLifecycleStatus.FAILED}
    ),
    OrgLifecycleStatus.PROVISIONING: frozenset(
        {OrgLifecycleStatus.ACTIVE, OrgLifecycleStatus.FAILED}
    ),
    OrgLifecycleStatus.ACTIVE: frozenset(
        {OrgLifecycleStatus.SUSPENDED, OrgLifecycleStatus.ARCHIVED}
    ),
    OrgLifecycleStatus.SUSPENDED: frozenset(
        {OrgLifecycleStatus.ACTIVE, OrgLifecycleStatus.ARCHIVED}
    ),
    OrgLifecycleStatus.ARCHIVED: frozenset(),  # terminal
    OrgLifecycleStatus.FAILED: frozenset(
        {OrgLifecycleStatus.PROVISIONING}
    ),  # re-provisioning only
}

#: Maps each workflow state to the set of states it may transition to.
#: completed, failed, cancelled are terminal.
VALID_WORKFLOW_TRANSITIONS: dict[WorkflowState, frozenset[WorkflowState]] = {
    WorkflowState.PENDING: frozenset({WorkflowState.RUNNING, WorkflowState.CANCELLED}),
    WorkflowState.RUNNING: frozenset(
        {WorkflowState.COMPLETED, WorkflowState.FAILED, WorkflowState.CANCELLED}
    ),
    WorkflowState.COMPLETED: frozenset(),  # terminal
    WorkflowState.FAILED: frozenset(),  # terminal (retry = new workflow)
    WorkflowState.CANCELLED: frozenset(),  # terminal
}


def validate_org_transition(
    from_status: OrgLifecycleStatus, to_status: OrgLifecycleStatus
) -> None:
    """Raise ValueError if the org lifecycle transition is not permitted."""
    allowed = VALID_ORG_TRANSITIONS.get(from_status, frozenset())
    if to_status not in allowed:
        raise ValueError(
            f"Invalid org lifecycle transition: {from_status!r} → {to_status!r}. "
            f"Allowed: {sorted(s.value for s in allowed) or 'none (terminal state)'}"
        )


# ---------------------------------------------------------------------------
# Domain dataclasses (export-safe: no secrets, no credentials)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProvisioningOrganization:
    """Snapshot of an organization's provisioning lifecycle state.

    tenant_id=None denotes a platform-level (multi-tenant) org.
    tenant_id set denotes a tenant-linked org.
    state_version: optimistic-lock counter; incremented on every state change.
    """

    organization_id: str
    org_name: str
    slug: str
    lifecycle_status: OrgLifecycleStatus
    compliance_classification: ComplianceClassification
    deployment_tier: DeploymentTier
    onboarding_state: OnboardingState
    created_by: str
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None
    env_assignment_id: Optional[str] = None
    region: Optional[str] = None
    idempotency_key: Optional[str] = None
    activated_at: Optional[datetime] = None
    suspended_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None
    state_version: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProvisioningWorkflow:
    """Snapshot of a single provisioning workflow run.

    A new workflow record is created per provisioning attempt. Retries
    create fresh records — retry_count tracks cumulative retry depth.
    state_version: optimistic-lock counter.
    """

    provisioning_id: str
    organization_id: str
    workflow_state: WorkflowState
    initiated_by: str
    started_at: datetime
    last_updated_at: datetime
    tenant_id: Optional[str] = None
    current_step: Optional[str] = None
    idempotency_key: Optional[str] = None
    parent_provisioning_id: Optional[str] = None
    env_target: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    failure_reason: Optional[str] = None
    failure_category: Optional[FailureCategory] = None
    completed_at: Optional[datetime] = None
    state_version: int = 0
    validation_results: dict[str, Any] = field(default_factory=dict)
    orchestration_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProvisioningAuditEvent:
    """Append-only audit record for a provisioning lifecycle event.

    Every state change and provisioning action MUST produce a
    ProvisioningAuditEvent. Records are never updated or deleted.

    event_hash: SHA-256 of canonical event fields for tamper-evidence.
    previous_event_hash: hash of the prior event for this org,
    forming a tamper-evident chain.
    """

    event_id: str
    organization_id: str
    event_type: OrgEventType
    actor: str
    outcome: str
    timestamp: datetime
    provisioning_id: Optional[str] = None
    tenant_id: Optional[str] = None
    env_id: Optional[str] = None
    workflow_state: Optional[str] = None
    failure_reason: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    event_hash: Optional[str] = None
    previous_event_hash: Optional[str] = None


# ---------------------------------------------------------------------------
# Activation precondition gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActivationBlocker:
    """Single reason why an org cannot be activated.

    blocker_type: workflow_incomplete / onboarding_incomplete /
                  env_not_assigned / compliance_pending
    """

    reason: str
    blocker_type: str


def check_activation_preconditions(
    org: ProvisioningOrganization,
    workflow: Optional[ProvisioningWorkflow] = None,
) -> list[ActivationBlocker]:
    """Return list of blockers. Empty list means org can activate."""
    blockers: list[ActivationBlocker] = []

    if org.lifecycle_status != OrgLifecycleStatus.PROVISIONING:
        blockers.append(
            ActivationBlocker(
                reason=(
                    f"Org must be in 'provisioning' state to activate; "
                    f"current status: {org.lifecycle_status.value!r}"
                ),
                blocker_type="workflow_incomplete",
            )
        )

    if workflow is None or workflow.workflow_state != WorkflowState.COMPLETED:
        wf_state = workflow.workflow_state.value if workflow else "none"
        blockers.append(
            ActivationBlocker(
                reason=(
                    f"No completed provisioning workflow; "
                    f"current workflow state: {wf_state!r}"
                ),
                blocker_type="workflow_incomplete",
            )
        )

    if org.onboarding_state not in (
        OnboardingState.PENDING_ACTIVATION,
        OnboardingState.COMPLETED,
    ):
        blockers.append(
            ActivationBlocker(
                reason=(
                    f"Onboarding not ready for activation; "
                    f"current onboarding state: {org.onboarding_state.value!r}"
                ),
                blocker_type="onboarding_incomplete",
            )
        )

    # Future hook: compliance gate — currently always passes.

    return blockers
