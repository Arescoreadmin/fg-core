"""Pydantic schemas for the Governance Orchestration Authority (PR 18.4).

All schemas use ``ConfigDict(extra="forbid")`` to prevent field injection.

Exception hierarchy:
  GovernanceOrchestrationError
    +- GovernanceOrchestrationNotFound
    +- GovernanceOrchestrationTenantViolation
    +- GovernanceOrchestrationConflict
    +- GovernanceOrchestrationInvalidTransition
    +- GovernanceOrchestrationPolicyViolation
    +- GovernanceOrchestrationValidationError
    +- GovernanceOrchestrationSimulationError
    +- GovernanceOrchestrationApprovalError
    +- GovernanceOrchestrationWorkflowError
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class GovernanceOrchestrationError(Exception):
    """Base exception for all Governance Orchestration errors."""


class GovernanceOrchestrationNotFound(GovernanceOrchestrationError):
    """Entity not found for tenant."""


class GovernanceOrchestrationTenantViolation(GovernanceOrchestrationError):
    """Cross-tenant access attempt detected."""


class GovernanceOrchestrationConflict(GovernanceOrchestrationError):
    """Conflict with an existing orchestration entity."""


class GovernanceOrchestrationInvalidTransition(GovernanceOrchestrationError):
    """State transition not permitted by the state machine."""


class GovernanceOrchestrationPolicyViolation(GovernanceOrchestrationError):
    """Requested action violates orchestration policy."""


class GovernanceOrchestrationValidationError(GovernanceOrchestrationError):
    """Input validation error at the schema-adjacent layer."""


class GovernanceOrchestrationSimulationError(GovernanceOrchestrationError):
    """Simulation could not be computed deterministically."""


class GovernanceOrchestrationApprovalError(GovernanceOrchestrationError):
    """Approval workflow error (missing stage, invalid quorum, etc.)."""


class GovernanceOrchestrationWorkflowError(GovernanceOrchestrationError):
    """Workflow lifecycle error (bad event, terminal state, etc.)."""


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class CreatePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    risk_level: str = Field(default="MEDIUM", max_length=32)
    policy_data: dict[str, Any] = Field(default_factory=dict)
    active: bool = Field(default=True)


class UpdatePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    risk_level: str | None = Field(default=None, max_length=32)
    policy_data: dict[str, Any] | None = None
    active: bool | None = None


class CreatePlaybookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    playbook_type: str = Field(..., max_length=64)
    description: str | None = Field(default=None, max_length=4096)
    playbook_data: dict[str, Any] = Field(default_factory=dict)


class CreateWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    playbook_id: str | None = Field(default=None, max_length=64)
    trigger_id: str | None = Field(default=None, max_length=64)
    context: dict[str, Any] = Field(default_factory=dict)


class CreateReassessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(..., min_length=1, max_length=64)
    trigger_id: str | None = Field(default=None, max_length=64)
    reason: str | None = Field(default=None, max_length=1024)


class CreateTriggerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger_type: str = Field(..., max_length=64)
    source_id: str | None = Field(default=None, max_length=64)
    reason: str | None = Field(default=None, max_length=1024)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    policy_version: str = Field(default="1.0", max_length=32)


class CreateSimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    change_type: str = Field(..., max_length=64)
    change_data: dict[str, Any] = Field(default_factory=dict)


class CreateApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_id: str = Field(..., min_length=1, max_length=64)
    actor_id: str = Field(..., min_length=1, max_length=255)
    stage: int = Field(default=1, ge=1, le=32)
    quorum: int = Field(default=1, ge=1, le=32)


class ApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(..., max_length=32)
    reason: str | None = Field(default=None, max_length=1024)
    delegated_to: str | None = Field(default=None, max_length=255)


class CreateMaintenanceWindowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    starts_at: str = Field(..., max_length=64)
    ends_at: str = Field(..., max_length=64)
    reason: str | None = Field(default=None, max_length=1024)


class CreateChangeDetectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    change_type: str = Field(..., max_length=64)
    source_id: str | None = Field(default=None, max_length=64)
    impact_level: str = Field(default="LOW", max_length=32)
    change_data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class PolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    description: str | None
    risk_level: str
    policy_data: dict[str, Any]
    active: bool
    version: str
    created_at: str
    updated_at: str


class PolicyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PolicyResponse]
    total: int
    offset: int
    limit: int


class PlaybookResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    playbook_type: str
    description: str | None
    playbook_data: dict[str, Any]
    created_at: str
    updated_at: str


class PlaybookListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PlaybookResponse]
    total: int
    offset: int
    limit: int


class WorkflowResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    workflow_state: str
    playbook_id: str | None
    trigger_id: str | None
    context: dict[str, Any]
    created_at: str
    updated_at: str
    completed_at: str | None


class WorkflowListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[WorkflowResponse]
    total: int
    offset: int
    limit: int


class ReassessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    assessment_id: str
    trigger_id: str | None
    reassessment_state: str
    reason: str | None
    scheduled_at: str | None
    completed_at: str | None
    outcome: str | None
    created_at: str
    updated_at: str


class ReassessmentListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ReassessmentResponse]
    total: int
    offset: int
    limit: int


class TriggerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    trigger_type: str
    source_id: str | None
    reason: str | None
    confidence: float
    policy_version: str
    created_at: str


class TriggerListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TriggerResponse]
    total: int
    offset: int
    limit: int


class SimulationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    change_type: str
    change_data: dict[str, Any]
    simulation_state: str
    result: dict[str, Any]
    created_at: str
    updated_at: str


class SimulationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SimulationResponse]
    total: int
    offset: int
    limit: int


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    workflow_id: str
    actor_id: str
    stage: int
    quorum: int
    approval_state: str
    decision: str | None
    reason: str | None
    delegated_to: str | None
    created_at: str
    updated_at: str


class ApprovalListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ApprovalResponse]
    total: int


class MaintenanceWindowResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    window_state: str
    starts_at: str
    ends_at: str
    reason: str | None
    created_at: str
    updated_at: str


class MaintenanceWindowListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[MaintenanceWindowResponse]
    total: int


class ChangeDetectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    change_type: str
    source_id: str | None
    impact_level: str
    change_data: dict[str, Any]
    created_at: str


class ChangeDetectionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ChangeDetectionResponse]
    total: int
    offset: int
    limit: int


class DashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    active_policies: int
    active_workflows: int
    pending_reassessments: int
    pending_approvals: int
    active_maintenance_windows: int
    recent_triggers: int
    evidence_sufficiency_pct: float
    control_health_pct: float
    governance_score: float
    computed_at: str


class StatisticsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_policies: int
    total_playbooks: int
    total_workflows: int
    total_reassessments: int
    total_triggers: int
    total_approvals: int
    workflow_by_state: dict[str, int]
    reassessment_by_state: dict[str, int]
    trigger_by_type: dict[str, int]
    approval_by_state: dict[str, int]
    computed_at: str


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    authority: str
    version: str
    schema_version: str
    checks: dict[str, str]


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    entity_type: str
    entity_id: str
    event_type: str
    actor_id: str | None
    event_metadata: dict[str, Any]
    created_at: str


class TimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[TimelineEventResponse]
    total: int
    offset: int
    limit: int


class HistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    entity_id: str
    events: list[TimelineEventResponse]
    total: int


class SearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    policies: list[PolicyResponse]
    playbooks: list[PlaybookResponse]
    workflows: list[WorkflowResponse]
    total: int


class ImpactAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    change_type: str
    impact_level: str
    governance_score_delta: float
    control_effectiveness_delta: float
    risk_reduction: float
    affected_controls: int
    affected_evidence: int
    recommendations: list[str]
    computed_at: str


__all__ = [
    # Exceptions
    "GovernanceOrchestrationError",
    "GovernanceOrchestrationNotFound",
    "GovernanceOrchestrationTenantViolation",
    "GovernanceOrchestrationConflict",
    "GovernanceOrchestrationInvalidTransition",
    "GovernanceOrchestrationPolicyViolation",
    "GovernanceOrchestrationValidationError",
    "GovernanceOrchestrationSimulationError",
    "GovernanceOrchestrationApprovalError",
    "GovernanceOrchestrationWorkflowError",
    # Requests
    "CreatePolicyRequest",
    "UpdatePolicyRequest",
    "CreatePlaybookRequest",
    "CreateWorkflowRequest",
    "CreateReassessmentRequest",
    "CreateTriggerRequest",
    "CreateSimulationRequest",
    "CreateApprovalRequest",
    "ApproveRequest",
    "CreateMaintenanceWindowRequest",
    "CreateChangeDetectionRequest",
    # Responses
    "PolicyResponse",
    "PolicyListResponse",
    "PlaybookResponse",
    "PlaybookListResponse",
    "WorkflowResponse",
    "WorkflowListResponse",
    "ReassessmentResponse",
    "ReassessmentListResponse",
    "TriggerResponse",
    "TriggerListResponse",
    "SimulationResponse",
    "SimulationListResponse",
    "ApprovalResponse",
    "ApprovalListResponse",
    "MaintenanceWindowResponse",
    "MaintenanceWindowListResponse",
    "ChangeDetectionResponse",
    "ChangeDetectionListResponse",
    "DashboardResponse",
    "StatisticsResponse",
    "HealthResponse",
    "TimelineEventResponse",
    "TimelineResponse",
    "HistoryResponse",
    "SearchResponse",
    "ImpactAnalysisResponse",
]
