"""Pydantic schemas for the Remediation Authority API.

All request schemas use ``ConfigDict(extra="forbid")`` to prevent field
injection. All response schemas use the same for contract stability.

Exception hierarchy:
  RemediationAuthorityError
    +- RemediationNotFound
    +- RemediationTenantViolation
    +- RemediationConflict
    +- RemediationInvalidTransition
    +- RemediationImmutableState
    +- RemediationDependencyError
    +- RemediationAssignmentError
    +- RemediationVerificationError
    +- RemediationValidationError
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from services.remediation_authority.models import (
    AssignmentRole,
    DependencyType,
    RemediationPlanState,
    RemediationPriority,
    RemediationTaskState,
    RemediationVerificationState,
    SlaStatus,
)


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class RemediationAuthorityError(Exception):
    """Base exception for all Remediation Authority errors."""


class RemediationNotFound(RemediationAuthorityError):
    """Requested remediation entity does not exist or is not visible to tenant."""


class RemediationTenantViolation(RemediationAuthorityError):
    """Cross-tenant access attempt detected."""


class RemediationConflict(RemediationAuthorityError):
    """Conflict with existing remediation entity."""


class RemediationInvalidTransition(RemediationAuthorityError):
    """Requested state transition is not permitted by the state machine."""


class RemediationImmutableState(RemediationAuthorityError):
    """Entity is in an immutable state; mutation is not allowed."""


class RemediationDependencyError(RemediationAuthorityError):
    """Dependency graph error (cycle, invalid edge, etc.)."""


class RemediationAssignmentError(RemediationAuthorityError):
    """Invalid assignment (unknown role, duplicate, missing actor)."""


class RemediationVerificationError(RemediationAuthorityError):
    """Verification lifecycle error."""


class RemediationValidationError(RemediationAuthorityError):
    """Input validation error at the schema-adjacent layer."""


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class CreatePlanRequest(BaseModel):
    """Create a remediation plan."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    assessment_id: str | None = Field(default=None, max_length=64)
    target_date: str | None = Field(default=None, max_length=64)


class UpdatePlanRequest(BaseModel):
    """Partial update to a remediation plan."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    plan_state: RemediationPlanState | None = None
    target_date: str | None = Field(default=None, max_length=64)


class CreateTaskRequest(BaseModel):
    """Create a remediation task."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str | None = Field(default=None, max_length=64)
    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    priority: RemediationPriority = Field(default=RemediationPriority.MEDIUM)
    owner_id: str | None = Field(default=None, max_length=255)
    reviewer_id: str | None = Field(default=None, max_length=255)
    approver_id: str | None = Field(default=None, max_length=255)
    finding_id: str | None = Field(default=None, max_length=64)
    control_id: str | None = Field(default=None, max_length=64)
    evidence_id: str | None = Field(default=None, max_length=64)
    target_date: str | None = Field(default=None, max_length=64)
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)


class UpdateTaskRequest(BaseModel):
    """Partial update to a remediation task."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    priority: RemediationPriority | None = None
    owner_id: str | None = Field(default=None, max_length=255)
    reviewer_id: str | None = Field(default=None, max_length=255)
    approver_id: str | None = Field(default=None, max_length=255)
    target_date: str | None = Field(default=None, max_length=64)
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)


class TransitionTaskRequest(BaseModel):
    """Request to transition a task to a new state."""

    model_config = ConfigDict(extra="forbid")

    to_state: RemediationTaskState
    reason: str | None = Field(default=None, max_length=1024)


class CreateAssignmentRequest(BaseModel):
    """Create an assignment for a task."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., min_length=1, max_length=64)
    actor_id: str = Field(..., min_length=1, max_length=255)
    role: AssignmentRole


class CreateDependencyRequest(BaseModel):
    """Create a dependency edge between two tasks."""

    model_config = ConfigDict(extra="forbid")

    source_task_id: str = Field(..., min_length=1, max_length=64)
    target_task_id: str = Field(..., min_length=1, max_length=64)
    dependency_type: DependencyType = Field(default=DependencyType.BLOCKS)


class CreateVerificationRequest(BaseModel):
    """Record a verification event against a task."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., min_length=1, max_length=64)
    verifier_id: str = Field(..., min_length=1, max_length=255)
    verification_state: RemediationVerificationState = Field(
        default=RemediationVerificationState.IN_REVIEW
    )
    evidence_id: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=2048)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class PlanResponse(BaseModel):
    """Full representation of a remediation plan."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    title: str
    description: str | None
    plan_state: str
    assessment_id: str | None
    target_date: str | None
    created_at: str
    updated_at: str
    completed_at: str | None


class PlanListResponse(BaseModel):
    """Paginated list of plans."""

    model_config = ConfigDict(extra="forbid")

    items: list[PlanResponse]
    total: int
    offset: int
    limit: int


class TaskResponse(BaseModel):
    """Full representation of a remediation task."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    plan_id: str | None
    title: str
    description: str | None
    task_state: str
    priority: str
    owner_id: str | None
    reviewer_id: str | None
    approver_id: str | None
    finding_id: str | None
    control_id: str | None
    evidence_id: str | None
    target_date: str | None
    risk_score: float | None
    sla_status: str
    created_at: str
    updated_at: str
    completed_at: str | None


class TaskListResponse(BaseModel):
    """Paginated list of tasks."""

    model_config = ConfigDict(extra="forbid")

    items: list[TaskResponse]
    total: int
    offset: int
    limit: int


class TimelineEventResponse(BaseModel):
    """Single timeline event."""

    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    event_type: str
    from_state: str | None
    to_state: str | None
    actor_id: str | None
    reason: str | None
    event_metadata: dict[str, Any]
    created_at: str


class TimelineResponse(BaseModel):
    """Task timeline events."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    events: list[TimelineEventResponse]
    total: int


class HistoryEntryResponse(BaseModel):
    """Alias structure for state-history entries."""

    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    from_state: str | None
    to_state: str | None
    actor_id: str | None
    reason: str | None
    created_at: str


class HistoryResponse(BaseModel):
    """Task state history."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    entries: list[HistoryEntryResponse]
    total: int


class AssignmentResponse(BaseModel):
    """Assignment record."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    task_id: str
    actor_id: str
    role: str
    created_at: str


class AssignmentListResponse(BaseModel):
    """List of assignments (optionally filtered by task)."""

    model_config = ConfigDict(extra="forbid")

    items: list[AssignmentResponse]
    total: int


class DependencyResponse(BaseModel):
    """Dependency edge record."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    source_task_id: str
    target_task_id: str
    dependency_type: str
    created_at: str


class DependencyListResponse(BaseModel):
    """List of dependency edges."""

    model_config = ConfigDict(extra="forbid")

    items: list[DependencyResponse]
    total: int


class VerificationResponse(BaseModel):
    """Verification record."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    task_id: str
    verifier_id: str
    verification_state: str
    evidence_id: str | None
    notes: str | None
    created_at: str


class VerificationListResponse(BaseModel):
    """List of verifications."""

    model_config = ConfigDict(extra="forbid")

    items: list[VerificationResponse]
    total: int


class StatisticsResponse(BaseModel):
    """Aggregated tenant statistics."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_plans: int
    total_tasks: int
    by_state: dict[str, int]
    by_priority: dict[str, int]
    by_sla_status: dict[str, int]
    verifications_pending: int
    verifications_approved: int
    average_completion_days: float | None
    computed_at: str


class ForecastResponse(BaseModel):
    """Deterministic forecast summary."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    horizon_days: int
    predicted_completions: int
    predicted_breaches: int
    open_task_count: int
    average_velocity_per_day: float
    computed_at: str


class RiskResponse(BaseModel):
    """Risk reduction summary."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_risk_score: float
    open_risk_score: float
    mitigated_risk_score: float
    risk_reduction_pct: float
    by_priority: dict[str, float]
    computed_at: str


class DashboardResponse(BaseModel):
    """Portfolio-wide remediation dashboard."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    open_tasks: int
    in_progress_tasks: int
    blocked_tasks: int
    ready_for_review: int
    completed_tasks: int
    breached_sla: int
    at_risk_sla: int
    upcoming_deadlines: list[TaskResponse]
    priority_breakdown: dict[str, int]
    computed_at: str


class SearchResponse(BaseModel):
    """Search result items."""

    model_config = ConfigDict(extra="forbid")

    query: str
    items: list[TaskResponse]
    total: int


class HealthResponse(BaseModel):
    """Health response for the Remediation Authority."""

    model_config = ConfigDict(extra="forbid")

    status: str
    authority: str
    version: str
    schema_version: str
    checks: dict[str, str]


# Re-export enums for external convenience (typed)
__all__ = [
    # Exceptions
    "RemediationAuthorityError",
    "RemediationNotFound",
    "RemediationTenantViolation",
    "RemediationConflict",
    "RemediationInvalidTransition",
    "RemediationImmutableState",
    "RemediationDependencyError",
    "RemediationAssignmentError",
    "RemediationVerificationError",
    "RemediationValidationError",
    # Requests
    "CreatePlanRequest",
    "UpdatePlanRequest",
    "CreateTaskRequest",
    "UpdateTaskRequest",
    "TransitionTaskRequest",
    "CreateAssignmentRequest",
    "CreateDependencyRequest",
    "CreateVerificationRequest",
    # Responses
    "PlanResponse",
    "PlanListResponse",
    "TaskResponse",
    "TaskListResponse",
    "TimelineEventResponse",
    "TimelineResponse",
    "HistoryEntryResponse",
    "HistoryResponse",
    "AssignmentResponse",
    "AssignmentListResponse",
    "DependencyResponse",
    "DependencyListResponse",
    "VerificationResponse",
    "VerificationListResponse",
    "StatisticsResponse",
    "ForecastResponse",
    "RiskResponse",
    "DashboardResponse",
    "SearchResponse",
    "HealthResponse",
    # Re-exported enums
    "AssignmentRole",
    "DependencyType",
    "RemediationPlanState",
    "RemediationPriority",
    "RemediationTaskState",
    "RemediationVerificationState",
    "SlaStatus",
]
