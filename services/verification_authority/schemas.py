"""services/verification_authority/schemas.py — Pydantic schemas for Verification Workflow Authority.

All request schemas use extra="forbid" to prevent field injection.
All response schemas use extra="forbid" for contract stability.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from services.verification_authority.models import (
    AssigneeType,
    EscalationType,
    VerificationWorkflowState,
    WorkflowSlaStatus,
)


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class VerificationRequestNotFound(Exception):
    pass


class VerificationRequestConflict(Exception):
    pass


class VerificationWorkflowInvalidTransition(Exception):
    pass


class VerificationRequestImmutableState(Exception):
    pass


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class CreateVerificationRequestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1, max_length=64)
    notes: Optional[str] = Field(default=None)
    priority: int = Field(default=50, ge=0, le=100)
    review_due_at: Optional[str] = Field(default=None)
    decision_due_at: Optional[str] = Field(default=None)


class AssignVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignee_id: str = Field(..., min_length=1, max_length=255)
    assignee_type: AssigneeType
    assigned_due_at: Optional[str] = Field(default=None)


class TransitionWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: VerificationWorkflowState
    notes: Optional[str] = Field(default=None)


class EscalateVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    escalation_type: EscalationType
    escalation_notes: Optional[str] = Field(default=None)
    escalated_to: Optional[str] = Field(default=None)


class RecordResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: str = Field(..., description="APPROVED or REJECTED")
    decision_notes: Optional[str] = Field(default=None)


class SetWorkflowSlaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_due_at: Optional[str] = Field(default=None)
    decision_due_at: Optional[str] = Field(default=None)
    escalation_due_at: Optional[str] = Field(default=None)
    assigned_due_at: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class VerificationRequestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    workflow_state: str
    requested_by: str
    requester_actor_type: str
    requested_at: str
    assignee_id: Optional[str]
    assignee_type: Optional[str]
    assigned_at: Optional[str]
    priority: int
    notes: Optional[str]
    review_due_at: Optional[str]
    decision_due_at: Optional[str]
    escalation_due_at: Optional[str]
    assigned_due_at: Optional[str]
    completed_at: Optional[str]
    cancelled_at: Optional[str]
    expired_at: Optional[str]
    escalation_count: int
    last_escalation_type: Optional[str]
    last_escalated_at: Optional[str]
    last_escalated_by: Optional[str]
    created_at: str
    updated_at: str
    sla_status: Optional[WorkflowSlaStatus] = None


class VerificationRequestListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[VerificationRequestResponse]
    total: int


class VerificationResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    request_id: str
    evidence_id: str
    result: str
    decided_by: str
    decider_actor_type: str
    decision_notes: Optional[str]
    decided_at: str
    created_at: str


class VerificationAuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    request_id: str
    evidence_id: str
    event_type: str
    actor_id: str
    actor_type: str
    old_state: Optional[str]
    new_state: Optional[str]
    details: Optional[str]
    occurred_at: str
    created_at: str


class VerificationAuditListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[VerificationAuditResponse]
    total: int
    request_id: str


class WorkflowSlaStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    review_sla_status: Optional[str]
    decision_sla_status: Optional[str]
    escalation_sla_status: Optional[str]
    assigned_sla_status: Optional[str]
    overdue_fields: list[str]


class QueueItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    evidence_id: str
    workflow_state: str
    priority: int
    assignee_id: Optional[str]
    assignee_type: Optional[str]
    review_due_at: Optional[str]
    sla_status: Optional[str]


class QueueResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: str
    items: list[QueueItemResponse]
    total: int


class WorkflowDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_requests: int
    by_state: dict[str, int]
    overdue_count: int
    due_soon_count: int
    avg_priority: float
    unassigned_count: int
    escalated_count: int
    completed_count: int


class WorkflowCginSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_at: str
    tenant_id: str
    total_requests: int
    by_state: dict[str, int]
    overdue_count: int
    escalated_count: int
    completed_last_30d: int
