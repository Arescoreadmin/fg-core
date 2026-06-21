# services/risk_governance/schemas.py
"""Pydantic schemas and domain exceptions for PR 14.2 — Risk Governance Engine."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class ApprovalType(str, Enum):
    SINGLE = "single"
    MULTI_APPROVER = "multi_approver"
    COMMITTEE = "committee"
    DELEGATED = "delegated"
    EMERGENCY = "emergency"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


TERMINAL_APPROVAL_STATUSES = {ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED, ApprovalStatus.REVOKED}
APPROVAL_ALLOWED_TRANSITIONS: dict[ApprovalStatus, set[ApprovalStatus]] = {
    ApprovalStatus.PENDING: {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED, ApprovalStatus.REVOKED},
    ApprovalStatus.APPROVED: {ApprovalStatus.REVOKED},
    ApprovalStatus.REJECTED: set(),
    ApprovalStatus.EXPIRED: set(),
    ApprovalStatus.REVOKED: set(),
}


class ReviewType(str, Enum):
    PERIODIC = "periodic"
    TRIGGERED = "triggered"
    EMERGENCY = "emergency"
    COMPLIANCE = "compliance"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    OVERDUE = "overdue"
    WAIVED = "waived"


class ReviewOutcome(str, Enum):
    CONTINUE = "continue"
    REVOKE = "revoke"
    MODIFY = "modify"
    ESCALATE = "escalate"


class EscalationTrigger(str, Enum):
    MISSED_REVIEW = "missed_review"
    MISSED_APPROVAL = "missed_approval"
    EXPIRED_ACCEPTANCE = "expired_acceptance"
    EXPIRED_APPROVAL = "expired_approval"
    CRITICAL_RESIDUAL_RISK = "critical_residual_risk"
    REVIEW_OVERDUE = "review_overdue"
    APPROVAL_REJECTED = "approval_rejected"


class EscalationLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalThreshold(str, Enum):
    SINGLE = "single"
    MAJORITY = "majority"
    UNANIMOUS = "unanimous"
    QUORUM = "quorum"


class GovernanceEventType(str, Enum):
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_REVOKED = "approval_revoked"
    APPROVAL_EXPIRED = "approval_expired"
    REVIEW_CREATED = "review_created"
    REVIEW_COMPLETED = "review_completed"
    REVIEW_OVERDUE = "review_overdue"
    REVIEW_WAIVED = "review_waived"
    ESCALATION_CREATED = "escalation_created"
    ESCALATION_RESOLVED = "escalation_resolved"
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class GovernanceError(Exception):
    pass


class ApprovalNotFound(GovernanceError):
    pass


class ReviewNotFound(GovernanceError):
    pass


class PolicyNotFound(GovernanceError):
    pass


class EscalationNotFound(GovernanceError):
    pass


class GovernanceTenantViolation(GovernanceError):
    pass


class ApprovalInvalidTransition(GovernanceError):
    pass


class ApprovalConflict(GovernanceError):
    pass


class ReviewConflict(GovernanceError):
    pass


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class CreateApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approver_name: str = Field(..., min_length=1, max_length=255)
    approver_email: str | None = Field(default=None, max_length=255)
    approver_role: str | None = Field(default=None, max_length=255)
    approval_authority: str | None = Field(default=None, max_length=255)
    approval_type: ApprovalType = ApprovalType.SINGLE
    comments: str | None = None
    expires_at: str | None = None
    quorum_required: int | None = Field(default=None, ge=1)
    quorum_position: int | None = Field(default=None, ge=1)
    is_required: bool = True


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ApprovalStatus = Field(..., description="APPROVED or REJECTED")
    comments: str | None = None
    reason: str | None = None


class CreateReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_type: ReviewType = ReviewType.PERIODIC
    reviewer: str | None = Field(default=None, max_length=255)
    review_due_at: str = Field(..., description="ISO 8601 datetime")
    review_notes: str | None = None

    @field_validator("review_due_at")
    @classmethod
    def _validate_review_due_at(cls, v: str) -> str:
        from datetime import datetime

        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError(
                f"review_due_at must be a valid ISO 8601 datetime, got {v!r}."
            )
        return v


class CompleteReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ReviewStatus = Field(..., description="COMPLETED or WAIVED")
    outcome: ReviewOutcome | None = None
    review_notes: str | None = None
    reviewer: str | None = Field(default=None, max_length=255)


class CreatePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    approval_threshold: ApprovalThreshold = ApprovalThreshold.SINGLE
    required_roles: list[str] | None = None
    required_count: int = Field(default=1, ge=1)
    quorum_percentage: int | None = Field(default=None, ge=1, le=100)
    auto_expire_days: int | None = Field(default=None, ge=1)
    review_frequency_days: int = Field(default=90, ge=1)
    sequential: bool = False


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    risk_acceptance_id: str
    approver_name: str
    approver_email: str | None
    approver_role: str | None
    approval_authority: str | None
    approval_type: str
    status: str
    comments: str | None
    approved_at: str | None
    expires_at: str | None
    quorum_required: int | None
    quorum_position: int | None
    is_required: bool
    created_at: str
    updated_at: str
    schema_version: str


class ApprovalListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ApprovalResponse]
    total: int


class ApprovalAuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    approval_id: str
    risk_acceptance_id: str
    event_type: str
    actor: str
    old_state: dict[str, Any] | None
    new_state: dict[str, Any] | None
    reason: str | None
    event_at: str


class ApprovalAuditListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ApprovalAuditResponse]
    total: int


class ReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    risk_acceptance_id: str
    review_type: str
    reviewer: str | None
    status: str
    review_due_at: str
    review_completed_at: str | None
    review_notes: str | None
    outcome: str | None
    created_at: str
    updated_at: str
    schema_version: str


class ReviewListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ReviewResponse]
    total: int


class EscalationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    risk_acceptance_id: str
    trigger: str
    level: str
    details: dict[str, Any] | None
    actor: str
    resolved: bool
    resolved_at: str | None
    resolved_by: str | None
    created_at: str
    schema_version: str


class EscalationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EscalationResponse]
    total: int


class PolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    policy_name: str
    description: str | None
    active: bool
    approval_threshold: str
    required_roles: list[str] | None
    required_count: int
    quorum_percentage: int | None
    auto_expire_days: int | None
    review_frequency_days: int
    sequential: bool
    created_at: str
    updated_at: str
    schema_version: str


class PolicyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PolicyResponse]
    total: int


class GovernanceDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    pending_approvals: int
    overdue_reviews: int
    unresolved_escalations: int
    expired_risks: int
    upcoming_expirations_30d: int
    governance_debt_score: int
