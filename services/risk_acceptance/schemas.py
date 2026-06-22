# services/risk_acceptance/schemas.py
"""Domain enums, exceptions, and Pydantic schemas for PR 14.1 — Risk Acceptance.

Status lifecycle:
  DRAFT → PENDING_APPROVAL → APPROVED → ACTIVE
  ACTIVE   → EXPIRED (automatic) | REVOKED (manual)
  PENDING_APPROVAL → REJECTED
  DRAFT | PENDING_APPROVAL → REVOKED
  Terminal: EXPIRED, REVOKED, REJECTED

Illegal transitions return HTTP 422.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RiskAcceptanceStatus(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    REJECTED = "rejected"


TERMINAL_STATUSES = {
    RiskAcceptanceStatus.EXPIRED,
    RiskAcceptanceStatus.REVOKED,
    RiskAcceptanceStatus.REJECTED,
}

# Authoritative transition map: current_status → allowed target statuses
ALLOWED_TRANSITIONS: dict[RiskAcceptanceStatus, set[RiskAcceptanceStatus]] = {
    RiskAcceptanceStatus.DRAFT: {
        RiskAcceptanceStatus.PENDING_APPROVAL,
        RiskAcceptanceStatus.REVOKED,
    },
    RiskAcceptanceStatus.PENDING_APPROVAL: {
        RiskAcceptanceStatus.APPROVED,
        RiskAcceptanceStatus.REJECTED,
        RiskAcceptanceStatus.REVOKED,
    },
    RiskAcceptanceStatus.APPROVED: {
        RiskAcceptanceStatus.ACTIVE,
        RiskAcceptanceStatus.REVOKED,
    },
    RiskAcceptanceStatus.ACTIVE: {
        RiskAcceptanceStatus.EXPIRED,
        RiskAcceptanceStatus.REVOKED,
    },
    RiskAcceptanceStatus.EXPIRED: set(),
    RiskAcceptanceStatus.REVOKED: set(),
    RiskAcceptanceStatus.REJECTED: set(),
}


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalAuthority(str, Enum):
    CISO = "ciso"
    RISK_COMMITTEE = "risk_committee"
    EXECUTIVE_SPONSOR = "executive_sponsor"
    BUSINESS_OWNER = "business_owner"


class RiskAcceptanceEventType(str, Enum):
    RISK_CREATED = "risk_created"
    RISK_SUBMITTED = "risk_submitted"  # DRAFT → PENDING_APPROVAL
    RISK_APPROVED = "risk_approved"  # PENDING_APPROVAL → APPROVED
    RISK_ACTIVATED = "risk_activated"  # APPROVED → ACTIVE
    RISK_REJECTED = "risk_rejected"  # → REJECTED
    RISK_REVOKED = "risk_revoked"  # → REVOKED
    RISK_EXPIRED = "risk_expired"  # → EXPIRED (automatic)
    RISK_UPDATED = "risk_updated"  # field-level update (status unchanged)
    RISK_REVIEWED = "risk_reviewed"  # review cycle recorded


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RiskAcceptanceError(Exception):
    """Base risk acceptance domain error."""


class RiskAcceptanceNotFound(RiskAcceptanceError):
    """Record does not exist or does not belong to caller's tenant."""


class RiskAcceptanceTenantViolation(RiskAcceptanceError):
    """Cross-tenant reference detected — request denied."""


class RiskAcceptanceInvalidTransition(RiskAcceptanceError):
    """Attempted transition is not permitted by the state machine."""


class RiskAcceptanceConflict(RiskAcceptanceError):
    """Optimistic-lock conflict or duplicate detection."""


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CompensatingControl(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., min_length=1, max_length=128)
    description: str = Field(..., min_length=1, max_length=2048)


class CreateRiskAcceptanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., min_length=1, max_length=64)
    assessment_id: str = Field(..., min_length=1, max_length=64)
    remediation_task_id: str | None = Field(default=None, max_length=64)

    title: str = Field(..., min_length=1, max_length=512)
    business_justification: str = Field(..., min_length=1)
    risk_rationale: str = Field(..., min_length=1)

    accepted_by: str = Field(..., min_length=1, max_length=255)

    approver_name: str | None = Field(default=None, max_length=512)
    approver_role: str | None = Field(default=None, max_length=255)
    approval_authority: ApprovalAuthority | None = None
    approval_source: str = Field(default="api_key", max_length=64)

    expires_at: str | None = None  # ISO 8601 — required for ACTIVE; optional at DRAFT

    inherent_risk: RiskLevel | None = None
    residual_risk: RiskLevel | None = None

    compensating_controls: list[CompensatingControl] = Field(default_factory=list)

    review_required: bool = False
    review_frequency_days: int | None = Field(default=None, ge=1, le=3650)
    next_review_at: str | None = None


class UpdateRiskAcceptanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    business_justification: str | None = Field(default=None, min_length=1)
    risk_rationale: str | None = Field(default=None, min_length=1)

    approver_name: str | None = None
    approver_role: str | None = None
    approval_authority: ApprovalAuthority | None = None

    expires_at: str | None = None

    inherent_risk: RiskLevel | None = None
    residual_risk: RiskLevel | None = None

    compensating_controls: list[CompensatingControl] | None = None

    review_required: bool | None = None
    review_frequency_days: int | None = Field(default=None, ge=1, le=3650)
    next_review_at: str | None = None

    remediation_task_id: str | None = Field(default=None, max_length=64)


class TransitionRiskAcceptanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_status: RiskAcceptanceStatus
    reason: str | None = Field(default=None, min_length=1, max_length=4096)

    # Approval attribution (required when transitioning to APPROVED)
    approver_name: str | None = Field(default=None, max_length=512)
    approver_role: str | None = Field(default=None, max_length=255)
    approval_authority: ApprovalAuthority | None = None


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class RiskAcceptanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    schema_version: str

    finding_id: str
    assessment_id: str
    remediation_task_id: str | None

    status: str
    title: str
    business_justification: str
    risk_rationale: str

    accepted_by: str
    accepted_at: str | None

    approver_name: str | None
    approver_role: str | None
    approval_authority: str | None
    approval_source: str

    expires_at: str | None

    inherent_risk: str | None
    residual_risk: str | None

    compensating_controls: list[Any] | None

    review_required: bool
    review_frequency_days: int | None
    next_review_at: str | None

    created_at: str
    updated_at: str


class RiskAcceptanceAuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    risk_acceptance_id: str
    event_type: str
    actor: str
    old_state: dict[str, Any] | None
    new_state: dict[str, Any] | None
    reason: str | None
    event_at: str


class RiskAcceptanceListResponse(BaseModel):
    items: list[RiskAcceptanceResponse]
    total: int
    limit: int
    offset: int


class RiskAcceptanceAuditListResponse(BaseModel):
    items: list[RiskAcceptanceAuditResponse]
    total: int


class AllowedTransitionsResponse(BaseModel):
    current_status: str
    allowed: list[str]
