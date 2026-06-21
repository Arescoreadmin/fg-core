# services/control_registry/schemas.py
"""Pydantic schemas and domain exceptions for PR 14.3 — Compensating Control Registry."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class ControlType(str, Enum):
    TECHNICAL = "technical"
    ADMINISTRATIVE = "administrative"
    PHYSICAL = "physical"
    PROCESS = "process"
    HUMAN = "human"
    DETECTIVE = "detective"
    PREVENTIVE = "preventive"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"


class ControlCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"
    FAILED = "failed"


class EffectivenessRating(str, Enum):
    UNKNOWN = "unknown"
    INEFFECTIVE = "ineffective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    EFFECTIVE = "effective"
    HIGHLY_EFFECTIVE = "highly_effective"


class ControlStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"
    SUSPENDED = "suspended"


class ControlReviewStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    OVERDUE = "overdue"


class ControlReviewOutcome(str, Enum):
    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    NEEDS_UPDATE = "needs_update"


class ControlFreshness(str, Enum):
    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    EXPIRED = "expired"


class ControlEventType(str, Enum):
    CONTROL_CREATED = "control_created"
    CONTROL_UPDATED = "control_updated"
    CONTROL_ACTIVATED = "control_activated"
    CONTROL_RETIRED = "control_retired"
    CONTROL_SUSPENDED = "control_suspended"
    CONTROL_REACTIVATED = "control_reactivated"
    CONTROL_VERIFIED = "control_verified"
    CONTROL_VERIFICATION_EXPIRED = "control_verification_expired"
    CONTROL_EVIDENCE_LINKED = "control_evidence_linked"
    CONTROL_RISK_LINKED = "control_risk_linked"
    CONTROL_REVIEW_CREATED = "control_review_created"
    CONTROL_REVIEW_COMPLETED = "control_review_completed"
    CONTROL_REVIEW_OVERDUE = "control_review_overdue"


# Status transition map — authoritative
CONTROL_STATUS_TRANSITIONS: dict[ControlStatus, set[ControlStatus]] = {
    ControlStatus.DRAFT: {ControlStatus.ACTIVE},
    ControlStatus.ACTIVE: {ControlStatus.RETIRED, ControlStatus.SUSPENDED},
    ControlStatus.SUSPENDED: {ControlStatus.ACTIVE},
    ControlStatus.RETIRED: set(),
}

# Verification statuses that allow evidence-gated verification
VERIFIABLE_STATUSES = {ControlStatus.ACTIVE, ControlStatus.DRAFT}


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class ControlRegistryError(Exception):
    pass


class ControlNotFound(ControlRegistryError):
    pass


class ControlTenantViolation(ControlRegistryError):
    pass


class ControlInvalidTransition(ControlRegistryError):
    pass


class ControlConflict(ControlRegistryError):
    pass


class ControlVerificationError(ControlRegistryError):
    pass


class ControlReviewNotFound(ControlRegistryError):
    pass


class ControlReviewConflict(ControlRegistryError):
    pass


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class CreateControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str | None = Field(default=None, min_length=1, max_length=255)
    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = None
    control_type: ControlType = ControlType.TECHNICAL
    criticality: ControlCriticality = ControlCriticality.MEDIUM
    owner: str | None = Field(default=None, max_length=255)
    owner_email: str | None = Field(default=None, max_length=255)
    business_unit: str | None = Field(default=None, max_length=255)
    effectiveness_rating: EffectivenessRating = EffectivenessRating.UNKNOWN
    review_frequency_days: int = Field(default=90, ge=1)


class UpdateControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = None
    control_type: ControlType | None = None
    criticality: ControlCriticality | None = None
    owner: str | None = None
    owner_email: str | None = None
    business_unit: str | None = None
    effectiveness_rating: EffectivenessRating | None = None
    review_frequency_days: int | None = Field(default=None, ge=1)
    next_review_at: str | None = None
    control_status: ControlStatus | None = None


class VerifyControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notes: str | None = None


class CreateControlReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer: str | None = Field(default=None, max_length=255)
    review_date: str = Field(..., description="ISO 8601 datetime")
    outcome: ControlReviewOutcome | None = None
    notes: str | None = None
    effectiveness_before: EffectivenessRating | None = None
    effectiveness_after: EffectivenessRating | None = None

    @field_validator("review_date")
    @classmethod
    def _validate_review_date(cls, v: str) -> str:
        from datetime import datetime

        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError(
                f"review_date must be a valid ISO 8601 datetime, got {v!r}."
            )
        return v


class CompleteControlReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: ControlReviewOutcome = Field(..., description="Review outcome")
    notes: str | None = None
    effectiveness_before: EffectivenessRating | None = None
    effectiveness_after: EffectivenessRating | None = None


class LinkEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1, max_length=255)
    evidence_type: str = Field(..., min_length=1, max_length=128)
    linked_by: str | None = Field(default=None, max_length=255)


class LinkRiskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_acceptance_id: str = Field(..., min_length=1, max_length=255)
    rationale: str | None = None


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ControlResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    control_id: str
    title: str
    description: str | None
    control_type: str
    criticality: str
    owner: str | None
    owner_email: str | None
    business_unit: str | None
    effectiveness_rating: str
    verification_status: str
    control_status: str
    review_frequency_days: int
    next_review_at: str | None
    last_review_at: str | None
    last_verified_at: str | None
    freshness: str
    created_at: str
    updated_at: str
    schema_version: str


class ControlListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ControlResponse]
    total: int


class ControlEvidenceLinkResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    control_id: str
    evidence_id: str
    evidence_type: str
    linked_at: str
    linked_by: str | None


class ControlEvidenceLinkListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ControlEvidenceLinkResponse]
    total: int


class RiskAcceptanceControlLinkResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    risk_acceptance_id: str
    control_id: str
    rationale: str | None
    created_at: str


class RiskAcceptanceControlLinkListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RiskAcceptanceControlLinkResponse]
    total: int


class ControlReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    control_id: str
    reviewer: str | None
    status: str
    review_date: str
    completed_at: str | None
    outcome: str | None
    notes: str | None
    effectiveness_before: str | None
    effectiveness_after: str | None
    created_at: str
    updated_at: str
    schema_version: str


class ControlReviewListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ControlReviewResponse]
    total: int


class ControlAuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    control_id: str
    event_type: str
    actor: str
    old_state: dict[str, Any] | None
    new_state: dict[str, Any] | None
    reason: str | None
    event_at: str


class ControlAuditListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ControlAuditResponse]
    total: int


class ControlDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_controls: int
    active_controls: int
    draft_controls: int
    retired_controls: int
    verified_controls: int
    unverified_controls: int
    controls_without_evidence: int
    controls_without_owner: int
    controls_with_expired_verification: int
    controls_due_for_review: int
    high_criticality_unverified: int


class FreshnessSweepResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expired: int


class ReviewSweepResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    marked_overdue: int


# ---------------------------------------------------------------------------
# Reporting contracts (no PDF — structured data only for future report PRs)
# ---------------------------------------------------------------------------


class ControlReportingSnapshot(BaseModel):
    """Deterministic reporting model for compensating control appendix."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    title: str
    control_type: str
    criticality: str
    effectiveness_rating: str
    verification_status: str
    freshness: str
    owner: str | None
    last_verified_at: str | None
    evidence_count: int
    review_count: int
