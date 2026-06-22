# services/governance_portal/schemas.py
"""Schemas for the Governance Portal bounded context (PR 14.4).

Enums, exceptions, and Pydantic request/response models.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AcknowledgementEntityType(str, Enum):
    ACCEPTED_RISK = "accepted_risk"
    REVIEW_OUTCOME = "review_outcome"
    GOVERNANCE_DECISION = "governance_decision"
    CONTROL_EXCEPTION = "control_exception"
    EVIDENCE_REQUEST = "evidence_request"


class PortalAuditEventType(str, Enum):
    RISK_VIEWED = "risk_viewed"
    RISK_ACKNOWLEDGED = "risk_acknowledged"
    CONTROL_VIEWED = "control_viewed"
    EVIDENCE_VIEWED = "evidence_viewed"
    ACK_CREATED = "ack_created"
    DASHBOARD_VIEWED = "dashboard_viewed"
    AUDIT_ACCESSED = "audit_accessed"


class EvidenceFreshnessState(str, Enum):
    FRESH = "fresh"
    AGING = "aging"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PortalError(Exception):
    pass


class PortalEntityNotFound(PortalError):
    pass


class PortalAcknowledgementConflict(PortalError):
    pass


class PortalAcknowledgementNotFound(PortalError):
    pass


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class CreateAcknowledgementRequest(BaseModel):
    entity_type: AcknowledgementEntityType
    entity_id: str = Field(..., min_length=1, max_length=255)
    acknowledged_by: str = Field(..., min_length=1, max_length=255)
    comments: str | None = Field(default=None, max_length=4096)


# ---------------------------------------------------------------------------
# Response models — risk
# ---------------------------------------------------------------------------


class PortalRiskSummary(BaseModel):
    id: str
    title: str
    status: str
    residual_risk: str | None
    inherent_risk: str | None
    expires_at: str | None
    next_review_at: str | None
    accepted_by: str | None
    compensating_controls_count: int
    schema_version: str


class PortalRiskListResponse(BaseModel):
    items: list[PortalRiskSummary]
    total: int
    limit: int
    offset: int


class PortalApprovalSummary(BaseModel):
    id: str
    approver_name: str | None
    approver_role: str | None
    approval_type: str | None
    status: str
    approved_at: str | None
    comments: str | None


class PortalRiskDetailResponse(BaseModel):
    id: str
    title: str
    status: str
    business_justification: str | None
    risk_rationale: str | None
    residual_risk: str | None
    inherent_risk: str | None
    expires_at: str | None
    next_review_at: str | None
    accepted_by: str | None
    approver_name: str | None
    approver_role: str | None
    approval_authority: str | None
    approval_source: str | None
    compensating_controls: list[str]
    approvals: list[PortalApprovalSummary]
    schema_version: str
    created_at: str
    updated_at: str | None


# ---------------------------------------------------------------------------
# Response models — controls
# ---------------------------------------------------------------------------


class PortalControlSummary(BaseModel):
    id: str
    control_id: str
    title: str
    control_type: str
    control_status: str
    effectiveness_rating: str | None
    verification_status: str
    criticality: str | None
    owner: str | None
    last_verified_at: str | None
    evidence_freshness: EvidenceFreshnessState
    schema_version: str


class PortalControlListResponse(BaseModel):
    items: list[PortalControlSummary]
    total: int
    limit: int
    offset: int


class PortalControlDetailResponse(BaseModel):
    id: str
    control_id: str
    title: str
    description: str | None
    control_type: str
    control_status: str
    effectiveness_rating: str | None
    verification_status: str
    criticality: str | None
    owner: str | None
    owner_email: str | None
    business_unit: str | None
    last_verified_at: str | None
    next_review_at: str | None
    review_frequency_days: int | None
    evidence_count: int
    evidence_freshness: EvidenceFreshnessState
    schema_version: str
    created_at: str
    updated_at: str | None


# ---------------------------------------------------------------------------
# Response models — evidence
# ---------------------------------------------------------------------------


class PortalEvidenceSummary(BaseModel):
    id: str
    control_id: str
    evidence_id: str
    evidence_type: str
    linked_by: str | None
    linked_at: str
    freshness: EvidenceFreshnessState


class PortalEvidenceListResponse(BaseModel):
    items: list[PortalEvidenceSummary]
    total: int
    limit: int
    offset: int


class PortalEvidenceDetailResponse(BaseModel):
    id: str
    control_id: str
    evidence_id: str
    evidence_type: str
    description: str | None
    linked_by: str | None
    linked_at: str
    freshness: EvidenceFreshnessState
    control_title: str | None
    control_verification_status: str | None


# ---------------------------------------------------------------------------
# Response models — acknowledgements
# ---------------------------------------------------------------------------


class AcknowledgementResponse(BaseModel):
    id: str
    tenant_id: str
    entity_type: str
    entity_id: str
    acknowledged_by: str
    acknowledged_at: str
    comments: str | None
    schema_version: str
    created_at: str


class AcknowledgementListResponse(BaseModel):
    items: list[AcknowledgementResponse]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Response models — audit
# ---------------------------------------------------------------------------


class PortalAuditEntryResponse(BaseModel):
    id: str
    event_type: str
    actor: str
    entity_type: str | None
    entity_id: str | None
    event_at: str
    schema_version: str


class PortalAuditListResponse(BaseModel):
    items: list[PortalAuditEntryResponse]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Response models — dashboard
# ---------------------------------------------------------------------------


class PortalDashboardResponse(BaseModel):
    total_risks: int
    active_risks: int
    expiring_risks: int  # expires within 30 days
    expired_risks: int
    total_controls: int
    active_controls: int
    verified_controls: int
    unverified_controls: int
    controls_with_expired_evidence: int
    total_evidence: int
    fresh_evidence: int
    stale_evidence: int  # aging + expiring_soon + expired
    pending_acknowledgements: int  # entity counts with zero acks
    recent_acknowledgements: int  # acks in last 30 days
    governance_health_score: int  # 0-100
