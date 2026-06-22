# services/governance_reporting/schemas.py
"""Domain enums, exceptions, and Pydantic models for PR 14.5 — Governance Reporting.

Covers the Governance Reporting & Attestation bounded context.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ReportStatus(str, Enum):
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SUPERSEDED = "SUPERSEDED"


class AttestationType(str, Enum):
    OWNER = "OWNER"
    RISK_OWNER = "RISK_OWNER"
    APPROVER = "APPROVER"
    REVIEWER = "REVIEWER"
    EXECUTIVE = "EXECUTIVE"
    AUDITOR = "AUDITOR"


class ReportAuditEventType(str, Enum):
    GENERATED = "GENERATED"
    DOWNLOADED = "DOWNLOADED"
    EXPORTED = "EXPORTED"
    ATTESTED = "ATTESTED"
    SUPERSEDED = "SUPERSEDED"


class VerificationResult(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    TAMPERED = "TAMPERED"


class ActorType(str, Enum):
    HUMAN = "HUMAN"
    AGENT = "AGENT"
    SYSTEM = "SYSTEM"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ReportError(Exception):
    """Base exception for governance reporting errors."""


class ReportNotFound(ReportError):
    """Raised when a requested report or its required data is not found."""


class ReportGenerationFailed(ReportError):
    """Raised when report generation fails."""


class AttestationError(ReportError):
    """Raised when an attestation operation fails."""


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class GenerateReportRequest(BaseModel):
    risk_acceptance_id: str = Field(..., min_length=1, max_length=64)
    generated_by: str = Field(..., min_length=1, max_length=255)
    snapshot_timestamp: str | None = None


class CreateAttestationRequest(BaseModel):
    attestor: str = Field(..., min_length=1, max_length=255)
    attestor_role: str | None = Field(default=None, max_length=255)
    attestation_type: AttestationType
    attestation_statement: str = Field(..., min_length=10, max_length=4096)
    actor_type: ActorType = ActorType.HUMAN


# ---------------------------------------------------------------------------
# Response sub-models
# ---------------------------------------------------------------------------


class RiskSection(BaseModel):
    id: str
    title: str
    business_justification: str
    risk_rationale: str
    residual_risk: str | None
    inherent_risk: str | None
    status: str
    accepted_by: str
    accepted_at: str | None
    expires_at: str | None
    next_review_at: str | None
    review_frequency_days: int | None
    schema_version: str


class ApprovalEntry(BaseModel):
    id: str
    approver_name: str
    approver_email: str | None
    approver_role: str | None
    approval_authority: str | None
    approval_type: str
    status: str
    comments: str | None
    approved_at: str | None
    quorum_required: int | None
    quorum_position: int | None
    is_required: bool


class ReviewEntry(BaseModel):
    id: str
    review_type: str
    reviewer: str | None
    status: str
    review_due_at: str
    review_completed_at: str | None
    outcome: str | None
    review_notes: str | None


class EvidenceEntry(BaseModel):
    id: str
    evidence_id: str
    evidence_type: str
    linked_by: str | None
    linked_at: str


class ControlEntry(BaseModel):
    id: str
    control_id: str
    title: str
    description: str | None
    control_type: str
    control_status: str
    effectiveness_rating: str
    verification_status: str
    criticality: str
    owner: str | None
    last_verified_at: str | None
    review_frequency_days: int
    evidence_count: int
    evidence: list[EvidenceEntry]
    rationale: str | None


class ReportTimelineEntry(BaseModel):
    event_id: str
    event_type: str
    source: str
    actor: str | None
    occurred_at: str
    details: dict[str, Any]


# ---------------------------------------------------------------------------
# List / response models
# ---------------------------------------------------------------------------


class GovernanceReportSummary(BaseModel):
    id: str
    risk_acceptance_id: str
    report_version: int
    generated_at: str
    generated_by: str
    report_hash: str
    status: str
    schema_version: str
    evidence_count: int
    control_count: int
    approval_count: int
    review_count: int


class GovernanceReportListResponse(BaseModel):
    items: list[GovernanceReportSummary]
    total: int
    limit: int
    offset: int


class GovernanceReportDetail(BaseModel):
    id: str
    tenant_id: str
    risk_acceptance_id: str
    report_version: int
    generated_at: str
    generated_by: str
    report_hash: str
    manifest_hash: str | None
    schema_version: str
    snapshot_timestamp: str | None
    status: str
    risk_section: RiskSection
    approval_chain: list[ApprovalEntry]
    review_history: list[ReviewEntry]
    compensating_controls: list[ControlEntry]
    governance_timeline: list[ReportTimelineEntry]
    evidence_count: int
    control_count: int
    approval_count: int
    review_count: int


class ManifestResponse(BaseModel):
    id: str
    report_id: str
    risk_acceptance_hash: str
    approval_chain_hash: str
    review_history_hash: str
    control_evidence_hash: str
    timeline_hash: str
    overall_hash: str


class ReportTimelineResponse(BaseModel):
    items: list[ReportTimelineEntry]
    total: int


class AttestationResponse(BaseModel):
    id: str
    report_id: str
    attestor: str
    attestor_role: str | None
    attestation_type: str
    attested_at: str
    attestation_statement: str
    signature_hash: str
    schema_version: str
    actor_type: str
    created_at: str


class AttestationListResponse(BaseModel):
    items: list[AttestationResponse]
    total: int
    limit: int
    offset: int


class VerificationResponse(BaseModel):
    result: str
    report_id: str
    report_hash: str
    manifest_hash: str
    verified_at: str
    evidence_count: int
    control_count: int
    approval_count: int
    review_count: int
    details: dict[str, Any]
