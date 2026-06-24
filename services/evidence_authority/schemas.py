"""services/evidence_authority/schemas.py — Pydantic schemas for Evidence Authority API.

All request schemas use extra="forbid" to prevent field injection.
All response schemas use extra="forbid" for contract stability.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from services.evidence_authority.models import (
    ActorType,
    EvidenceClassification,
    EvidenceCollectionMethod,
    EvidenceLifecycleState,
    EvidenceOwnershipRole,
    EvidenceRelatedEntityType,
    EvidenceRelationshipType,
    EvidenceSourceType,
    EvidenceTrustState,
    VerificationSource,
)


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class EvidenceAuthorityError(Exception):
    pass


class EvidenceNotFound(EvidenceAuthorityError):
    pass


class EvidenceTenantViolation(EvidenceAuthorityError):
    pass


class EvidenceInvalidTransition(EvidenceAuthorityError):
    pass


class EvidenceConflict(EvidenceAuthorityError):
    pass


class EvidenceImmutableState(EvidenceAuthorityError):
    pass


class EvidenceInvalidTrustTransition(EvidenceAuthorityError):
    pass


class EvidenceOwnershipNotFound(EvidenceAuthorityError):
    pass


class EvidenceRelationshipConflict(EvidenceAuthorityError):
    pass


# ---------------------------------------------------------------------------
# Create Evidence
# ---------------------------------------------------------------------------


class CreateEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None)
    source_type: EvidenceSourceType
    source_system: str | None = Field(default=None, max_length=255)
    source_ref: str | None = Field(default=None, max_length=1024)
    collection_method: EvidenceCollectionMethod
    classification: EvidenceClassification = EvidenceClassification.INTERNAL
    classification_labels: list[str] = Field(default_factory=list)
    engagement_id: str | None = Field(default=None, max_length=64)
    collected_at: str = Field(
        ..., description="ISO 8601 UTC timestamp of evidence collection at source"
    )
    expires_at: str | None = Field(
        default=None, description="ISO 8601 UTC expiration timestamp"
    )

    @field_validator("collected_at", "expires_at")
    @classmethod
    def _validate_iso8601(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from datetime import datetime

        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Must be ISO 8601 datetime, got {v!r}")
        return v

    @field_validator("classification_labels")
    @classmethod
    def _validate_labels(cls, v: list[str]) -> list[str]:
        from services.evidence_authority.models import KNOWN_CLASSIFICATION_LABELS

        unknown = [lbl for lbl in v if lbl not in KNOWN_CLASSIFICATION_LABELS]
        if unknown:
            # Warn but allow — labels set is open for extensibility
            pass
        return v


# ---------------------------------------------------------------------------
# Update Evidence Metadata
# ---------------------------------------------------------------------------


class UpdateEvidenceMetadataRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = None
    source_system: str | None = Field(default=None, max_length=255)
    source_ref: str | None = Field(default=None, max_length=1024)
    expires_at: str | None = Field(default=None)

    @field_validator("expires_at")
    @classmethod
    def _validate_iso8601(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from datetime import datetime

        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Must be ISO 8601 datetime, got {v!r}")
        return v


# ---------------------------------------------------------------------------
# Lifecycle Transition
# ---------------------------------------------------------------------------


class TransitionLifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: EvidenceLifecycleState
    reason: str | None = Field(default=None, max_length=1024)


# ---------------------------------------------------------------------------
# Assign Ownership
# ---------------------------------------------------------------------------


class AssignOwnershipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: EvidenceOwnershipRole
    actor_id: str = Field(..., min_length=1, max_length=255)
    actor_type: ActorType = ActorType.HUMAN


# ---------------------------------------------------------------------------
# Revoke Ownership
# ---------------------------------------------------------------------------


class RevokeOwnershipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ownership_id: str = Field(..., min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=512)


# ---------------------------------------------------------------------------
# Verify Evidence (trust state transition)
# ---------------------------------------------------------------------------


class VerifyEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_trust_state: EvidenceTrustState
    verification_source: VerificationSource
    verification_method: str | None = Field(default=None, max_length=128)
    confidence_score: int | None = Field(default=None, ge=0, le=100)
    notes: str | None = Field(default=None, max_length=2048)


# ---------------------------------------------------------------------------
# Link Relationship
# ---------------------------------------------------------------------------


class LinkRelationshipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    related_entity_type: EvidenceRelatedEntityType
    related_entity_id: str = Field(..., min_length=1, max_length=255)
    relationship_type: EvidenceRelationshipType = EvidenceRelationshipType.LINKED_TO
    link_metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Response: Evidence Record
# ---------------------------------------------------------------------------


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_ref: str
    lifecycle_state: str
    classification: str
    classification_labels: list[str]
    source_type: str
    source_system: str | None
    source_ref: str | None
    collection_method: str
    title: str
    description: str | None
    content_hash: str | None
    content_hash_algorithm: str | None
    integrity_hash: str | None
    trust_state: str
    trust_score: int | None
    verification_count: int
    last_verification_source: str | None
    owner_id: str | None
    owner_type: str | None
    creator_id: str
    creator_type: str
    engagement_id: str | None
    collected_at: str
    submitted_at: str | None
    reviewed_at: str | None
    verified_at: str | None
    expires_at: str | None
    revoked_at: str | None
    archived_at: str | None
    evidence_version: str
    superseded_by: str | None
    schema_version: str
    created_at: str
    updated_at: str
    # PR 14.6.5 — quality scores (None until first compute)
    freshness_score: int | None = None
    verification_score: int | None = None
    completeness_score: int | None = None
    quality_last_computed_at: str | None = None


class EvidenceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EvidenceResponse]
    total: int
    offset: int
    limit: int


# ---------------------------------------------------------------------------
# Response: Ownership
# ---------------------------------------------------------------------------


class EvidenceOwnershipResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    role: str
    actor_id: str
    actor_type: str
    assigned_at: str
    assigned_by: str
    revoked_at: str | None
    revoked_by: str | None
    is_active: bool
    created_at: str


class EvidenceOwnershipListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EvidenceOwnershipResponse]
    total: int


# ---------------------------------------------------------------------------
# Response: Relationship
# ---------------------------------------------------------------------------


class EvidenceRelationshipResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    related_entity_type: str
    related_entity_id: str
    relationship_type: str
    link_metadata: dict[str, Any]
    linked_at: str
    linked_by: str
    created_at: str


class EvidenceRelationshipListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EvidenceRelationshipResponse]
    total: int


# ---------------------------------------------------------------------------
# Response: Trust Event
# ---------------------------------------------------------------------------


class EvidenceTrustEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    from_trust_state: str
    to_trust_state: str
    verification_source: str
    verifier_id: str
    verifier_type: str
    verification_method: str | None
    confidence_score: int | None
    notes: str | None
    event_hash: str | None
    prev_event_hash: str | None
    created_at: str


class EvidenceTrustHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    current_trust_state: str
    trust_score: int | None
    verification_count: int
    events: list[EvidenceTrustEventResponse]


# ---------------------------------------------------------------------------
# Response: Audit Event
# ---------------------------------------------------------------------------


class EvidenceAuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    event_type: str
    from_state: str | None
    to_state: str | None
    actor_id: str
    actor_type: str
    reason: str | None
    event_metadata: dict[str, Any]
    transaction_id: str | None
    created_at: str


class EvidenceAuditListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EvidenceAuditEventResponse]
    total: int


# ---------------------------------------------------------------------------
# Response: Dashboard
# ---------------------------------------------------------------------------


class EvidenceDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_evidence: int
    by_lifecycle_state: dict[str, int]
    by_trust_state: dict[str, int]
    by_classification: dict[str, int]
    by_source_type: dict[str, int]
    verified_count: int
    unverified_count: int
    expired_count: int
    revoked_count: int
    high_confidence_count: int
    disputed_count: int
    expiring_soon_count: int  # expires within 30 days
    without_owner_count: int
    without_relationships_count: int


# ---------------------------------------------------------------------------
# PR 14.6.5 — Quality Scores + Governance Status Report
# ---------------------------------------------------------------------------


class EvidenceQualityScoreResponse(BaseModel):
    """Deterministic quality scores for a single evidence record."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    freshness_score: int
    verification_score: int
    completeness_score: int
    trust_score: int | None
    quality_last_computed_at: str


class EvidenceStatusItemResponse(BaseModel):
    """Canonical evidence status for a single item — for governance consumers."""

    model_config = ConfigDict(extra="forbid")

    id: str
    evidence_ref: str
    title: str
    lifecycle_state: str
    trust_state: str
    freshness_score: int | None
    trust_score: int | None
    verification_score: int | None
    completeness_score: int | None
    quality_last_computed_at: str | None
    owner_id: str | None
    expires_at: str | None
    verified_at: str | None
    collected_at: str


class EvidenceStatusReportResponse(BaseModel):
    """Governance-ready evidence status report.

    All status information originates from Canonical Evidence Authority.
    Consumers must not compute status from any other source.
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    generated_at: str
    total: int
    items: list[EvidenceStatusItemResponse]
    # State aggregations
    by_lifecycle_state: dict[str, int]
    by_trust_state: dict[str, int]
    # Quality aggregations (None if no evidence has been scored yet)
    avg_freshness_score: float | None
    avg_verification_score: float | None
    avg_completeness_score: float | None
    avg_trust_score: float | None
    # Governance health indicators
    without_owner_count: int
    expired_count: int
    expiring_soon_count: int
    disputed_count: int
    invalidated_count: int
    attested_count: int


# ---------------------------------------------------------------------------
# PR 14.6.5A — Exception classes
# ---------------------------------------------------------------------------


class VerificationConflict(EvidenceAuthorityError):
    pass


class ControlLinkConflict(EvidenceAuthorityError):
    pass


class RiskLinkConflict(EvidenceAuthorityError):
    pass


# ---------------------------------------------------------------------------
# PR 14.6.5A — Request schemas
# ---------------------------------------------------------------------------

from services.evidence_authority.models import (  # noqa: E402
    EvidenceLinkTargetType,
    VerificationActorType,
    VerificationResult,
    VerificationType,
)


def _validate_iso8601(v: str) -> str:
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid ISO 8601 datetime: {v!r}") from exc
    return v


class CreateVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verification_type: VerificationType
    verification_method: str | None = Field(default=None, max_length=256)
    verification_result: VerificationResult
    verification_confidence: int | None = Field(default=None, ge=0, le=100)
    verification_notes: str | None = Field(default=None, max_length=2048)
    verified_by: str = Field(..., min_length=1, max_length=255)
    verified_actor_type: VerificationActorType = VerificationActorType.HUMAN
    verified_at: str = Field(..., description="ISO 8601 UTC")

    @field_validator("verified_at")
    @classmethod
    def _check_verified_at(cls, v: str) -> str:
        return _validate_iso8601(v)


class SetSlaDeadlinesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_due_at: str | None = None
    verification_due_at: str | None = None
    freshness_due_at: str | None = None

    @field_validator(
        "review_due_at", "verification_due_at", "freshness_due_at", mode="before"
    )
    @classmethod
    def _check_iso8601(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_iso8601(v)


class LinkControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(..., min_length=1, max_length=64)


class LinkRiskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    linked_resource_id: str = Field(..., min_length=1, max_length=64)
    link_type: EvidenceLinkTargetType


# ---------------------------------------------------------------------------
# PR 14.6.5A — Response schemas
# ---------------------------------------------------------------------------


class VerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    verification_type: str
    verification_method: str | None
    verification_result: str
    verification_confidence: int | None
    verification_notes: str | None
    verified_by: str
    verified_actor_type: str
    verified_at: str
    schema_version: str
    created_at: str


class VerificationSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    verification_count: int
    passed_count: int
    failed_count: int
    inconclusive_count: int
    verification_success_rate: float | None
    verification_age_days: int | None
    latest_verification_at: str | None
    latest_verification_result: str | None
    latest_verification_type: str | None


class VerificationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[VerificationResponse]
    total: int


class SlaStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    review_due_at: str | None
    verification_due_at: str | None
    freshness_due_at: str | None
    review_sla_status: str | None
    verification_sla_status: str | None
    freshness_sla_status: str | None
    computed_at: str


class ControlLinkResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    control_id: str
    linked_by: str
    linked_at: str
    created_at: str


class ControlLinkListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ControlLinkResponse]
    total: int


class RiskLinkResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    linked_resource_id: str
    link_type: str
    linked_by: str
    linked_at: str
    created_at: str


class RiskLinkListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RiskLinkResponse]
    total: int


class CoverageAnalyticsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    generated_at: str
    controls_with_evidence: int
    controls_without_evidence: int
    risks_with_evidence: int
    risks_without_evidence: int
    findings_with_evidence: int
    exceptions_with_evidence: int
    verified_controls: int
    unverified_controls: int
    total_control_links: int
    total_risk_links: int
    evidence_density: float
    coverage_percentage: float
    total_known_controls: int


class HealthSignalsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    generated_at: str
    verification_overdue_count: int
    review_overdue_count: int
    freshness_overdue_count: int
    orphaned_evidence_count: int
    unlinked_evidence_count: int
    disputed_evidence_count: int
    invalidated_evidence_count: int
    attested_evidence_count: int
    verified_evidence_count: int


# ---------------------------------------------------------------------------
# PR 14.6.5A — CGIN canonical snapshots (Sections 7 & 8)
# ---------------------------------------------------------------------------


class EvidenceStatusSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    snapshot_version: str
    tenant_id: str
    generated_at: str
    evidence_id: str
    lifecycle_state: str
    trust_state: str
    freshness_score: int | None
    verification_score: int | None
    completeness_score: int | None
    trust_score: int | None
    sla_review_status: str | None
    sla_verification_status: str | None
    benchmark_freshness_percentile: int | None = None
    benchmark_verification_percentile: int | None = None


class VerificationSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    snapshot_version: str
    tenant_id: str
    evidence_id: str
    generated_at: str
    verification_count: int
    passed_count: int
    verification_success_rate: float | None
    latest_verification_at: str | None
    latest_verification_type: str | None
    verification_age_days: int | None


class CoverageSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    snapshot_version: str
    tenant_id: str
    generated_at: str
    controls_with_evidence: int
    controls_without_evidence: int
    risks_with_evidence: int
    verified_controls: int
    evidence_density: float
    coverage_percentage: float
    benchmark_density_percentile: int | None = None
    benchmark_coverage_percentile: int | None = None


class HealthSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    snapshot_version: str
    tenant_id: str
    generated_at: str
    verification_overdue_count: int
    review_overdue_count: int
    freshness_overdue_count: int
    orphaned_evidence_count: int
    unlinked_evidence_count: int
    disputed_evidence_count: int
    invalidated_evidence_count: int
    attested_evidence_count: int
    verified_evidence_count: int


class CGINSnapshotBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    bundle_version: str
    tenant_id: str
    generated_at: str
    evidence_snapshots: list[EvidenceStatusSnapshot]
    verification_snapshots: list[VerificationSnapshot]
    coverage: CoverageSnapshot
    health: HealthSnapshot
