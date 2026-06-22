"""services/evidence_authority/schemas.py — Pydantic schemas for Evidence Authority API.

All request schemas use extra="forbid" to prevent field injection.
All response schemas use extra="forbid" for contract stability.
"""

from __future__ import annotations

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
