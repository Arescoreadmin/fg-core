"""services/actor_identity/models.py — Pydantic v2 models for actor attribution (PR 535)."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ActorType(str, Enum):
    human_user = "human_user"
    system_process = "system_process"
    automation = "automation"
    connector = "connector"
    api_client = "api_client"
    service_account = "service_account"
    scheduled_job = "scheduled_job"
    ai_agent = "ai_agent"
    governance_workflow = "governance_workflow"
    autonomous_system = "autonomous_system"
    unknown = "unknown"


class TrustLevel(str, Enum):
    verified = "verified"
    high = "high"
    medium = "medium"
    low = "low"
    unverified = "unverified"


class SnapshotReason(str, Enum):
    action_time = "action_time"
    audit_event = "audit_event"
    periodic = "periodic"


class AttributionEventType(str, Enum):
    scan_ingestion = "scan_ingestion"
    document_analysis = "document_analysis"
    observation = "observation"
    artifact_upload = "artifact_upload"
    report_generation = "report_generation"
    report_approval = "report_approval"
    report_supersede = "report_supersede"
    report_delivery = "report_delivery"
    manifest_generation = "manifest_generation"
    evidence_provenance = "evidence_provenance"
    governance_decision = "governance_decision"
    custom = "custom"


# ---------------------------------------------------------------------------
# Core identity models
# ---------------------------------------------------------------------------


class ActorIdentityResolved(BaseModel):
    """Resolved actor identity extracted from an inbound request."""

    actor_id: str
    actor_type: ActorType
    actor_subject: str
    actor_display_name: str
    email_hash: Optional[str] = None
    authentication_method: str
    identity_provider: str
    governance_role: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.unverified
    is_service_account: bool = False
    is_robot: bool = False
    service_account_id: Optional[str] = None
    robot_identity: Optional[str] = None
    delegated_by: Optional[str] = None
    tenant_id: str
    organization_id: Optional[str] = None


class ActorIdentitySnapshot(BaseModel):
    """Captured immutable identity snapshot at action time."""

    snapshot_id: str
    actor_id: str
    actor_type: ActorType
    actor_subject: str
    actor_display_name: str
    email_hash: Optional[str] = None
    authentication_method: str
    identity_provider: str
    governance_role: Optional[str] = None
    permission_snapshot: list[str] = Field(default_factory=list)
    groups_snapshot: list[str] = Field(default_factory=list)
    department: Optional[str] = None
    organization_snapshot: Optional[str] = None
    trust_level: TrustLevel
    is_service_account: bool = False
    is_robot: bool = False
    delegated_by: Optional[str] = None
    captured_at: str
    tenant_id: str
    snapshot_reason: SnapshotReason = SnapshotReason.action_time


# ---------------------------------------------------------------------------
# Fingerprinting & attribution
# ---------------------------------------------------------------------------


class ActorFingerprint(BaseModel):
    """Non-repudiation fingerprints for a single attribution event."""

    actor_fingerprint: str
    identity_fingerprint: str
    request_fingerprint: str
    attribution_hash: str  # SHA-256 of the three fingerprints
    event_hash: str  # SHA-256 of attribution_hash + event context
    previous_hash: Optional[str] = None


class AutonomousActorFields(BaseModel):
    """Additional fields for autonomous system actors."""

    decision_confidence: Optional[float] = None
    policy_version: Optional[str] = None
    authority_chain: Optional[list[str]] = Field(default_factory=list)
    execution_context: Optional[dict] = None
    reasoning_reference: Optional[str] = None
    governance_scope: Optional[str] = None


class ActorAttributionContext(BaseModel):
    """Full attribution context attached to a governance event."""

    attribution_id: str
    actor_id: str
    snapshot_id: str
    event_type: AttributionEventType
    event_ref: Optional[str] = None
    event_ref_type: Optional[str] = None
    actor_type: ActorType
    actor_display_name: str
    authentication_method: str
    identity_provider: str
    session_id: Optional[str] = None
    request_id: str
    client_ip_hash: Optional[str] = None
    user_agent_hash: Optional[str] = None
    governance_role: Optional[str] = None
    trust_level: TrustLevel
    fingerprints: ActorFingerprint
    created_at: str
    tenant_id: str
    organization_id: Optional[str] = None
    autonomous_fields: Optional[AutonomousActorFields] = None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class IdentityValidationResult(BaseModel):
    """Result of an actor identity validation check."""

    valid: bool
    actor_id: str
    actor_type: ActorType
    violations: list[str] = Field(default_factory=list)
    trust_level: TrustLevel
    validated_at: str
