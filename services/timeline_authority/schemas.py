"""Timeline Authority schemas — PR 14.6.2."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


class TimelineSourceSystem(str, Enum):
    EVIDENCE_AUTHORITY = "EVIDENCE_AUTHORITY"
    RISK_GOVERNANCE = "RISK_GOVERNANCE"
    CONTROL_REGISTRY = "CONTROL_REGISTRY"
    GOVERNANCE_PORTAL = "GOVERNANCE_PORTAL"
    GOVERNANCE_REPORTING = "GOVERNANCE_REPORTING"
    FIELD_ASSESSMENT = "FIELD_ASSESSMENT"
    FRAMEWORK_AUTHORITY = "FRAMEWORK_AUTHORITY"
    REMEDIATION_VERIFICATION = "REMEDIATION_VERIFICATION"
    AUTONOMOUS_GOVERNANCE = "AUTONOMOUS_GOVERNANCE"
    TIMELINE_AUTHORITY = "TIMELINE_AUTHORITY"


class TimelineEntityType(str, Enum):
    EVIDENCE = "EVIDENCE"
    RISK = "RISK"
    CONTROL = "CONTROL"
    FRAMEWORK = "FRAMEWORK"
    FRAMEWORK_CONTROL = "FRAMEWORK_CONTROL"
    MAPPING = "MAPPING"
    ENGAGEMENT = "ENGAGEMENT"
    REPORT = "REPORT"
    DECISION = "DECISION"
    AGENT = "AGENT"
    TENANT = "TENANT"
    REMEDIATION = "REMEDIATION"


class TimelineSeverity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class TimelineActorType(str, Enum):
    HUMAN = "HUMAN"
    SERVICE = "SERVICE"
    AGENT = "AGENT"
    AUTONOMOUS_SYSTEM = "AUTONOMOUS_SYSTEM"
    SYSTEM = "SYSTEM"


class TimelineAuthorityLevel(str, Enum):
    SYSTEM = "SYSTEM"
    HUMAN = "HUMAN"
    REVIEWER = "REVIEWER"
    COMMITTEE = "COMMITTEE"
    AUTONOMOUS_AGENT = "AUTONOMOUS_AGENT"
    AUTONOMOUS_SYSTEM = "AUTONOMOUS_SYSTEM"
    AGI_SYSTEM = "AGI_SYSTEM"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TimelineAuthorityError(Exception):
    pass


class TimelineEventNotFound(TimelineAuthorityError):
    pass


class TimelineConflict(TimelineAuthorityError):
    pass


class TimelineIntegrityError(TimelineAuthorityError):
    pass


class TimelineTenantViolation(TimelineAuthorityError):
    pass


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class TimelineEventRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_system: TimelineSourceSystem
    source_type: str = ""
    entity_type: TimelineEntityType
    entity_id: str
    event_type: str
    actor_type: TimelineActorType = TimelineActorType.SYSTEM
    actor_id: str = ""
    occurred_at: str  # ISO 8601 UTC
    severity: TimelineSeverity = TimelineSeverity.INFO
    metadata_json: dict[str, Any] = {}
    correlation_id: str = ""
    causation_id: str = ""
    # P1: authority level
    authority_level: TimelineAuthorityLevel = TimelineAuthorityLevel.SYSTEM
    # P1: signature reservation (unused until Notary / cryptographic chains)
    signature_algorithm: str = ""
    signature_value: str = ""
    signed_at: str | None = None
    # P1: external references (Jira, ServiceNow, Azure DevOps, legal hold)
    external_reference: str = ""
    external_reference_type: str = ""
    # P1: federation hooks (CGIN / cross-tenant governance analytics)
    origin_system: str = ""
    origin_tenant: str = ""
    origin_event_id: str = ""


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    tenant_id: str
    event_id: str
    event_hash: str
    prev_event_hash: str
    source_system: str
    source_type: str
    entity_type: str
    entity_id: str
    event_type: str
    actor_type: str
    actor_id: str
    occurred_at: str
    recorded_at: str
    severity: str
    metadata_json: dict[str, Any]
    correlation_id: str
    causation_id: str
    replay_version: int
    schema_version: int
    # P1 fields
    authority_level: str
    signature_algorithm: str
    signature_value: str
    signed_at: str | None
    external_reference: str
    external_reference_type: str
    origin_system: str
    origin_tenant: str
    origin_event_id: str


class TimelineReplayResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    events: list[TimelineEventResponse]
    event_count: int
    replay_deterministic: bool = True
    entity_type: str | None = None
    entity_id: str | None = None
    source_system: str | None = None


class TimelineExportChainSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity_type: str
    entity_id: str
    event_count: int
    chain_valid: bool
    first_event_id: str
    last_event_id: str
    last_event_hash: str


class TimelineExportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    format: str
    events: list[TimelineEventResponse]
    event_count: int
    integrity_status: str  # "valid" | "invalid" | "unchecked"
    chain_verification_summary: list[TimelineExportChainSummary]
    deterministic_ordering: bool = True


class TimelineChainStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity_type: str
    entity_id: str
    event_count: int
    chain_valid: bool
    broken_at_event_id: str | None = None


class TimelineIntegrityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_events: int
    chains_checked: int
    chains_valid: int
    chains_invalid: int
    integrity_valid: bool
    chain_details: list[TimelineChainStatus]
    hash_chain_validations: int


class TimelineStatisticsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_events: int
    events_by_source_system: dict[str, int]
    events_by_entity_type: dict[str, int]
    events_by_severity: dict[str, int]
    unique_entities: int
    unique_source_systems: int
