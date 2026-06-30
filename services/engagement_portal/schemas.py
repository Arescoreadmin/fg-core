"""Pydantic schemas for the Engagement Portal (PR 18.2).

All request and response schemas use ConfigDict(extra="forbid") to prevent
field injection and contract drift.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Exception hierarchy (schema-level, used by engine + API layer)
# ---------------------------------------------------------------------------


class EngagementPortalError(Exception):
    """Base exception for the Engagement Portal."""


class PortalEntityNotFound(EngagementPortalError):
    """Requested entity not found for tenant."""


class PortalAccessDenied(EngagementPortalError):
    """Tenant scope violation or missing tenant context."""


class PortalSearchError(EngagementPortalError):
    """Search request invalid or backend failure."""


class PortalNotificationError(EngagementPortalError):
    """Notification write or delivery failure."""


class PortalConfigError(EngagementPortalError):
    """Portal configuration or preference write failure."""


class PortalTimelineError(EngagementPortalError):
    """Timeline read failure."""


class PortalActivityError(EngagementPortalError):
    """Activity log write failure."""


class PortalStatisticsError(EngagementPortalError):
    """Statistics aggregation failure."""


class PortalWorkspaceError(EngagementPortalError):
    """Workspace read failure."""


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class UpdatePreferencesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    theme: str | None = Field(default=None, max_length=64)
    notification_email: bool = True
    timezone: str | None = Field(default=None, max_length=64)
    language: str | None = Field(default=None, max_length=32)


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(..., min_length=1, max_length=512)
    scope: list[str] | None = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class AcknowledgeNotificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notification_id: str = Field(..., min_length=1, max_length=64)


class RecordActivityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(..., min_length=1, max_length=64)
    workspace: str | None = Field(default=None, max_length=64)
    entity_id: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    schema_version: str
    timestamp: str


class DashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    engagement_id: str | None
    overall_readiness: float | None
    governance_score: float | None
    assessment_progress: float | None
    evidence_collected: int
    evidence_verified: int
    evidence_freshness_pct: float | None
    open_findings: int
    remediation_progress: float | None
    pending_approvals: int
    latest_report_id: str | None
    latest_report_state: str | None
    verification_status: str | None
    trust_status: str | None
    transparency_status: str | None
    generated_at: str


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    source_system: str
    entity_id: str | None
    entity_type: str | None
    actor_id: str | None
    summary: str
    occurred_at: str
    authoritative_ref: str | None


class TimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TimelineEvent]
    total: int
    offset: int
    limit: int


class EvidenceWorkspaceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    title: str | None
    classification: str | None
    freshness_status: str | None
    verification_status: str | None
    trust_digest: str | None
    transparency_entry: str | None
    collected_at: str | None
    reviewer_notes: str | None


class EvidenceWorkspaceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EvidenceWorkspaceItem]
    total: int
    offset: int
    limit: int


class ReportWorkspaceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: str
    report_ref: str
    report_type: str
    lifecycle_state: str
    title: str
    quality_grade: str | None
    published_at: str | None
    has_pdf: bool
    has_html: bool
    has_json: bool
    manifest_hash: str | None
    trust_verified: bool


class ReportWorkspaceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ReportWorkspaceItem]
    total: int
    offset: int
    limit: int


class RemediationWorkspaceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    title: str | None
    priority: str | None
    status: str | None
    owner_id: str | None
    due_date: str | None
    verification_required: bool
    evidence_required: bool
    completion_pct: float | None


class RemediationWorkspaceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RemediationWorkspaceItem]
    total: int
    offset: int
    limit: int


class TrustWorkspaceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trust_manifest: dict[str, Any] | None
    signing_algorithm: str | None
    key_provider: str | None
    provider_version: str | None
    trust_digest: str | None
    verified: bool
    last_signed_at: str | None
    history_count: int


class TransparencyWorkspaceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transparency_root: str | None
    merkle_root: str | None
    append_only_confirmed: bool
    sequence_count: int
    last_entry_at: str | None
    proof_available: bool


class ActivityFeedItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activity_id: str
    event_type: str
    workspace: str | None
    entity_id: str | None
    actor_id: str | None
    occurred_at: str
    summary: str | None


class ActivityFeedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ActivityFeedItem]
    total: int
    offset: int
    limit: int


class PortalStatisticsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_activities: int
    total_reports_viewed: int
    total_evidence_viewed: int
    total_searches: int
    active_notifications: int
    preferences_set: bool
    computed_at: str


class SearchResultItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_id: str
    result_type: str
    title: str | None
    ref: str | None
    matched_field: str | None
    score: float | None


class SearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    items: list[SearchResultItem]
    total: int
    took_ms: int | None


class NotificationItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notification_id: str
    notification_type: str
    status: str
    subject: str | None
    body: str | None
    created_at: str
    delivered_at: str | None


class NotificationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[NotificationItem]
    total: int
    offset: int
    limit: int


class PreferencesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    theme: str | None
    notification_email: bool
    timezone: str | None
    language: str | None
    updated_at: str | None
