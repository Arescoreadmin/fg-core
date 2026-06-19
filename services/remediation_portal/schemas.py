# services/remediation_portal/schemas.py
from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class VerificationState(str, Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class PortalAuditEventType(str, Enum):
    PORTAL_TASK_VIEWED = "portal_task_viewed"
    PORTAL_COMMENT_ADDED = "portal_comment_added"
    PORTAL_COMMENT_EDITED = "portal_comment_edited"
    PORTAL_EVIDENCE_UPLOADED = "portal_evidence_uploaded"
    PORTAL_OWNER_ACKNOWLEDGED = "portal_owner_acknowledged"
    PORTAL_STATUS_VIEWED = "portal_status_viewed"


class PortalError(Exception):
    """Base portal domain error."""


class PortalNotFound(PortalError):
    """Resource not found or belongs to another tenant."""


class PortalTenantViolation(PortalError):
    """Cross-tenant access detected."""


class PortalCommentNotFound(PortalError):
    """Comment not found or belongs to another tenant."""


class PortalEvidenceDuplicate(PortalError):
    """Evidence with this SHA256 already submitted for this task."""


# Safe client-facing projection — excludes internal fields
class PortalTaskView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    tenant_id: str
    finding_id: str
    assessment_id: str
    title: str
    description: str | None
    recommended_action: str | None
    priority: str
    status: str
    assigned_display_name: str | None
    assigned_at: str | None  # ISO string (converted from datetime if needed)
    due_date: str | None  # ISO string
    sla_target_days: int | None
    sla_breach_at: str | None  # ISO string
    sla_status: str
    created_at: str
    updated_at: str
    closed_at: str | None
    comment_count: int = 0
    evidence_count: int = 0


class PortalTaskSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str
    priority: str
    status: str
    sla_status: str
    assigned_display_name: str | None
    due_date: str | None
    sla_breach_at: str | None


class PortalDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    open_count: int
    planned_count: int
    in_progress_count: int
    closed_count: int
    accepted_risk_count: int
    overdue_count: int
    unassigned_count: int
    recent_open: list[PortalTaskSummary]
    overdue_tasks: list[PortalTaskSummary]


class PortalCommentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    task_id: str
    author: str
    body: str
    is_edited: bool
    created_at: str
    updated_at: str


class PortalCommentListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    comments: list[PortalCommentResponse]
    total: int


class PortalEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    task_id: str
    filename: str
    content_type: str
    sha256: str
    submitted_by: str
    submitted_at: str
    classification: str | None
    description: str | None
    verification_state: str


class PortalEvidenceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    evidence: list[PortalEvidenceResponse]
    total: int


class PortalAuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    task_id: str
    event_type: str
    actor: str
    event_at: str
    event_metadata: dict[str, Any]


class PortalAuditListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    events: list[PortalAuditEventResponse]


class AddCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(..., min_length=1, max_length=10000)
    author: str = Field(..., min_length=1, max_length=255)


class EditCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(..., min_length=1, max_length=10000)


class SubmitEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(..., min_length=1, max_length=512)
    content_type: str = Field(..., min_length=1, max_length=128)
    sha256: str = Field(..., min_length=64, max_length=64)
    submitted_by: str = Field(..., min_length=1, max_length=255)
    classification: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=5000)
    evidence_metadata: dict[str, Any] = Field(default_factory=dict)


class AcknowledgeOwnershipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acknowledged_by: str = Field(..., min_length=1, max_length=255)
    acknowledgement_note: str | None = Field(default=None, max_length=2000)


class AcknowledgeOwnershipResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    acknowledged_by: str
    acknowledged_at: str
    task_status: str
    sla_status: str
