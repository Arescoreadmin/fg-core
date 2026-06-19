# services/remediation_portal/schemas.py
from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_METADATA_MAX_BYTES = 8192  # 8 KB

# Approved MIME type registry. image/* family is allowed as a prefix.
_ALLOWED_MIME_PREFIXES = frozenset({"image/"})
_ALLOWED_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "application/zip",
        "application/json",
        "application/octet-stream",
        "text/plain",
        "text/csv",
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/gif",
        "image/tiff",
    }
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Read-only projections
# ---------------------------------------------------------------------------


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
    assigned_at: str | None
    due_date: str | None
    sla_target_days: int | None
    sla_breach_at: str | None
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


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


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
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


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
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


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
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Request schemas — with hardened validators (PR 13.5)
# ---------------------------------------------------------------------------


class AddCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(..., min_length=1, max_length=10000)
    author: str = Field(..., min_length=1, max_length=255)

    @field_validator("body")
    @classmethod
    def _body_not_blank(cls, v: str) -> str:
        if not v.strip():
            try:
                from api.observability.metrics import (
                    PORTAL_COMMENT_VALIDATION_FAILURES_TOTAL,
                    PORTAL_VALIDATION_FAILURES_TOTAL,
                )

                PORTAL_COMMENT_VALIDATION_FAILURES_TOTAL.inc()
                PORTAL_VALIDATION_FAILURES_TOTAL.inc()
            except Exception:
                pass
            raise ValueError("comment body must contain non-whitespace content")
        return v


class EditCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(..., min_length=1, max_length=10000)

    @field_validator("body")
    @classmethod
    def _body_not_blank(cls, v: str) -> str:
        if not v.strip():
            try:
                from api.observability.metrics import (
                    PORTAL_COMMENT_VALIDATION_FAILURES_TOTAL,
                    PORTAL_VALIDATION_FAILURES_TOTAL,
                )

                PORTAL_COMMENT_VALIDATION_FAILURES_TOTAL.inc()
                PORTAL_VALIDATION_FAILURES_TOTAL.inc()
            except Exception:
                pass
            raise ValueError("comment body must contain non-whitespace content")
        return v


class SubmitEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(..., min_length=1, max_length=512)
    content_type: str = Field(..., min_length=1, max_length=128)
    sha256: str = Field(..., min_length=64, max_length=64)
    submitted_by: str = Field(..., min_length=1, max_length=255)
    classification: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=5000)
    evidence_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sha256")
    @classmethod
    def _sha256_hex(cls, v: str) -> str:
        if not _SHA256_RE.fullmatch(v):
            try:
                from api.observability.metrics import (
                    PORTAL_SHA256_VALIDATION_FAILURES_TOTAL,
                    PORTAL_VALIDATION_FAILURES_TOTAL,
                )

                PORTAL_SHA256_VALIDATION_FAILURES_TOTAL.inc()
                PORTAL_VALIDATION_FAILURES_TOTAL.inc()
            except Exception:
                pass
            raise ValueError(
                "sha256 must be exactly 64 lowercase hexadecimal characters ([a-f0-9]{64})"
            )
        return v

    @field_validator("content_type")
    @classmethod
    def _mime_whitelist(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized in _ALLOWED_MIME_TYPES:
            return normalized
        for prefix in _ALLOWED_MIME_PREFIXES:
            if normalized.startswith(prefix):
                return normalized
        try:
            from api.observability.metrics import PORTAL_VALIDATION_FAILURES_TOTAL

            PORTAL_VALIDATION_FAILURES_TOTAL.inc()
        except Exception:
            pass
        raise ValueError(
            f"content_type {v!r} is not in the approved MIME type list. "
            f"Allowed: {sorted(_ALLOWED_MIME_TYPES)} plus image/* family."
        )

    @field_validator("evidence_metadata")
    @classmethod
    def _metadata_size(cls, v: dict) -> dict:
        serialized = json.dumps(v, separators=(",", ":"))
        if len(serialized) > _METADATA_MAX_BYTES:
            try:
                from api.observability.metrics import (
                    PORTAL_METADATA_REJECTIONS_TOTAL,
                    PORTAL_VALIDATION_FAILURES_TOTAL,
                )

                PORTAL_METADATA_REJECTIONS_TOTAL.inc()
                PORTAL_VALIDATION_FAILURES_TOTAL.inc()
            except Exception:
                pass
            raise ValueError(
                f"evidence_metadata exceeds the 8 KB size limit "
                f"(got {len(serialized)} bytes)"
            )
        return v


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
