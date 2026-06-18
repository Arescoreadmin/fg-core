# services/remediation/schemas.py
"""Domain enums, exceptions, and Pydantic schemas for the Remediation subsystem.

PR 13.1 — Remediation Management Foundation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RemediationPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RemediationStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    # PR 13.2 will add: in_progress, pending_verification, accepted_risk, etc.


class RemediationAuditEventType(str, Enum):
    TASK_CREATED = "task_created"
    TASK_UPDATED = "task_updated"
    TASK_CLOSED = "task_closed"
    TASK_DELETED = "task_deleted"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RemediationError(Exception):
    """Base remediation domain error."""


class RemediationNotFound(RemediationError):
    """Task does not exist or does not belong to the caller's tenant."""


class RemediationTenantViolation(RemediationError):
    """Cross-tenant reference detected — request denied."""


class RemediationReferenceError(RemediationError):
    """Finding or assessment referenced by the task does not exist."""


class RemediationConflict(RemediationError):
    """Operation conflicts with current task state (e.g., closing an already-closed task)."""


# ---------------------------------------------------------------------------
# Internal value objects
# ---------------------------------------------------------------------------


class TaskSnapshot(BaseModel):
    """Immutable point-in-time snapshot of a task for audit old_state/new_state."""

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
    created_by: str
    assigned_to: str | None
    created_at: str
    updated_at: str
    closed_at: str | None
    task_metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# API request / response schemas
# ---------------------------------------------------------------------------


class CreateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., min_length=1, max_length=64)
    assessment_id: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=10000)
    recommended_action: str | None = Field(default=None, max_length=10000)
    priority: RemediationPriority = RemediationPriority.MEDIUM
    assigned_to: str | None = Field(default=None, max_length=255)
    task_metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=10000)
    recommended_action: str | None = Field(default=None, max_length=10000)
    priority: RemediationPriority | None = None
    assigned_to: str | None = None
    task_metadata: dict[str, Any] | None = None


class TaskResponse(BaseModel):
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
    created_by: str
    assigned_to: str | None
    created_at: str
    updated_at: str
    closed_at: str | None
    task_metadata: dict[str, Any]
    schema_version: str


class TaskListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tasks: list[TaskResponse]
    total: int


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    task_id: str
    event_type: str
    actor: str
    old_state: dict[str, Any] | None
    new_state: dict[str, Any] | None
    event_at: str
