"""Enums and constants for the Remediation Authority (PR 18.3).

Pure Python. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from enum import Enum


REMEDIATION_AUTHORITY_SCHEMA_VERSION: str = "1.0"


class RemediationPlanState(str, Enum):
    """Lifecycle of a remediation plan."""

    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    ON_HOLD = "ON_HOLD"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    ARCHIVED = "ARCHIVED"


class RemediationTaskState(str, Enum):
    """Lifecycle of a remediation task."""

    OPEN = "OPEN"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    VERIFYING = "VERIFYING"
    APPROVED = "APPROVED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    REOPENED = "REOPENED"


class RemediationPriority(str, Enum):
    """Priority classification for remediation tasks."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RemediationVerificationState(str, Enum):
    """Verification lifecycle of a remediation task closure."""

    PENDING = "PENDING"
    IN_REVIEW = "IN_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class AssignmentRole(str, Enum):
    """Role of an actor assigned to a remediation task."""

    OWNER = "OWNER"
    REVIEWER = "REVIEWER"
    APPROVER = "APPROVER"
    CONTRIBUTOR = "CONTRIBUTOR"


class SlaStatus(str, Enum):
    """SLA computation result for a task."""

    ON_TRACK = "ON_TRACK"
    AT_RISK = "AT_RISK"
    BREACHED = "BREACHED"
    UNSCHEDULED = "UNSCHEDULED"


class DependencyType(str, Enum):
    """Kind of dependency edge between tasks."""

    BLOCKS = "BLOCKS"
    REQUIRES = "REQUIRES"
    RELATED = "RELATED"


# Task states from which no forward transition is expected
TERMINAL_TASK_STATES = frozenset(
    {
        RemediationTaskState.COMPLETED,
        RemediationTaskState.CANCELLED,
    }
)

# Task states blocking mutation of core fields
IMMUTABLE_TASK_STATES = frozenset(
    {
        RemediationTaskState.COMPLETED,
        RemediationTaskState.CANCELLED,
    }
)

# Plan states blocking mutation
IMMUTABLE_PLAN_STATES = frozenset(
    {
        RemediationPlanState.COMPLETED,
        RemediationPlanState.CANCELLED,
        RemediationPlanState.ARCHIVED,
    }
)


class RemediationAuthorityDomainError(Exception):
    """Base class for domain-level (non-schema) errors."""


class RemediationNotFoundDomainError(RemediationAuthorityDomainError):
    """Requested remediation entity not found for tenant."""


class RemediationTenantViolationDomainError(RemediationAuthorityDomainError):
    """Cross-tenant access attempt detected."""
