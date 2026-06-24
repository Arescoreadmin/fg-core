"""services/verification_authority/models.py — Domain models for Verification Workflow Authority.

Pure Python. No I/O. No SQLAlchemy. No scoring logic.

All enums and state machines are defined here as the authoritative contract.
Changing a transition map or adding a state is a breaking change.

Design principles:
  - Fail-closed: unknown states or invalid transitions raise immediately.
  - Immutability: terminal states cannot transition out.
  - AGI-forward: actor_type supports human|service|agent|autonomous_system.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet


# ---------------------------------------------------------------------------
# Workflow State
# ---------------------------------------------------------------------------


class VerificationWorkflowState(str, Enum):
    """11-state verification workflow state machine."""

    REQUESTED = "REQUESTED"
    QUEUED = "QUEUED"
    ASSIGNED = "ASSIGNED"
    IN_REVIEW = "IN_REVIEW"
    PENDING_INFORMATION = "PENDING_INFORMATION"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ESCALATED = "ESCALATED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"


# Terminal states — no transitions out
TERMINAL_WORKFLOW_STATES: FrozenSet[VerificationWorkflowState] = frozenset(
    {
        VerificationWorkflowState.APPROVED,
        VerificationWorkflowState.REJECTED,
        VerificationWorkflowState.EXPIRED,
        VerificationWorkflowState.CANCELLED,
        VerificationWorkflowState.COMPLETED,
    }
)

# Authoritative transition map
VALID_WORKFLOW_TRANSITIONS: dict[
    VerificationWorkflowState, FrozenSet[VerificationWorkflowState]
] = {
    VerificationWorkflowState.REQUESTED: frozenset(
        {
            VerificationWorkflowState.QUEUED,
            VerificationWorkflowState.CANCELLED,
            VerificationWorkflowState.EXPIRED,
        }
    ),
    VerificationWorkflowState.QUEUED: frozenset(
        {
            VerificationWorkflowState.ASSIGNED,
            VerificationWorkflowState.CANCELLED,
            VerificationWorkflowState.EXPIRED,
        }
    ),
    VerificationWorkflowState.ASSIGNED: frozenset(
        {
            VerificationWorkflowState.IN_REVIEW,
            VerificationWorkflowState.CANCELLED,
            VerificationWorkflowState.EXPIRED,
        }
    ),
    VerificationWorkflowState.IN_REVIEW: frozenset(
        {
            VerificationWorkflowState.PENDING_INFORMATION,
            VerificationWorkflowState.APPROVED,
            VerificationWorkflowState.REJECTED,
            VerificationWorkflowState.ESCALATED,
            VerificationWorkflowState.CANCELLED,
            VerificationWorkflowState.EXPIRED,
        }
    ),
    VerificationWorkflowState.PENDING_INFORMATION: frozenset(
        {
            VerificationWorkflowState.IN_REVIEW,
            VerificationWorkflowState.CANCELLED,
            VerificationWorkflowState.EXPIRED,
        }
    ),
    VerificationWorkflowState.ESCALATED: frozenset(
        {
            VerificationWorkflowState.IN_REVIEW,
            VerificationWorkflowState.APPROVED,
            VerificationWorkflowState.REJECTED,
            VerificationWorkflowState.CANCELLED,
            VerificationWorkflowState.EXPIRED,
        }
    ),
    VerificationWorkflowState.APPROVED: frozenset(
        {
            VerificationWorkflowState.COMPLETED,
        }
    ),
    VerificationWorkflowState.REJECTED: frozenset(),  # terminal
    VerificationWorkflowState.EXPIRED: frozenset(),  # terminal
    VerificationWorkflowState.CANCELLED: frozenset(),  # terminal
    VerificationWorkflowState.COMPLETED: frozenset(),  # terminal
}


def validate_workflow_transition(from_state: str, to_state: str) -> None:
    """Raise ValueError if the workflow transition is not permitted."""
    try:
        from_enum = VerificationWorkflowState(from_state)
    except ValueError:
        raise ValueError(f"Unknown workflow state: {from_state!r}")
    try:
        to_enum = VerificationWorkflowState(to_state)
    except ValueError:
        raise ValueError(f"Unknown workflow state: {to_state!r}")

    allowed = VALID_WORKFLOW_TRANSITIONS.get(from_enum, frozenset())
    if to_enum not in allowed:
        allowed_str = sorted(s.value for s in allowed) or ["none (terminal)"]
        raise ValueError(
            f"Invalid workflow transition: {from_state!r} → {to_state!r}. "
            f"Allowed: {allowed_str}"
        )


# ---------------------------------------------------------------------------
# Assignee Type
# ---------------------------------------------------------------------------


class AssigneeType(str, Enum):
    ANALYST = "ANALYST"
    MANAGER = "MANAGER"
    DIRECTOR = "DIRECTOR"
    VP = "VP"
    EXECUTIVE = "EXECUTIVE"
    SYSTEM = "SYSTEM"
    EXTERNAL_AUDITOR = "EXTERNAL_AUDITOR"


# ---------------------------------------------------------------------------
# Escalation Type
# ---------------------------------------------------------------------------


class EscalationType(str, Enum):
    MANUAL = "MANUAL"
    AUTOMATIC = "AUTOMATIC"
    SLA = "SLA"
    REVIEW = "REVIEW"
    EXECUTIVE = "EXECUTIVE"


# ---------------------------------------------------------------------------
# Audit Event Types
# ---------------------------------------------------------------------------


class VerificationRequestAuditEventType(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    ASSIGNED = "ASSIGNED"
    REASSIGNED = "REASSIGNED"
    REVIEW_STARTED = "REVIEW_STARTED"
    INFORMATION_REQUESTED = "INFORMATION_REQUESTED"
    INFORMATION_PROVIDED = "INFORMATION_PROVIDED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ESCALATED = "ESCALATED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    SLA_SET = "SLA_SET"
    RESULT_RECORDED = "RESULT_RECORDED"


# ---------------------------------------------------------------------------
# SLA Status
# ---------------------------------------------------------------------------


class WorkflowSlaStatus(str, Enum):
    ON_TRACK = "ON_TRACK"
    DUE_SOON = "DUE_SOON"
    OVERDUE = "OVERDUE"
