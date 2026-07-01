"""Deterministic state machine for remediation tasks and plans.

VALID_TRANSITIONS maps every task state to the set of task states it may
transition to. Any attempt to move outside the allowed set raises ValueError.

The state machine is pure — no I/O, no side effects, no globals.
"""

from __future__ import annotations

from typing import FrozenSet

from services.remediation_authority.models import (
    IMMUTABLE_PLAN_STATES,
    IMMUTABLE_TASK_STATES,
    RemediationPlanState,
    RemediationTaskState,
)


VALID_TRANSITIONS: dict[RemediationTaskState, FrozenSet[RemediationTaskState]] = {
    RemediationTaskState.OPEN: frozenset(
        {
            RemediationTaskState.ASSIGNED,
            RemediationTaskState.IN_PROGRESS,
            RemediationTaskState.BLOCKED,
            RemediationTaskState.CANCELLED,
        }
    ),
    RemediationTaskState.ASSIGNED: frozenset(
        {
            RemediationTaskState.IN_PROGRESS,
            RemediationTaskState.BLOCKED,
            RemediationTaskState.CANCELLED,
            RemediationTaskState.OPEN,
        }
    ),
    RemediationTaskState.IN_PROGRESS: frozenset(
        {
            RemediationTaskState.BLOCKED,
            RemediationTaskState.READY_FOR_REVIEW,
            RemediationTaskState.CANCELLED,
            RemediationTaskState.ASSIGNED,
        }
    ),
    RemediationTaskState.BLOCKED: frozenset(
        {
            RemediationTaskState.IN_PROGRESS,
            RemediationTaskState.ASSIGNED,
            RemediationTaskState.CANCELLED,
        }
    ),
    RemediationTaskState.READY_FOR_REVIEW: frozenset(
        {
            RemediationTaskState.VERIFYING,
            RemediationTaskState.IN_PROGRESS,
            RemediationTaskState.CANCELLED,
        }
    ),
    RemediationTaskState.VERIFYING: frozenset(
        {
            RemediationTaskState.APPROVED,
            RemediationTaskState.IN_PROGRESS,
            RemediationTaskState.CANCELLED,
        }
    ),
    RemediationTaskState.APPROVED: frozenset(
        {
            RemediationTaskState.COMPLETED,
            RemediationTaskState.REOPENED,
        }
    ),
    RemediationTaskState.COMPLETED: frozenset(),
    RemediationTaskState.CANCELLED: frozenset(),
    RemediationTaskState.REOPENED: frozenset(
        {
            RemediationTaskState.OPEN,
            RemediationTaskState.IN_PROGRESS,
            RemediationTaskState.CANCELLED,
        }
    ),
}


VALID_PLAN_TRANSITIONS: dict[RemediationPlanState, FrozenSet[RemediationPlanState]] = {
    RemediationPlanState.DRAFT: frozenset(
        {
            RemediationPlanState.ACTIVE,
            RemediationPlanState.CANCELLED,
        }
    ),
    RemediationPlanState.ACTIVE: frozenset(
        {
            RemediationPlanState.ON_HOLD,
            RemediationPlanState.COMPLETED,
            RemediationPlanState.CANCELLED,
        }
    ),
    RemediationPlanState.ON_HOLD: frozenset(
        {
            RemediationPlanState.ACTIVE,
            RemediationPlanState.CANCELLED,
        }
    ),
    RemediationPlanState.COMPLETED: frozenset(
        {
            RemediationPlanState.ARCHIVED,
        }
    ),
    RemediationPlanState.CANCELLED: frozenset(
        {
            RemediationPlanState.ARCHIVED,
        }
    ),
    RemediationPlanState.ARCHIVED: frozenset(),
}


def validate_transition(
    from_state: RemediationTaskState,
    to_state: RemediationTaskState,
) -> None:
    """Raise ValueError if the transition is not permitted."""
    allowed = VALID_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        allowed_str = sorted(s.value for s in allowed) or ["none (terminal)"]
        raise ValueError(
            f"Invalid task transition: {from_state.value!r} -> {to_state.value!r}. "
            f"Allowed: {allowed_str}"
        )


def validate_plan_transition(
    from_state: RemediationPlanState,
    to_state: RemediationPlanState,
) -> None:
    """Raise ValueError if the plan transition is not permitted."""
    allowed = VALID_PLAN_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        allowed_str = sorted(s.value for s in allowed) or ["none (terminal)"]
        raise ValueError(
            f"Invalid plan transition: {from_state.value!r} -> {to_state.value!r}. "
            f"Allowed: {allowed_str}"
        )


def is_immutable_state(state: RemediationTaskState) -> bool:
    """Return True if the state blocks core-field mutation."""
    return state in IMMUTABLE_TASK_STATES


def is_immutable_plan_state(state: RemediationPlanState) -> bool:
    """Return True if the plan state blocks core-field mutation."""
    return state in IMMUTABLE_PLAN_STATES


def allowed_next_states(state: RemediationTaskState) -> list[str]:
    """Return the sorted list of allowed next states as strings."""
    return sorted(s.value for s in VALID_TRANSITIONS.get(state, frozenset()))
