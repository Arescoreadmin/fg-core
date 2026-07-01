"""Workflow helpers for the Remediation Authority.

Small pure functions layered over the state machine. Keeps the engine
thin and testable.
"""

from __future__ import annotations

from services.remediation_authority.models import RemediationTaskState
from services.remediation_authority.state_machine import (
    allowed_next_states,
    is_immutable_state,
    validate_transition,
)


def transition(
    from_state: RemediationTaskState,
    to_state: RemediationTaskState,
) -> RemediationTaskState:
    """Validate and return the new task state.

    Raises ValueError if the transition is not permitted.
    """
    validate_transition(from_state, to_state)
    return to_state


def can_mutate_task(state: RemediationTaskState) -> bool:
    """Return True if mutation of core fields is currently allowed."""
    return not is_immutable_state(state)


def next_states(state: RemediationTaskState) -> list[str]:
    """Return the allowed next states from ``state``."""
    return allowed_next_states(state)


def coerce_state(value: str) -> RemediationTaskState:
    """Convert a string to a RemediationTaskState, raising ValueError on invalid."""
    try:
        return RemediationTaskState(value)
    except ValueError as exc:
        raise ValueError(f"Unknown task state: {value!r}") from exc
