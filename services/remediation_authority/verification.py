"""Verification helpers for the Remediation Authority.

Determines whether a task closure is eligible for approval / requires
another review round. Pure Python only.
"""

from __future__ import annotations

from services.remediation_authority.models import (
    RemediationTaskState,
    RemediationVerificationState,
)
from services.remediation_authority.schemas import RemediationVerificationError


TERMINAL_VERIFICATION_STATES = frozenset(
    {
        RemediationVerificationState.APPROVED.value,
        RemediationVerificationState.REJECTED.value,
        RemediationVerificationState.EXPIRED.value,
    }
)


def is_terminal(state: str) -> bool:
    """Return True if the verification state is terminal."""
    return state in TERMINAL_VERIFICATION_STATES


def normalize_state(state: str) -> str:
    """Return the canonical state string, raising if unknown."""
    try:
        return RemediationVerificationState(state).value
    except ValueError as exc:
        raise RemediationVerificationError(
            f"Unknown verification state: {state!r}"
        ) from exc


def can_transition_task_to_verifying(task_state: str) -> bool:
    """Return True if the task can move to VERIFYING from its current state."""
    return task_state == RemediationTaskState.READY_FOR_REVIEW.value


def approval_completes_task(task_state: str, verification_state: str) -> bool:
    """Return True when an approval verification should close the task."""
    normalized = normalize_state(verification_state)
    return (
        task_state == RemediationTaskState.VERIFYING.value
        and normalized == RemediationVerificationState.APPROVED.value
    )
