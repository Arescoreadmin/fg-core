"""Policy lifecycle state machine for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from services.governance_intelligence.models import PolicyLifecycleState, MUTABLE_POLICY_STATES
from services.governance_intelligence.schemas import GovernanceIntelligencePolicyError


# Valid transitions for each PolicyLifecycleState
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    PolicyLifecycleState.DRAFT.value: frozenset(
        {PolicyLifecycleState.REVIEW.value, PolicyLifecycleState.ARCHIVED.value}
    ),
    PolicyLifecycleState.REVIEW.value: frozenset(
        {
            PolicyLifecycleState.APPROVED.value,
            PolicyLifecycleState.DRAFT.value,
            PolicyLifecycleState.ARCHIVED.value,
        }
    ),
    PolicyLifecycleState.APPROVED.value: frozenset(
        {PolicyLifecycleState.ACTIVE.value, PolicyLifecycleState.ARCHIVED.value}
    ),
    PolicyLifecycleState.ACTIVE.value: frozenset(
        {PolicyLifecycleState.DEPRECATED.value, PolicyLifecycleState.SUPERSEDED.value}
    ),
    PolicyLifecycleState.DEPRECATED.value: frozenset(
        {PolicyLifecycleState.ARCHIVED.value}
    ),
    PolicyLifecycleState.SUPERSEDED.value: frozenset(
        {PolicyLifecycleState.ARCHIVED.value}
    ),
    PolicyLifecycleState.ARCHIVED.value: frozenset(),  # terminal
}


def validate_transition(current_state: str, target_state: str) -> None:
    """Raise GovernanceIntelligencePolicyError if transition is invalid."""
    allowed = VALID_TRANSITIONS.get(current_state)
    if allowed is None:
        raise GovernanceIntelligencePolicyError(
            f"Unknown policy lifecycle state: '{current_state}'"
        )
    if target_state not in allowed:
        raise GovernanceIntelligencePolicyError(
            f"Invalid policy state transition: '{current_state}' → '{target_state}'. "
            f"Allowed from '{current_state}': {sorted(allowed) or '(none — terminal state)'}"
        )


def is_mutable(lifecycle_state: str) -> bool:
    """Return True if the state allows editing (DRAFT or REVIEW)."""
    try:
        state = PolicyLifecycleState(lifecycle_state)
    except ValueError:
        return False
    return state in MUTABLE_POLICY_STATES
