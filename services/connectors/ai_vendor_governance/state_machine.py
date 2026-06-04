"""Governance workflow state machine (PR 4).

Not standalone. This module is not standalone. It requires the fg-core API,
auth layer, and Postgres substrate.

Defines valid workflow state transitions for FaAiVendorGovernanceRecord.
All transition validation is deterministic — no external I/O, no LLM calls.

States:
  discovered        — tool found by PR1, no governance action yet
  needs_owner       — tool lacks both business_owner and technical_owner
  needs_review      — owner present, formal review not yet completed
  approved          — governance review completed, usage approved
  restricted        — usage permitted under specific conditions only
  rejected          — usage prohibited
  exception_granted — usage permitted despite policy gaps (time-limited)
  retired           — tool is no longer in use (terminal state)

Initial state rules (deterministic from PR3 evidence):
  both owners null/"Unknown"  → needs_owner
  at least one owner set      → needs_review
  default                     → discovered
"""

from __future__ import annotations

WORKFLOW_STATES: frozenset[str] = frozenset(
    {
        "discovered",
        "needs_owner",
        "needs_review",
        "approved",
        "restricted",
        "rejected",
        "exception_granted",
        "retired",
    }
)

# Append-only: do not remove or expand allowed targets without a PR
_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "discovered": frozenset({"needs_owner", "needs_review", "approved", "rejected"}),
    "needs_owner": frozenset({"needs_review", "rejected"}),
    "needs_review": frozenset(
        {"approved", "restricted", "rejected", "exception_granted"}
    ),
    "approved": frozenset({"needs_review", "restricted", "rejected", "retired"}),
    "restricted": frozenset({"needs_review", "approved", "rejected", "retired"}),
    "rejected": frozenset({"needs_review", "exception_granted"}),
    "exception_granted": frozenset({"approved", "needs_review", "rejected"}),
    "retired": frozenset(),  # terminal — no outbound transitions
}

TARGET_TYPES: frozenset[str] = frozenset(
    {
        "vendor",
        "ai_tool",
        "ai_agent",
        "autonomous_system",
        "agent_swarm",
        "decision_engine",
        "agi_provider",
    }
)

DECISION_TYPES: frozenset[str] = frozenset(
    {
        "approved",
        "restricted",
        "rejected",
        "exception_granted",
        "retired",
        "owner_assigned",
        "review_completed",
        "state_transition",
        "finding_acknowledged",
        "governance_initiated",
    }
)


def is_valid_transition(from_state: str, to_state: str) -> bool:
    """Return True if the from_state → to_state transition is permitted."""
    return to_state in _VALID_TRANSITIONS.get(from_state, frozenset())


def validate_transition(from_state: str, to_state: str) -> None:
    """Raise ValueError if the transition is not permitted.

    Callers (PATCH route, bridge) use this to fail-fast before any DB write.
    """
    if from_state not in WORKFLOW_STATES:
        raise ValueError(f"Unknown current state: {from_state!r}")
    if to_state not in WORKFLOW_STATES:
        raise ValueError(f"Unknown target state: {to_state!r}")
    if not is_valid_transition(from_state, to_state):
        allowed = sorted(_VALID_TRANSITIONS.get(from_state, frozenset()))
        raise ValueError(
            f"Transition {from_state!r} → {to_state!r} is not permitted. "
            f"Allowed from {from_state!r}: {allowed}"
        )


def determine_initial_state(
    business_owner: str | None, technical_owner: str | None
) -> str:
    """Determine the initial workflow_state deterministically from PR3 owner fields.

    PR3 defaults both owners to "Unknown" — treat null or "Unknown" as absent.
    """

    def _owner_set(v: str | None) -> bool:
        return v is not None and v.strip().lower() not in ("unknown", "")

    if _owner_set(business_owner) or _owner_set(technical_owner):
        return "needs_review"
    return "needs_owner"
