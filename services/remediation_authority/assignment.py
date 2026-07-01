"""Assignment helpers for the Remediation Authority.

Pure Python helpers around AssignmentRole rules.
"""

from __future__ import annotations

from services.remediation_authority.models import AssignmentRole
from services.remediation_authority.schemas import RemediationAssignmentError


VALID_ROLES = frozenset(
    {
        AssignmentRole.OWNER.value,
        AssignmentRole.REVIEWER.value,
        AssignmentRole.APPROVER.value,
        AssignmentRole.CONTRIBUTOR.value,
    }
)


def normalize_role(role: str | AssignmentRole) -> str:
    """Return the canonical role string, raising if unknown."""
    if isinstance(role, AssignmentRole):
        return role.value
    if role not in VALID_ROLES:
        raise RemediationAssignmentError(f"unknown assignment role: {role!r}")
    return role


def is_reviewer(role: str | AssignmentRole) -> bool:
    """Return True if the role is REVIEWER."""
    return normalize_role(role) == AssignmentRole.REVIEWER.value


def is_owner(role: str | AssignmentRole) -> bool:
    """Return True if the role is OWNER."""
    return normalize_role(role) == AssignmentRole.OWNER.value


def is_approver(role: str | AssignmentRole) -> bool:
    """Return True if the role is APPROVER."""
    return normalize_role(role) == AssignmentRole.APPROVER.value


def validate_actor_id(actor_id: str) -> None:
    """Raise RemediationAssignmentError if actor_id is empty/whitespace."""
    if not isinstance(actor_id, str) or not actor_id.strip():
        raise RemediationAssignmentError("actor_id must be a non-empty string")
