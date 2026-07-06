"""State machine and approval type registries for the Governance Execution Engine."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType


_STATE_TRANSITIONS_SOURCE: dict[str, frozenset[str]] = {
    "Draft": frozenset({"Validated"}),
    "Validated": frozenset({"AwaitingApproval", "Draft"}),
    "AwaitingApproval": frozenset({"Approved", "Validated"}),
    "Approved": frozenset({"Scheduled", "AwaitingApproval"}),
    "Scheduled": frozenset({"Executing", "Approved"}),
    "Executing": frozenset({"Verifying", "Failed", "Completed"}),
    "Verifying": frozenset({"Completed", "Failed"}),
    "Completed": frozenset({"Measured"}),
    "Measured": frozenset({"Archived"}),
    "Archived": frozenset(),
    "Failed": frozenset({"Rollback"}),
    "Rollback": frozenset({"Verification", "Closed"}),
    "Verification": frozenset({"Closed"}),
    "Closed": frozenset(),
}
EXECUTION_STATE_TRANSITIONS: Mapping[str, frozenset[str]] = MappingProxyType(
    _STATE_TRANSITIONS_SOURCE
)

_APPROVAL_TYPE_REGISTRY_SOURCE: dict[str, int] = {
    "SingleApprover": 1,
    "DualApproval": 2,
    "MajorityApproval": 3,
    "RiskBased": 1,
    "Emergency": 1,
    "Executive": 1,
    "Compliance": 1,
    "Security": 1,
    "Authority": 1,
}
APPROVAL_TYPE_REGISTRY: Mapping[str, int] = MappingProxyType(
    _APPROVAL_TYPE_REGISTRY_SOURCE
)

GOVERNANCE_GATES: tuple[str, ...] = (
    "simulation_passed",
    "validation_passed",
    "authority_verified",
    "evidence_present",
    "policy_allows_execution",
    "risk_threshold_satisfied",
    "required_approvals_complete",
    "replay_package_valid",
    "digital_twin_fingerprint_unchanged",
)


def is_valid_transition(from_state: str, to_state: str) -> bool:
    """Return True if transitioning from_state → to_state is valid."""
    return to_state in EXECUTION_STATE_TRANSITIONS.get(from_state, frozenset())


def get_required_approvers(approval_type: str) -> int:
    """Return minimum approver count for the given approval type."""
    return APPROVAL_TYPE_REGISTRY.get(approval_type, 1)
