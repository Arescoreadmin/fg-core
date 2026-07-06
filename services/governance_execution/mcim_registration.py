"""MCIM registration for Governance Execution Engine objects."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

GOVERNANCE_EXECUTION_MCIM_VERSION = "MCIM-18.8.3-GOVERNANCE-EXECUTION"

_MCIM_REGISTRATION_SOURCE: dict[str, str] = {
    "execution_plan": "MCIM-18.8.3-EXEC-PLAN",
    "execution_run": "MCIM-18.8.3-EXEC-RUN",
    "execution_decision": "MCIM-18.8.3-EXEC-DECISION",
    "execution_verification": "MCIM-18.8.3-EXEC-VERIFICATION",
    "execution_measurement": "MCIM-18.8.3-EXEC-MEASUREMENT",
    "execution_replay": "MCIM-18.8.3-EXEC-REPLAY",
    "execution_manifest": "MCIM-18.8.3-EXEC-MANIFEST",
    "execution_approval": "MCIM-18.8.3-EXEC-APPROVAL",
    "execution_gate": "MCIM-18.8.3-EXEC-GATE",
    "execution_policy": "MCIM-18.8.3-EXEC-POLICY",
    "execution_authority": "MCIM-18.8.3-EXEC-AUTHORITY",
    "execution_rollback": "MCIM-18.8.3-EXEC-ROLLBACK",
    "execution_audit": "MCIM-18.8.3-EXEC-AUDIT",
}
MCIM_REGISTRATION_SOURCE: Mapping[str, str] = MappingProxyType(
    _MCIM_REGISTRATION_SOURCE
)
