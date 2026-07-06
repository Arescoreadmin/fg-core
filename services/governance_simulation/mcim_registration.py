"""MCIM registration manifest source for Governance Simulation Engine artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

GOVERNANCE_SIMULATION_MCIM_VERSION = "MCIM-18.8.2-GOVERNANCE-SIMULATION"

_MCIM_REGISTRATION_SOURCE: dict[str, str] = {
    "scenario": "MCIM-18.8.2-SIM-SCENARIO",
    "overlay": "MCIM-18.8.2-SIM-OVERLAY",
    "impact_report": "MCIM-18.8.2-SIM-IMPACT-REPORT",
    "diff_report": "MCIM-18.8.2-SIM-DIFF-REPORT",
    "replay_package": "MCIM-18.8.2-SIM-REPLAY-PACKAGE",
    "simulation_manifest": "MCIM-18.8.2-SIM-MANIFEST",
    "simulation_validator": "MCIM-18.8.2-SIM-VALIDATOR",
    "simulation_fingerprint": "MCIM-18.8.2-SIM-FINGERPRINT",
    "simulation_category": "MCIM-18.8.2-SIM-CATEGORY",
    "simulation_run": "MCIM-18.8.2-SIM-RUN",
}

MCIM_REGISTRATION_SOURCE: Mapping[str, str] = MappingProxyType(
    _MCIM_REGISTRATION_SOURCE
)
