"""MCIM adapter for Governance Digital Twin artifacts.

The shared MCIM registration manifest is the source of truth. The twin consumes that
registration; it does not invent a parallel runtime metadata authority.
"""

from __future__ import annotations

from collections.abc import Mapping

from services.governance_digital_twin.mcim_registration import (
    GOVERNANCE_DIGITAL_TWIN_MCIM_VERSION,
    MCIM_REGISTRATION_SOURCE,
)

MCIM_COMPONENT_REGISTRY: Mapping[str, str] = MCIM_REGISTRATION_SOURCE

__all__ = [
    "GOVERNANCE_DIGITAL_TWIN_MCIM_VERSION",
    "MCIM_COMPONENT_REGISTRY",
    "MCIM_REGISTRATION_SOURCE",
]
