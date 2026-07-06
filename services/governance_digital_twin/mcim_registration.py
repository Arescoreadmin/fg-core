"""MCIM registration manifest source for Governance Digital Twin artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

GOVERNANCE_DIGITAL_TWIN_MCIM_VERSION = "MCIM-18.8.1-GOVERNANCE-DIGITAL-TWIN"

_MCIM_REGISTRATION_SOURCE = {
    "twin": "MCIM-18.8.1-GDT-TWIN",
    "snapshot": "MCIM-18.8.1-GDT-SNAPSHOT",
    "manifest": "MCIM-18.8.1-GDT-MANIFEST",
    "baseline": "MCIM-18.8.1-GDT-BASELINE",
    "authority_graph": "MCIM-18.8.1-GDT-AUTHORITY-GRAPH",
    "relationship_graph": "MCIM-18.8.1-GDT-RELATIONSHIP-GRAPH",
    "export": "MCIM-18.8.1-GDT-EXPORT",
    "validator": "MCIM-18.8.1-GDT-VALIDATOR",
}

MCIM_REGISTRATION_SOURCE: Mapping[str, str] = MappingProxyType(_MCIM_REGISTRATION_SOURCE)
