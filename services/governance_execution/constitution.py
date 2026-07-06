"""Permanent governance execution rules — immutable by design."""

from __future__ import annotations


GOVERNANCE_EXECUTION_PERMANENT_RULES: tuple[str, ...] = (
    "digital_twin_immutable",
    "simulation_immutable",
    "execution_evidence_first",
    "approval_required",
    "authority_required",
    "replay_required",
    "rollback_required",
    "verification_required",
    "measurement_required",
    "fail_closed",
    "unknown_over_fabrication",
    "tenant_isolation",
    "version_everything",
    "deterministic_ordering",
    "no_autonomous_execution",
    "no_hidden_decisions",
    "no_ai_generated_governance",
)

GOVERNANCE_EXECUTION_CONSTITUTION_VERSION = "18.8.3"
