"""Production qualification authority — pure validation logic (PROD-QUAL-001).

This module contains only stateless validation. DB writes and reads live in
api/field_assessment.py following the same pattern as _record_report_qa_decision.
"""

from __future__ import annotations

from typing import Mapping

PRODUCTION_GATES: tuple[str, ...] = (
    "PRODUCTION_DEPENDENCY_SECURITY",
    "PRODUCTION_SCHEMA_AND_RLS",
    "CANONICAL_ASSESSMENT_PROOF",
    "DURABLE_EXECUTION_AND_RECOVERY",
)

VALID_GATE_NAMES: frozenset[str] = frozenset(PRODUCTION_GATES)


def validate_gate_name(gate_name: str) -> list[str]:
    """Return error list if gate_name is not a recognized production gate."""
    if gate_name not in VALID_GATE_NAMES:
        return [
            f"unknown gate '{gate_name}'; recognized gates: {sorted(VALID_GATE_NAMES)}"
        ]
    return []


def check_finalization_readiness(
    attestations: Mapping[str, bool],
    truth_gate_decision: str,
) -> list[str]:
    """Validate that all conditions for a QUALIFIED decision are met.

    Returns a list of blocking reasons; empty list means QUALIFIED can be issued.

    Args:
        attestations: mapping of gate_name → attested bool for the current request
        truth_gate_decision: the decision string from report_json["result_truth_gate"]
    """
    reasons: list[str] = []

    if truth_gate_decision != "PASS":
        reasons.append(
            f"result_truth_gate decision is '{truth_gate_decision}'; PASS required"
        )

    for gate in PRODUCTION_GATES:
        if attestations.get(gate) is not True:
            reasons.append(f"gate '{gate}' not attested True")

    return reasons
