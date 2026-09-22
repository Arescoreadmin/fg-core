"""Bounded Customer-Zero acceptance contracts and deterministic aggregation.

This module deliberately does not recalculate assessment truth.  It validates
the independently-authored corpus/expected-outcome contracts and aggregates
evidence emitted by the canonical FrostGate authorities.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

ACCEPTANCE_WORK_ITEM = "CUSTOMER-ZERO-ACCEPT-001"
ACCEPTANCE_SCHEMA_VERSION = "1.0"
_STATES = {"PASS", "FAIL", "NOT_PROVEN"}


class AcceptanceContractError(ValueError):
    """The immutable acceptance contract is malformed or inconsistent."""


def canonical_fingerprint(value: Mapping[str, Any]) -> str:
    """Fingerprint canonical JSON without the self-referential fingerprint."""
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def _without_fingerprint(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result.pop(field, None)
    return result


def validate_corpus(corpus: Mapping[str, Any]) -> str:
    required = (
        "corpus_id",
        "corpus_version",
        "schema_version",
        "synthetic",
        "scenarios",
    )
    if any(key not in corpus for key in required):
        raise AcceptanceContractError("CORPUS_SCHEMA_INVALID")
    if corpus["synthetic"] is not True:
        raise AcceptanceContractError("CORPUS_MUST_BE_SYNTHETIC")
    scenarios = corpus["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise AcceptanceContractError("CORPUS_SCENARIOS_MISSING")
    for scenario in scenarios:
        if not isinstance(scenario, Mapping) or not scenario.get("scenario_id"):
            raise AcceptanceContractError("CORPUS_SCENARIO_INVALID")
    expected = canonical_fingerprint(_without_fingerprint(corpus, "fingerprint"))
    if corpus.get("fingerprint") != expected:
        raise AcceptanceContractError("CORPUS_FINGERPRINT_MISMATCH")
    return expected


def validate_expected_outcomes(
    outcomes: Mapping[str, Any], corpus: Mapping[str, Any]
) -> str:
    required = (
        "expected_outcome_id",
        "expected_outcome_version",
        "schema_version",
        "assertions",
    )
    if any(key not in outcomes for key in required):
        raise AcceptanceContractError("EXPECTED_OUTCOME_SCHEMA_INVALID")
    if outcomes.get("corpus_id") != corpus.get("corpus_id") or outcomes.get(
        "corpus_version"
    ) != corpus.get("corpus_version"):
        raise AcceptanceContractError("EXPECTED_OUTCOME_CORPUS_MISMATCH")
    if outcomes.get("corpus_fingerprint") != corpus.get("fingerprint"):
        raise AcceptanceContractError("EXPECTED_OUTCOME_FINGERPRINT_MISMATCH")
    if not isinstance(outcomes["assertions"], list) or not outcomes["assertions"]:
        raise AcceptanceContractError("EXPECTED_OUTCOMES_MISSING")
    expected = canonical_fingerprint(_without_fingerprint(outcomes, "fingerprint"))
    if outcomes.get("fingerprint") != expected:
        raise AcceptanceContractError("EXPECTED_OUTCOME_FINGERPRINT_MISMATCH")
    return expected


def validate_approval(
    approval: Mapping[str, Any], corpus: Mapping[str, Any], outcomes: Mapping[str, Any]
) -> None:
    required = (
        "status",
        "corpus_id",
        "corpus_version",
        "corpus_fingerprint",
        "expected_outcome_id",
        "expected_outcome_version",
        "expected_outcome_fingerprint",
    )
    if any(key not in approval for key in required):
        raise AcceptanceContractError("APPROVAL_SCHEMA_INVALID")
    if approval.get("status") != "APPROVED":
        raise AcceptanceContractError("CORPUS_APPROVAL_PENDING")
    if (
        approval["corpus_id"] != corpus.get("corpus_id")
        or approval["corpus_version"] != corpus.get("corpus_version")
        or approval["corpus_fingerprint"] != corpus.get("fingerprint")
    ):
        raise AcceptanceContractError("APPROVED_CORPUS_BINDING_MISMATCH")
    if (
        approval["expected_outcome_id"] != outcomes.get("expected_outcome_id")
        or approval["expected_outcome_version"]
        != outcomes.get("expected_outcome_version")
        or approval["expected_outcome_fingerprint"] != outcomes.get("fingerprint")
    ):
        raise AcceptanceContractError("APPROVED_EXPECTED_OUTCOME_BINDING_MISMATCH")
    if (
        not approval.get("approver")
        or not approval.get("approved_at")
        or not approval.get("provenance")
    ):
        raise AcceptanceContractError("APPROVAL_PROVENANCE_MISSING")


@dataclass(frozen=True)
class AcceptanceDimension:
    state: str
    reason: str
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state not in _STATES:
            raise AcceptanceContractError("ACCEPTANCE_STATE_INVALID")

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "evidence": list(self.evidence),
        }


def aggregate_dimensions(dimensions: Mapping[str, AcceptanceDimension]) -> str:
    states = [dimension.state for dimension in dimensions.values()]
    if any(state == "FAIL" for state in states):
        return "FAIL"
    if any(state == "NOT_PROVEN" for state in states):
        return "NOT_PROVEN"
    return "PASS"


def build_acceptance_bundle(
    *,
    corpus: Mapping[str, Any],
    expected_outcomes: Mapping[str, Any],
    approval: Mapping[str, Any] | None,
    source_sha: str,
    dimensions: Mapping[str, AcceptanceDimension],
    acceptance_run_id: str,
    environment: str,
) -> dict[str, Any]:
    validate_corpus(corpus)
    validate_expected_outcomes(expected_outcomes, corpus)
    approval_dimension = dimensions.get("CORPUS_APPROVAL")
    if approval is not None:
        try:
            validate_approval(approval, corpus, expected_outcomes)
        except AcceptanceContractError as exc:
            if approval_dimension is None or approval_dimension.state == "PASS":
                raise
            approval_dimension = AcceptanceDimension(approval_dimension.state, str(exc))
    elif approval_dimension is None:
        approval_dimension = AcceptanceDimension(
            "NOT_PROVEN", "CORPUS_APPROVAL_MISSING"
        )
    if approval_dimension is None:
        approval_dimension = AcceptanceDimension(
            "NOT_PROVEN", "CORPUS_APPROVAL_MISSING"
        )
    all_dimensions = dict(dimensions)
    all_dimensions["CORPUS_APPROVAL"] = approval_dimension
    final_state = aggregate_dimensions(all_dimensions)
    return {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "work_item": ACCEPTANCE_WORK_ITEM,
        "acceptance_run_id": acceptance_run_id,
        "synthetic": True,
        "environment": environment,
        "corpus": {
            "id": corpus["corpus_id"],
            "version": corpus["corpus_version"],
            "fingerprint": corpus["fingerprint"],
        },
        "expected_outcomes": {
            "id": expected_outcomes["expected_outcome_id"],
            "version": expected_outcomes["expected_outcome_version"],
            "fingerprint": expected_outcomes["fingerprint"],
        },
        "approval": dict(approval) if approval is not None else None,
        "release": {"source_sha": source_sha},
        "dimensions": {
            name: dimension.to_dict()
            for name, dimension in sorted(all_dimensions.items())
        },
        "final_state": final_state,
        "final_reasons": [
            f"{name}:{dimension.reason}"
            for name, dimension in sorted(all_dimensions.items())
            if dimension.state != "PASS"
        ],
    }
