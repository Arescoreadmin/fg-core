"""FG_RESULT_TRUTH_GATE release-authority tests."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import copy

import pytest

from services.governance.report.result_truth_gate import (
    ResultTruthGateError,
    evaluate_result_truth_gate,
)


def _report(count: int = 2) -> dict[str, Any]:
    evidence = [
        {"evidence_id": f"ev-{i}", "provenance": "engagement:eng-1"}
        for i in range(count)
    ]
    finding = {
        "finding_id": "finding-1",
        "evidence_ids": ["ev-0"],
        "severity": "high",
    }
    claim = {
        "claim_id": "claim-1",
        "finding_id": "finding-1",
        "control_id": "security_posture",
        "domain": "security_posture",
        "severity": "high",
        "epistemic_state": "VERIFIED_DEFICIENT",
        "disposition": "verified_deficient",
        "evidence_ids": ["ev-0"],
        "tenant_id": "tenant-1",
        "engagement_id": "eng-1",
        "lineage": ["engagement:eng-1", "finding:finding-1", "evidence:ev-0"],
    }
    report = {
        "tenant_id": "tenant-1",
        "engagement_id": "eng-1",
        "assessment_id": "eng-1",
        "evidence_population": {
            "total_discovered": count,
            "eligible_count": count,
            "evaluated_count": count,
            "excluded_count": 0,
            "fingerprint": "population-hash",
        },
        "evidence_state_hash": "population-hash",
        "evidence_appendix": evidence,
        "findings": [finding],
        "epistemic_states": {"finding-1": {"state": "VERIFIED_DEFICIENT"}},
        "material_claims": [claim],
        "grounded_claims_fingerprint": "",
        "production_gates": {
            "PRODUCTION_DEPENDENCY_SECURITY": True,
            "PRODUCTION_SCHEMA_AND_RLS": True,
            "CANONICAL_ASSESSMENT_PROOF": True,
            "DURABLE_EXECUTION_AND_RECOVERY": True,
        },
        "normalized_findings": [finding],
        "canonical_posture": {"active_adverse_count": 1},
    }
    report["grounded_claims_fingerprint"] = hashlib.sha256(
        json.dumps(
            {"version": "1.0", "claims": [claim]}, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    return report


def test_valid_result_passes_and_replays() -> None:
    first = evaluate_result_truth_gate(
        _report(101), tenant_id="tenant-1", engagement_id="eng-1"
    )
    second = evaluate_result_truth_gate(
        _report(101), tenant_id="tenant-1", engagement_id="eng-1"
    )
    assert first.decision == "PASS"
    assert first.result_fingerprint == second.result_fingerprint


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (
            lambda r: r.update({"evidence_state_hash": "tampered"}),
            "EVIDENCE_FINGERPRINT_MISMATCH",
        ),
        (
            lambda r: r["material_claims"][0].update({"epistemic_state": "UNKNOWN"}),
            "UNKNOWN_EPISTEMIC_STATE",
        ),
        (
            lambda r: r["material_claims"][0].update({"finding_id": "other"}),
            "UNRESOLVED_CLAIM_FINDING_LINEAGE",
        ),
        (lambda r: r.update({"tenant_id": "other"}), "TENANT_SCOPE_MISMATCH"),
    ],
)
def test_invalid_canonical_inputs_fail_closed(mutation, reason: str) -> None:
    report = _report()
    mutation(report)
    with pytest.raises(ResultTruthGateError) as exc_info:
        evaluate_result_truth_gate(report, tenant_id="tenant-1", engagement_id="eng-1")
    assert reason in exc_info.value.reasons


def test_population_appendix_cannot_be_truncated() -> None:
    report = _report(101)
    report["evidence_appendix"] = report["evidence_appendix"][:100]
    with pytest.raises(ResultTruthGateError, match="EVIDENCE_APPENDIX_INCOMPLETE"):
        evaluate_result_truth_gate(report, tenant_id="tenant-1", engagement_id="eng-1")


def test_input_order_does_not_change_result() -> None:
    first = _report(3)
    second = copy.deepcopy(first)
    second["evidence_appendix"] = list(reversed(second["evidence_appendix"]))
    assert (
        evaluate_result_truth_gate(
            first, tenant_id="tenant-1", engagement_id="eng-1"
        ).result_fingerprint
        == evaluate_result_truth_gate(
            second, tenant_id="tenant-1", engagement_id="eng-1"
        ).result_fingerprint
    )


def test_production_gates_and_claim_fingerprint_are_required() -> None:
    report = _report()
    report["production_gates"] = {}
    with pytest.raises(ResultTruthGateError) as exc_info:
        evaluate_result_truth_gate(
            report,
            tenant_id="tenant-1",
            engagement_id="eng-1",
            require_production_gates=True,
        )
    assert (
        "PRODUCTION_GATE_NOT_PROVEN:PRODUCTION_SCHEMA_AND_RLS" in exc_info.value.reasons
    )


def test_suppressed_adverse_finding_fails_closed() -> None:
    report = _report()
    report["findings"] = []
    with pytest.raises(ResultTruthGateError, match="ADVERSE_FINDING_SUPPRESSED"):
        evaluate_result_truth_gate(report, tenant_id="tenant-1", engagement_id="eng-1")


def test_truth_passes_without_production_qualification() -> None:
    report = _report()
    report["production_gates"] = {}
    result = evaluate_result_truth_gate(
        report, tenant_id="tenant-1", engagement_id="eng-1"
    )
    assert result.decision == "PASS"


def test_requested_production_qualification_fails_closed() -> None:
    report = _report()
    report["production_gates"] = {}
    report["production_qualification_requested"] = True
    with pytest.raises(ResultTruthGateError, match="PRODUCTION_GATE_NOT_PROVEN"):
        evaluate_result_truth_gate(report, tenant_id="tenant-1", engagement_id="eng-1")


def test_empty_evidence_population_fails_closed() -> None:
    report = _report(0)
    report["findings"] = []
    report["normalized_findings"] = []
    report["material_claims"] = []
    report["grounded_claims_fingerprint"] = hashlib.sha256(
        json.dumps(
            {"version": "1.0", "claims": []},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with pytest.raises(ResultTruthGateError, match="EMPTY_EVIDENCE_POPULATION"):
        evaluate_result_truth_gate(report, tenant_id="tenant-1", engagement_id="eng-1")
