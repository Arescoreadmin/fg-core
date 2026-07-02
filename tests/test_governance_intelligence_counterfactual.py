"""Tests for PR 18.5A — Counterfactual Governance Engine.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.counterfactual import (
    SUPPORTED_SCENARIOS,
    compare_counterfactuals,
    run_counterfactual,
    validate_counterfactual,
)
from services.governance_intelligence.schemas import (
    GovernanceIntelligenceSimulationError,
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASELINE = {
    "governance_score": 0.8,
    "risk_score": 0.2,
    "remediation_load": 0.3,
    "verification_load": 0.4,
    "compliance_score": 0.75,
    "automation_savings": 0.5,
    "sla_health": 0.9,
}


def _run(
    scenario: str, baseline: dict | None = None, params: dict | None = None
) -> dict:
    return run_counterfactual(scenario, baseline or _BASELINE, params or {})


# ---------------------------------------------------------------------------
# SUPPORTED_SCENARIOS
# ---------------------------------------------------------------------------


class TestSupportedScenarios:
    def test_is_frozenset(self):
        assert isinstance(SUPPORTED_SCENARIOS, frozenset)

    def test_has_9_scenarios(self):
        assert len(SUPPORTED_SCENARIOS) == 9

    def test_contains_policy_rollback(self):
        assert "POLICY_ROLLBACK" in SUPPORTED_SCENARIOS

    def test_contains_remediation_delay(self):
        assert "REMEDIATION_DELAY" in SUPPORTED_SCENARIOS

    def test_contains_approval_failure(self):
        assert "APPROVAL_FAILURE" in SUPPORTED_SCENARIOS

    def test_contains_evidence_expiry(self):
        assert "EVIDENCE_EXPIRY" in SUPPORTED_SCENARIOS

    def test_contains_verification_success(self):
        assert "VERIFICATION_SUCCESS" in SUPPORTED_SCENARIOS

    def test_contains_verification_failure(self):
        assert "VERIFICATION_FAILURE" in SUPPORTED_SCENARIOS

    def test_contains_trust_rotation(self):
        assert "TRUST_ROTATION" in SUPPORTED_SCENARIOS

    def test_contains_confidence_threshold_change(self):
        assert "CONFIDENCE_THRESHOLD_CHANGE" in SUPPORTED_SCENARIOS

    def test_contains_benchmark_cohort_change(self):
        assert "BENCHMARK_COHORT_CHANGE" in SUPPORTED_SCENARIOS


# ---------------------------------------------------------------------------
# validate_counterfactual
# ---------------------------------------------------------------------------


class TestValidateCounterfactual:
    def test_valid_scenario_does_not_raise(self):
        validate_counterfactual("POLICY_ROLLBACK", {})

    def test_invalid_scenario_raises_simulation_error(self):
        with pytest.raises(GovernanceIntelligenceSimulationError):
            validate_counterfactual("UNKNOWN_SCENARIO", {})

    def test_non_dict_parameters_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_counterfactual("POLICY_ROLLBACK", "bad")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# result_label and is_production invariants
# ---------------------------------------------------------------------------


class TestResultLabelInvariants:
    def test_policy_rollback_result_label(self):
        r = _run("POLICY_ROLLBACK")
        assert r["result_label"] == "PROJECTED"

    def test_policy_rollback_is_production_false(self):
        r = _run("POLICY_ROLLBACK")
        assert r["is_production"] is False

    def test_remediation_delay_result_label(self):
        r = _run("REMEDIATION_DELAY")
        assert r["result_label"] == "PROJECTED"

    def test_remediation_delay_is_production_false(self):
        r = _run("REMEDIATION_DELAY")
        assert r["is_production"] is False

    def test_approval_failure_result_label(self):
        r = _run("APPROVAL_FAILURE")
        assert r["result_label"] == "PROJECTED"

    def test_approval_failure_is_production_false(self):
        r = _run("APPROVAL_FAILURE")
        assert r["is_production"] is False

    def test_evidence_expiry_result_label(self):
        r = _run("EVIDENCE_EXPIRY")
        assert r["result_label"] == "PROJECTED"

    def test_evidence_expiry_is_production_false(self):
        r = _run("EVIDENCE_EXPIRY")
        assert r["is_production"] is False

    def test_verification_success_result_label(self):
        r = _run("VERIFICATION_SUCCESS")
        assert r["result_label"] == "PROJECTED"

    def test_verification_success_is_production_false(self):
        r = _run("VERIFICATION_SUCCESS")
        assert r["is_production"] is False

    def test_verification_failure_result_label(self):
        r = _run("VERIFICATION_FAILURE")
        assert r["result_label"] == "PROJECTED"

    def test_verification_failure_is_production_false(self):
        r = _run("VERIFICATION_FAILURE")
        assert r["is_production"] is False

    def test_trust_rotation_result_label(self):
        r = _run("TRUST_ROTATION")
        assert r["result_label"] == "PROJECTED"

    def test_trust_rotation_is_production_false(self):
        r = _run("TRUST_ROTATION")
        assert r["is_production"] is False

    def test_confidence_threshold_change_result_label(self):
        r = _run("CONFIDENCE_THRESHOLD_CHANGE")
        assert r["result_label"] == "PROJECTED"

    def test_confidence_threshold_change_is_production_false(self):
        r = _run("CONFIDENCE_THRESHOLD_CHANGE")
        assert r["is_production"] is False

    def test_benchmark_cohort_change_result_label(self):
        r = _run("BENCHMARK_COHORT_CHANGE")
        assert r["result_label"] == "PROJECTED"

    def test_benchmark_cohort_change_is_production_false(self):
        r = _run("BENCHMARK_COHORT_CHANGE")
        assert r["is_production"] is False


# ---------------------------------------------------------------------------
# Scenario output structure
# ---------------------------------------------------------------------------


class TestScenarioOutputStructure:
    def test_policy_rollback_has_projected_score(self):
        r = _run("POLICY_ROLLBACK")
        assert "projected_score" in r

    def test_policy_rollback_has_projected_risk(self):
        r = _run("POLICY_ROLLBACK")
        assert "projected_risk" in r

    def test_policy_rollback_scenario_field(self):
        r = _run("POLICY_ROLLBACK")
        assert r["scenario"] == "POLICY_ROLLBACK"

    def test_policy_rollback_baseline_score(self):
        r = _run("POLICY_ROLLBACK", {"governance_score": 0.7})
        assert abs(r["baseline_score"] - 0.7) < 1e-4

    def test_policy_rollback_score_clamped_to_0_1(self):
        r = _run(
            "POLICY_ROLLBACK", {"governance_score": 0.0}, {"rollback_severity": 1.0}
        )
        assert 0.0 <= r["projected_score"] <= 1.0

    def test_verification_success_score_increases(self):
        r = _run(
            "VERIFICATION_SUCCESS", {"governance_score": 0.5}, {"coverage_gain": 0.3}
        )
        assert r["projected_score"] >= 0.5

    def test_evidence_expiry_score_decreases(self):
        r = _run("EVIDENCE_EXPIRY", {"governance_score": 0.8}, {"expiry_fraction": 0.5})
        assert r["projected_score"] <= 0.8

    def test_remediation_delay_positive_delay(self):
        r = _run("REMEDIATION_DELAY", {"governance_score": 0.9}, {"delay_days": 90})
        assert r["projected_score"] <= 0.9

    def test_all_projected_scores_in_range(self):
        for scenario in SUPPORTED_SCENARIOS:
            r = _run(scenario)
            assert 0.0 <= r["projected_score"] <= 1.0, f"{scenario} score out of range"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestCounterfactualEdgeCases:
    def test_empty_baseline(self):
        r = run_counterfactual("POLICY_ROLLBACK", {}, {})
        assert r["result_label"] == "PROJECTED"
        assert r["is_production"] is False

    def test_extra_parameters_ignored(self):
        r = run_counterfactual("TRUST_ROTATION", {}, {"unknown_param": 999})
        assert r["result_label"] == "PROJECTED"

    def test_invalid_scenario_raises(self):
        with pytest.raises(GovernanceIntelligenceSimulationError):
            run_counterfactual("NONEXISTENT", {}, {})

    def test_benchmark_cohort_zero_delta(self):
        r = _run("BENCHMARK_COHORT_CHANGE", {}, {"cohort_size_delta": 0})
        assert r["result_label"] == "PROJECTED"

    def test_benchmark_cohort_large_negative(self):
        r = _run(
            "BENCHMARK_COHORT_CHANGE",
            {"governance_score": 0.8},
            {"cohort_size_delta": -500},
        )
        assert 0.0 <= r["projected_score"] <= 1.0

    def test_confidence_threshold_positive_delta(self):
        r = _run(
            "CONFIDENCE_THRESHOLD_CHANGE",
            {"governance_score": 0.8},
            {"threshold_delta": 0.2},
        )
        assert r["result_label"] == "PROJECTED"

    def test_confidence_threshold_negative_delta(self):
        r = _run(
            "CONFIDENCE_THRESHOLD_CHANGE",
            {"governance_score": 0.8},
            {"threshold_delta": -0.2},
        )
        assert r["result_label"] == "PROJECTED"


# ---------------------------------------------------------------------------
# compare_counterfactuals
# ---------------------------------------------------------------------------


class TestCompareCounterfactuals:
    def test_empty_list_returns_zero_count(self):
        result = compare_counterfactuals([])
        assert result["count"] == 0

    def test_empty_list_ranked_empty(self):
        result = compare_counterfactuals([])
        assert result["ranked"] == []

    def test_empty_best_scenario_none(self):
        result = compare_counterfactuals([])
        assert result["best_scenario"] is None

    def test_empty_worst_scenario_none(self):
        result = compare_counterfactuals([])
        assert result["worst_scenario"] is None

    def test_single_result_count_one(self):
        r = _run("POLICY_ROLLBACK")
        result = compare_counterfactuals([r])
        assert result["count"] == 1

    def test_multiple_results_sorted_by_score(self):
        r1 = _run(
            "VERIFICATION_SUCCESS", {"governance_score": 0.9}, {"coverage_gain": 0.05}
        )
        r2 = _run(
            "EVIDENCE_EXPIRY", {"governance_score": 0.5}, {"expiry_fraction": 0.5}
        )
        result = compare_counterfactuals([r2, r1])
        ranked = result["ranked"]
        assert ranked[0]["projected_score"] >= ranked[-1]["projected_score"]

    def test_best_scenario_highest_score(self):
        r1 = _run(
            "VERIFICATION_SUCCESS", {"governance_score": 0.9}, {"coverage_gain": 0.1}
        )
        r2 = _run(
            "EVIDENCE_EXPIRY", {"governance_score": 0.1}, {"expiry_fraction": 0.9}
        )
        result = compare_counterfactuals([r1, r2])
        assert result["best_scenario"] is not None

    def test_all_scenarios_compared(self):
        results = [_run(s) for s in sorted(SUPPORTED_SCENARIOS)]
        result = compare_counterfactuals(results)
        assert result["count"] == len(SUPPORTED_SCENARIOS)
