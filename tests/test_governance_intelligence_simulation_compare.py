"""Tests for PR 18.5A — Simulation Comparison Studio.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.simulation_compare import (
    _safe_float,
    compare_simulations,
    rank_simulations,
    validate_comparison_inputs,
)
from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASELINE = {
    "id": "sim-baseline",
    "governance_score": 0.7,
    "risk_score": 0.3,
    "compliance_score": 0.8,
    "workload": 0.4,
    "approval_rate": 0.85,
    "cost": 100.0,
    "automation_savings": 0.5,
}

_PROPOSED = {
    "id": "sim-proposed",
    "governance_score": 0.8,
    "risk_score": 0.2,
    "compliance_score": 0.85,
    "workload": 0.35,
    "approval_rate": 0.9,
    "cost": 90.0,
    "automation_savings": 0.55,
}


# ---------------------------------------------------------------------------
# validate_comparison_inputs
# ---------------------------------------------------------------------------


class TestValidateComparisonInputs:
    def test_valid_inputs_do_not_raise(self):
        validate_comparison_inputs(_BASELINE, _PROPOSED)

    def test_non_dict_baseline_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_comparison_inputs("not_a_dict", _PROPOSED)  # type: ignore[arg-type]

    def test_non_dict_proposed_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_comparison_inputs(_BASELINE, "not_a_dict")  # type: ignore[arg-type]

    def test_none_baseline_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_comparison_inputs(None, _PROPOSED)  # type: ignore[arg-type]

    def test_none_proposed_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_comparison_inputs(_BASELINE, None)  # type: ignore[arg-type]

    def test_empty_dicts_valid(self):
        validate_comparison_inputs({}, {})


# ---------------------------------------------------------------------------
# compare_simulations — invariants
# ---------------------------------------------------------------------------


class TestCompareSimulationsInvariants:
    def test_comparison_label(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert cmp["comparison_label"] == "DETERMINISTIC_COMPARISON"

    def test_is_production_false(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert cmp["is_production"] is False

    def test_comparison_label_with_minimal_inputs(self):
        cmp = compare_simulations({"id": "a"}, {"id": "b"})
        assert cmp["comparison_label"] == "DETERMINISTIC_COMPARISON"

    def test_is_production_false_with_minimal_inputs(self):
        cmp = compare_simulations({"id": "a"}, {"id": "b"})
        assert cmp["is_production"] is False


# ---------------------------------------------------------------------------
# compare_simulations — output structure
# ---------------------------------------------------------------------------


class TestCompareSimulationsOutput:
    def test_returns_dict(self):
        assert isinstance(compare_simulations(_BASELINE, _PROPOSED), dict)

    def test_has_baseline_id(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert cmp["baseline_id"] == "sim-baseline"

    def test_has_proposed_id(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert cmp["proposed_id"] == "sim-proposed"

    def test_has_risk_difference(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "risk_difference" in cmp

    def test_has_governance_difference(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "governance_difference" in cmp

    def test_has_compliance_difference(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "compliance_difference" in cmp

    def test_has_workload_difference(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "workload_difference" in cmp

    def test_has_approval_difference(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "approval_difference" in cmp

    def test_has_cost_difference(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "cost_difference" in cmp

    def test_has_automation_difference(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "automation_difference" in cmp

    def test_has_summary(self):
        cmp = compare_simulations(_BASELINE, _PROPOSED)
        assert "summary" in cmp
        assert isinstance(cmp["summary"], str)

    def test_governance_difference_correct(self):
        cmp = compare_simulations(
            {"id": "a", "governance_score": 0.7},
            {"id": "b", "governance_score": 0.8},
        )
        assert abs(cmp["governance_difference"] - 0.1) < 1e-4

    def test_risk_difference_correct(self):
        cmp = compare_simulations(
            {"id": "a", "risk_score": 0.3},
            {"id": "b", "risk_score": 0.2},
        )
        assert abs(cmp["risk_difference"] - (-0.1)) < 1e-4

    def test_cost_difference_negative_means_cheaper(self):
        cmp = compare_simulations(
            {"id": "a", "cost": 100.0},
            {"id": "b", "cost": 80.0},
        )
        assert cmp["cost_difference"] < 0

    def test_summary_mentions_improves_when_gov_diff_positive(self):
        cmp = compare_simulations(
            {"id": "a", "governance_score": 0.5},
            {"id": "b", "governance_score": 0.8},
        )
        assert "improves" in cmp["summary"]

    def test_summary_mentions_reduces_when_gov_diff_negative(self):
        cmp = compare_simulations(
            {"id": "a", "governance_score": 0.8},
            {"id": "b", "governance_score": 0.5},
        )
        assert "reduces" in cmp["summary"]

    def test_same_inputs_zero_governance_difference(self):
        cmp = compare_simulations(
            {"id": "a", "governance_score": 0.7},
            {"id": "b", "governance_score": 0.7},
        )
        assert cmp["governance_difference"] == 0.0

    def test_counterfactual_projected_keys_used_as_fallback(self):
        b = {"id": "a", "projected_governance_delta": -0.1}
        p = {"id": "b", "projected_governance_delta": 0.05}
        cmp = compare_simulations(b, p)
        assert cmp["comparison_label"] == "DETERMINISTIC_COMPARISON"

    def test_id_falls_back_to_name(self):
        cmp = compare_simulations({"name": "base"}, {"name": "prop"})
        assert cmp["baseline_id"] == "base"
        assert cmp["proposed_id"] == "prop"


# ---------------------------------------------------------------------------
# rank_simulations
# ---------------------------------------------------------------------------


class TestRankSimulations:
    def test_returns_list(self):
        sims = [{"governance_score": 0.7}, {"governance_score": 0.9}]
        assert isinstance(rank_simulations(sims, "governance_score"), list)

    def test_sorted_descending(self):
        sims = [
            {"id": "c", "governance_score": 0.3},
            {"id": "a", "governance_score": 0.9},
            {"id": "b", "governance_score": 0.6},
        ]
        ranked = rank_simulations(sims, "governance_score")
        scores = [s["governance_score"] for s in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_empty_list_returns_empty(self):
        assert rank_simulations([], "governance_score") == []

    def test_single_item_unchanged(self):
        sims = [{"governance_score": 0.8}]
        assert rank_simulations(sims, "governance_score") == sims

    def test_missing_key_treated_as_zero(self):
        sims = [
            {"id": "a", "governance_score": 0.8},
            {"id": "b"},  # missing key
        ]
        ranked = rank_simulations(sims, "governance_score")
        assert ranked[0]["id"] == "a"

    def test_rank_by_risk_score_descending(self):
        sims = [
            {"id": "a", "risk_score": 0.1},
            {"id": "b", "risk_score": 0.9},
        ]
        ranked = rank_simulations(sims, "risk_score")
        assert ranked[0]["id"] == "b"

    def test_tie_preserved_stably(self):
        sims = [
            {"id": "a", "governance_score": 0.7},
            {"id": "b", "governance_score": 0.7},
        ]
        ranked = rank_simulations(sims, "governance_score")
        assert len(ranked) == 2


# ---------------------------------------------------------------------------
# _safe_float helper
# ---------------------------------------------------------------------------


class TestSafeFloat:
    def test_numeric_value_returned(self):
        assert _safe_float({"k": 0.5}, "k") == 0.5

    def test_missing_key_returns_default(self):
        assert _safe_float({}, "k", 0.99) == 0.99

    def test_string_value_returns_default(self):
        assert _safe_float({"k": "bad"}, "k", 0.0) == 0.0

    def test_none_value_returns_default(self):
        assert _safe_float({"k": None}, "k", 0.0) == 0.0

    def test_int_value_converted_to_float(self):
        assert _safe_float({"k": 1}, "k") == 1.0
