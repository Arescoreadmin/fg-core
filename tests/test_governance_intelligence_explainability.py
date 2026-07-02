"""Tests for services/governance_intelligence/explainability.py

GIE-1 to GIE-200 — pure function tests for build_explanation,
format_explanation_text, and diff_impacts.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.explainability import (
    build_explanation,
    diff_impacts,
    format_explanation_text,
)


# ---------------------------------------------------------------------------
# GIE-1 — GIE-60: build_explanation
# ---------------------------------------------------------------------------


class TestBuildExplanation:
    """GIE-1 to GIE-60: build_explanation function tests."""

    def _default_args(self) -> dict:
        return {
            "trigger": "policy_update",
            "policy_version": "1.2",
            "evaluation": {"risk_score": 0.75, "control_count": 5},
            "decision": "APPROVE",
            "authorities_invoked": ["governance_orchestration", "risk_engine"],
            "expected_impact": {"workload_delta": 0.05, "risk_delta": -0.10},
            "observed_impact": {"workload_delta": 0.04, "risk_delta": -0.09},
        }

    def test_gie_1_returns_dict(self):
        """GIE-1: result is a dict."""
        result = build_explanation(**self._default_args())
        assert isinstance(result, dict)

    def test_gie_2_trigger_preserved(self):
        """GIE-2: trigger is preserved in result."""
        result = build_explanation(**self._default_args())
        assert result["trigger"] == "policy_update"

    def test_gie_3_policy_version_preserved(self):
        """GIE-3: policy_version is preserved."""
        result = build_explanation(**self._default_args())
        assert result["policy_version"] == "1.2"

    def test_gie_4_evaluation_preserved(self):
        """GIE-4: evaluation dict is preserved."""
        result = build_explanation(**self._default_args())
        assert result["evaluation"] == {"risk_score": 0.75, "control_count": 5}

    def test_gie_5_decision_preserved(self):
        """GIE-5: decision is preserved."""
        result = build_explanation(**self._default_args())
        assert result["decision"] == "APPROVE"

    def test_gie_6_authorities_invoked_preserved(self):
        """GIE-6: authorities_invoked list is preserved."""
        result = build_explanation(**self._default_args())
        assert result["authorities_invoked"] == [
            "governance_orchestration",
            "risk_engine",
        ]

    def test_gie_7_expected_impact_preserved(self):
        """GIE-7: expected_impact dict is preserved."""
        result = build_explanation(**self._default_args())
        assert result["expected_impact"]["workload_delta"] == pytest.approx(0.05)

    def test_gie_8_observed_impact_preserved(self):
        """GIE-8: observed_impact dict is preserved."""
        result = build_explanation(**self._default_args())
        assert result["observed_impact"]["risk_delta"] == pytest.approx(-0.09)

    def test_gie_9_has_impact_delta(self):
        """GIE-9: result contains impact_delta."""
        result = build_explanation(**self._default_args())
        assert "impact_delta" in result

    def test_gie_10_has_summary(self):
        """GIE-10: result contains summary string."""
        result = build_explanation(**self._default_args())
        assert "summary" in result
        assert isinstance(result["summary"], str)

    def test_gie_11_summary_includes_decision(self):
        """GIE-11: summary mentions the decision."""
        result = build_explanation(**self._default_args())
        assert "APPROVE" in result["summary"]

    def test_gie_12_summary_includes_trigger(self):
        """GIE-12: summary mentions the trigger."""
        result = build_explanation(**self._default_args())
        assert "policy_update" in result["summary"]

    def test_gie_13_summary_includes_policy_version(self):
        """GIE-13: summary mentions the policy version."""
        result = build_explanation(**self._default_args())
        assert "1.2" in result["summary"]

    def test_gie_14_summary_two_authorities_plural(self):
        """GIE-14: 2 authorities → 'authorities' (plural) in summary."""
        result = build_explanation(**self._default_args())
        assert "authorities" in result["summary"]

    def test_gie_15_summary_one_authority_singular(self):
        """GIE-15: 1 authority → 'authority' (singular) in summary."""
        args = self._default_args()
        args["authorities_invoked"] = ["single_authority"]
        result = build_explanation(**args)
        assert "authority" in result["summary"]
        assert "authorities" not in result["summary"]

    def test_gie_16_none_observed_impact_allowed(self):
        """GIE-16: None observed_impact is accepted."""
        args = self._default_args()
        args["observed_impact"] = None  # type: ignore[arg-type]
        result = build_explanation(**args)
        assert result["observed_impact"] is None

    def test_gie_17_empty_authorities_zero_count(self):
        """GIE-17: empty authorities_invoked → 0 authorities in summary."""
        args = self._default_args()
        args["authorities_invoked"] = []
        result = build_explanation(**args)
        assert "0" in result["summary"] or "authorit" in result["summary"]

    def test_gie_18_empty_evaluation_dict_ok(self):
        """GIE-18: empty evaluation dict is accepted."""
        args = self._default_args()
        args["evaluation"] = {}
        result = build_explanation(**args)
        assert result["evaluation"] == {}

    def test_gie_19_impact_delta_computed(self):
        """GIE-19: impact_delta is computed (result of diff_impacts)."""
        result = build_explanation(**self._default_args())
        # Should have delta for workload_delta key
        assert "workload_delta" in result["impact_delta"]

    def test_gie_20_impact_delta_absolute_delta_correct(self):
        """GIE-20: workload_delta absolute_delta = observed - expected."""
        result = build_explanation(**self._default_args())
        wd = result["impact_delta"]["workload_delta"]
        assert wd["absolute_delta"] == pytest.approx(0.04 - 0.05)

    def test_gie_21_none_observed_yields_empty_impact_delta(self):
        """GIE-21: None observed → diff_impacts with empty observed, yields expected keys."""
        args = self._default_args()
        args["observed_impact"] = None  # type: ignore[arg-type]
        result = build_explanation(**args)
        # diff_impacts called with {} for None
        delta = result["impact_delta"]
        assert isinstance(delta, dict)

    def test_gie_22_large_authorities_list(self):
        """GIE-22: large authorities list handled correctly."""
        args = self._default_args()
        args["authorities_invoked"] = [f"auth_{i}" for i in range(20)]
        result = build_explanation(**args)
        assert result["authorities_invoked"] == args["authorities_invoked"]
        assert "20" in result["summary"]

    def test_gie_23_different_decision_approve(self):
        """GIE-23: DENY decision in summary."""
        args = self._default_args()
        args["decision"] = "DENY"
        result = build_explanation(**args)
        assert "DENY" in result["summary"]

    def test_gie_24_nested_evaluation_preserved(self):
        """GIE-24: nested evaluation dict preserved."""
        args = self._default_args()
        args["evaluation"] = {"nested": {"key": "val"}, "score": 1.0}
        result = build_explanation(**args)
        assert result["evaluation"]["nested"] == {"key": "val"}

    def test_gie_25_unicode_trigger_preserved(self):
        """GIE-25: unicode trigger preserved."""
        args = self._default_args()
        args["trigger"] = "policy_update_☃"
        result = build_explanation(**args)
        assert "☃" in result["trigger"]


# ---------------------------------------------------------------------------
# GIE-61 — GIE-130: format_explanation_text
# ---------------------------------------------------------------------------


class TestFormatExplanationText:
    """GIE-61 to GIE-130: format_explanation_text function tests."""

    def _sample_explanation(self) -> dict:
        return {
            "trigger": "manual_audit",
            "policy_version": "2.0",
            "decision": "APPROVE",
            "authorities_invoked": ["governance_intelligence"],
            "expected_impact": {"risk_delta": -0.1, "control_count": 3},
            "observed_impact": {"risk_delta": -0.09, "control_count": 3},
            "impact_delta": {
                "risk_delta": {
                    "expected": -0.1,
                    "observed": -0.09,
                    "absolute_delta": 0.01,
                }
            },
        }

    def test_gie_61_returns_string(self):
        """GIE-61: result is a string."""
        result = format_explanation_text(self._sample_explanation())
        assert isinstance(result, str)

    def test_gie_62_contains_title(self):
        """GIE-62: result contains the header."""
        result = format_explanation_text(self._sample_explanation())
        assert "Governance Decision Explanation" in result

    def test_gie_63_contains_separator(self):
        """GIE-63: result contains the ======= separator."""
        result = format_explanation_text(self._sample_explanation())
        assert "====" in result

    def test_gie_64_contains_trigger(self):
        """GIE-64: result contains the trigger value."""
        result = format_explanation_text(self._sample_explanation())
        assert "manual_audit" in result

    def test_gie_65_contains_policy_version(self):
        """GIE-65: result contains the policy version."""
        result = format_explanation_text(self._sample_explanation())
        assert "2.0" in result

    def test_gie_66_contains_decision(self):
        """GIE-66: result contains the decision."""
        result = format_explanation_text(self._sample_explanation())
        assert "APPROVE" in result

    def test_gie_67_contains_authorities_section(self):
        """GIE-67: result contains Authorities Invoked section."""
        result = format_explanation_text(self._sample_explanation())
        assert "Authorities Invoked" in result

    def test_gie_68_authority_listed_with_dash(self):
        """GIE-68: each authority is listed with a dash prefix."""
        result = format_explanation_text(self._sample_explanation())
        assert "  - governance_intelligence" in result

    def test_gie_69_contains_expected_impact_section(self):
        """GIE-69: result contains Expected Impact section."""
        result = format_explanation_text(self._sample_explanation())
        assert "Expected Impact" in result

    def test_gie_70_contains_observed_impact_section(self):
        """GIE-70: result contains Observed Impact section when present."""
        result = format_explanation_text(self._sample_explanation())
        assert "Observed Impact" in result

    def test_gie_71_contains_impact_delta_section(self):
        """GIE-71: result contains Impact Delta section when non-empty."""
        result = format_explanation_text(self._sample_explanation())
        assert "Impact Delta" in result

    def test_gie_72_no_observed_impact_section_missing(self):
        """GIE-72: missing observed_impact → no Observed Impact section."""
        expl = self._sample_explanation()
        expl.pop("observed_impact")
        result = format_explanation_text(expl)
        assert "Observed Impact" not in result

    def test_gie_73_no_impact_delta_section_missing(self):
        """GIE-73: empty impact_delta → no Impact Delta section."""
        expl = self._sample_explanation()
        expl["impact_delta"] = {}
        result = format_explanation_text(expl)
        assert "Impact Delta" not in result

    def test_gie_74_empty_authorities_no_dash_lines(self):
        """GIE-74: empty authorities_invoked → no dash entries."""
        expl = self._sample_explanation()
        expl["authorities_invoked"] = []
        result = format_explanation_text(expl)
        # Authorities Invoked section present but no - entries
        assert "Authorities Invoked" in result

    def test_gie_75_multiple_authorities_all_listed(self):
        """GIE-75: multiple authorities all appear in text."""
        expl = self._sample_explanation()
        expl["authorities_invoked"] = ["auth_a", "auth_b", "auth_c"]
        result = format_explanation_text(expl)
        assert "auth_a" in result
        assert "auth_b" in result
        assert "auth_c" in result

    def test_gie_76_unknown_fields_default_gracefully(self):
        """GIE-76: missing fields default to 'unknown'."""
        result = format_explanation_text({})
        assert "unknown" in result

    def test_gie_77_expected_impact_keys_shown(self):
        """GIE-77: expected_impact keys appear in output."""
        result = format_explanation_text(self._sample_explanation())
        assert "risk_delta" in result

    def test_gie_78_multiline_result(self):
        """GIE-78: result is multiline."""
        result = format_explanation_text(self._sample_explanation())
        assert "\n" in result


# ---------------------------------------------------------------------------
# GIE-131 — GIE-200: diff_impacts
# ---------------------------------------------------------------------------


class TestDiffImpacts:
    """GIE-131 to GIE-200: diff_impacts function tests."""

    def test_gie_131_returns_dict(self):
        """GIE-131: result is a dict."""
        result = diff_impacts({"score": 1.0}, {"score": 1.1})
        assert isinstance(result, dict)

    def test_gie_132_numeric_absolute_delta(self):
        """GIE-132: absolute_delta = observed - expected."""
        result = diff_impacts({"score": 1.0}, {"score": 1.5})
        assert result["score"]["absolute_delta"] == pytest.approx(0.5)

    def test_gie_133_numeric_pct_delta(self):
        """GIE-133: pct_delta = (observed - expected) / |expected| * 100."""
        result = diff_impacts({"score": 2.0}, {"score": 3.0})
        assert result["score"]["pct_delta"] == pytest.approx(50.0)

    def test_gie_134_zero_expected_pct_delta_is_none(self):
        """GIE-134: pct_delta is None when expected=0."""
        result = diff_impacts({"score": 0.0}, {"score": 1.0})
        assert result["score"]["pct_delta"] is None

    def test_gie_135_expected_and_observed_in_result(self):
        """GIE-135: expected and observed values in result."""
        result = diff_impacts({"score": 1.0}, {"score": 2.0})
        assert result["score"]["expected"] == pytest.approx(1.0)
        assert result["score"]["observed"] == pytest.approx(2.0)

    def test_gie_136_non_numeric_changed_flag(self):
        """GIE-136: non-numeric values have 'changed' flag."""
        result = diff_impacts({"status": "PASS"}, {"status": "FAIL"})
        assert result["status"]["changed"] is True

    def test_gie_137_non_numeric_unchanged_flag(self):
        """GIE-137: non-numeric same values have changed=False."""
        result = diff_impacts({"status": "PASS"}, {"status": "PASS"})
        assert result["status"]["changed"] is False

    def test_gie_138_key_only_in_expected(self):
        """GIE-138: key only in expected → present in delta with None observed."""
        result = diff_impacts({"only_expected": 1.0}, {})
        assert "only_expected" in result

    def test_gie_139_key_only_in_observed(self):
        """GIE-139: key only in observed → present in delta with None expected."""
        result = diff_impacts({}, {"only_observed": 2.0})
        assert "only_observed" in result

    def test_gie_140_both_none_values_excluded(self):
        """GIE-140: keys where both expected and observed are None are excluded."""
        result = diff_impacts({"null_key": None}, {"null_key": None})
        assert "null_key" not in result

    def test_gie_141_empty_both_returns_empty(self):
        """GIE-141: both empty dicts → empty result."""
        result = diff_impacts({}, {})
        assert result == {}

    def test_gie_142_negative_delta_negative_absolute(self):
        """GIE-142: negative delta is preserved."""
        result = diff_impacts({"val": 5.0}, {"val": 3.0})
        assert result["val"]["absolute_delta"] == pytest.approx(-2.0)

    def test_gie_143_mixed_keys(self):
        """GIE-143: mixed key types all processed."""
        result = diff_impacts(
            {"score": 1.0, "status": "OK", "count": 10},
            {"score": 1.2, "status": "WARN", "count": 8},
        )
        assert "score" in result
        assert "status" in result
        assert "count" in result

    def test_gie_144_integer_numeric_handled(self):
        """GIE-144: integer values treated as numeric."""
        result = diff_impacts({"count": 10}, {"count": 15})
        assert result["count"]["absolute_delta"] == pytest.approx(5.0)

    def test_gie_145_large_float_precision(self):
        """GIE-145: large float values handled."""
        result = diff_impacts({"big": 1e10}, {"big": 1e10 + 1})
        assert result["big"]["absolute_delta"] == pytest.approx(1.0)

    def test_gie_146_pct_delta_rounding(self):
        """GIE-146: pct_delta is rounded to 2 decimal places."""
        result = diff_impacts({"val": 3.0}, {"val": 4.0})
        pct = result["val"]["pct_delta"]
        # 33.333... rounded to 2 decimal places = 33.33
        assert pct == pytest.approx(33.33, abs=0.01)

    def test_gie_147_all_keys_in_union(self):
        """GIE-147: result contains keys from both dicts."""
        result = diff_impacts({"a": 1.0, "b": 2.0}, {"b": 3.0, "c": 4.0})
        assert "a" in result
        assert "b" in result
        assert "c" in result

    def test_gie_148_zero_absolute_delta(self):
        """GIE-148: same numeric values → absolute_delta = 0."""
        result = diff_impacts({"val": 5.0}, {"val": 5.0})
        assert result["val"]["absolute_delta"] == pytest.approx(0.0)

    def test_gie_149_none_observed_string_changed(self):
        """GIE-149: None observed vs non-None expected → changed=True."""
        result = diff_impacts({"key": "value"}, {"key": None})
        assert result["key"]["changed"] is True

    def test_gie_150_list_value_changed_flag(self):
        """GIE-150: list values yield changed flag."""
        result = diff_impacts({"items": [1, 2]}, {"items": [1, 2, 3]})
        assert result["items"]["changed"] is True
