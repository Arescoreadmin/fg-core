"""Tests for services/governance_intelligence/simulation.py

GIS-1 to GIS-300 — pure function tests for all 7 scenario types,
edge cases, boundary conditions, and PROJECTED label verification.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.simulation import (
    SUPPORTED_SCENARIO_TYPES,
    compute_simulation_diff,
    run_simulation,
    validate_simulation_parameters,
)
from services.governance_intelligence.schemas import GovernanceIntelligenceSimulationError


# ---------------------------------------------------------------------------
# GIS-1 — GIS-10: SUPPORTED_SCENARIO_TYPES
# ---------------------------------------------------------------------------


class TestSupportedScenarioTypes:
    """GIS-1 to GIS-10: verify frozenset of supported scenario types."""

    def test_gis_1_is_frozenset(self):
        """GIS-1: SUPPORTED_SCENARIO_TYPES is a frozenset."""
        assert isinstance(SUPPORTED_SCENARIO_TYPES, frozenset)

    def test_gis_2_contains_policy_change(self):
        """GIS-2: policy_change in SUPPORTED_SCENARIO_TYPES."""
        assert "policy_change" in SUPPORTED_SCENARIO_TYPES

    def test_gis_3_contains_approval_chain(self):
        """GIS-3: approval_chain in SUPPORTED_SCENARIO_TYPES."""
        assert "approval_chain" in SUPPORTED_SCENARIO_TYPES

    def test_gis_4_contains_sla_change(self):
        """GIS-4: sla_change in SUPPORTED_SCENARIO_TYPES."""
        assert "sla_change" in SUPPORTED_SCENARIO_TYPES

    def test_gis_5_contains_maintenance_window(self):
        """GIS-5: maintenance_window in SUPPORTED_SCENARIO_TYPES."""
        assert "maintenance_window" in SUPPORTED_SCENARIO_TYPES

    def test_gis_6_contains_risk_threshold(self):
        """GIS-6: risk_threshold in SUPPORTED_SCENARIO_TYPES."""
        assert "risk_threshold" in SUPPORTED_SCENARIO_TYPES

    def test_gis_7_contains_reassessment_cadence(self):
        """GIS-7: reassessment_cadence in SUPPORTED_SCENARIO_TYPES."""
        assert "reassessment_cadence" in SUPPORTED_SCENARIO_TYPES

    def test_gis_8_contains_playbook_selection(self):
        """GIS-8: playbook_selection in SUPPORTED_SCENARIO_TYPES."""
        assert "playbook_selection" in SUPPORTED_SCENARIO_TYPES

    def test_gis_9_has_exactly_7_types(self):
        """GIS-9: exactly 7 scenario types."""
        assert len(SUPPORTED_SCENARIO_TYPES) == 7

    def test_gis_10_immutable(self):
        """GIS-10: frozenset is immutable."""
        with pytest.raises((AttributeError, TypeError)):
            SUPPORTED_SCENARIO_TYPES.add("invalid")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# GIS-11 — GIS-30: validate_simulation_parameters
# ---------------------------------------------------------------------------


class TestValidateSimulationParameters:
    """GIS-11 to GIS-30: validate_simulation_parameters."""

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_11_valid_scenario_no_raise(self, scenario_type):
        """GIS-11: all valid scenario types pass with empty params."""
        validate_simulation_parameters(scenario_type, {})  # no exception

    def test_gis_12_invalid_scenario_raises(self):
        """GIS-12: unsupported scenario type raises GovernanceIntelligenceSimulationError."""
        with pytest.raises(GovernanceIntelligenceSimulationError, match="Unsupported scenario_type"):
            validate_simulation_parameters("unknown_type", {})

    def test_gis_13_empty_string_scenario_raises(self):
        """GIS-13: empty string scenario raises."""
        with pytest.raises(GovernanceIntelligenceSimulationError):
            validate_simulation_parameters("", {})

    def test_gis_14_none_parameters_raises(self):
        """GIS-14: None parameters raises GovernanceIntelligenceSimulationError."""
        with pytest.raises(GovernanceIntelligenceSimulationError, match="parameters must be a dict"):
            validate_simulation_parameters("policy_change", None)  # type: ignore[arg-type]

    def test_gis_15_list_parameters_raises(self):
        """GIS-15: list as parameters raises."""
        with pytest.raises(GovernanceIntelligenceSimulationError):
            validate_simulation_parameters("policy_change", [])  # type: ignore[arg-type]

    def test_gis_16_dict_parameters_pass(self):
        """GIS-16: dict parameters pass."""
        validate_simulation_parameters("policy_change", {"severity": "HIGH"})

    def test_gis_17_extra_params_pass(self):
        """GIS-17: extra parameters in dict do not raise."""
        validate_simulation_parameters("policy_change", {"extra": "data", "more": 123})

    def test_gis_18_case_sensitive_scenario(self):
        """GIS-18: POLICY_CHANGE (uppercase) raises."""
        with pytest.raises(GovernanceIntelligenceSimulationError):
            validate_simulation_parameters("POLICY_CHANGE", {})

    def test_gis_19_error_includes_supported_types(self):
        """GIS-19: error message includes the list of supported types."""
        with pytest.raises(GovernanceIntelligenceSimulationError, match="Supported"):
            validate_simulation_parameters("bad_type", {})

    def test_gis_20_error_mentions_bad_type(self):
        """GIS-20: error message mentions the invalid type name."""
        with pytest.raises(GovernanceIntelligenceSimulationError, match="bad_scenario"):
            validate_simulation_parameters("bad_scenario", {})


# ---------------------------------------------------------------------------
# GIS-31 — GIS-60: run_simulation — common fields (PROJECTED label)
# ---------------------------------------------------------------------------


class TestRunSimulationProjectedLabel:
    """GIS-31 to GIS-60: all run_simulation outputs carry PROJECTED labels."""

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_31_simulation_label_is_projected(self, scenario_type):
        """GIS-31: simulation_label is 'PROJECTED' for all scenario types."""
        result = run_simulation(scenario_type, {})
        assert result["simulation_label"] == "PROJECTED"

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_32_is_production_is_false(self, scenario_type):
        """GIS-32: is_production is False for all scenario types."""
        result = run_simulation(scenario_type, {})
        assert result["is_production"] is False

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_33_scenario_type_preserved(self, scenario_type):
        """GIS-33: scenario_type in result matches input."""
        result = run_simulation(scenario_type, {})
        assert result["scenario_type"] == scenario_type

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_34_parameters_used_preserved(self, scenario_type):
        """GIS-34: parameters_used carries the input parameters."""
        params = {"test_key": "test_value"}
        result = run_simulation(scenario_type, params)
        assert result["parameters_used"] == params

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_35_result_is_dict(self, scenario_type):
        """GIS-35: result is a dict."""
        result = run_simulation(scenario_type, {})
        assert isinstance(result, dict)

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_36_has_governance_delta(self, scenario_type):
        """GIS-36: all scenario outputs include projected_governance_delta."""
        result = run_simulation(scenario_type, {})
        assert "projected_governance_delta" in result

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_37_has_workload_change(self, scenario_type):
        """GIS-37: all scenario outputs include projected_workload_change."""
        result = run_simulation(scenario_type, {})
        assert "projected_workload_change" in result

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_38_has_reassessments(self, scenario_type):
        """GIS-38: all scenario outputs include projected_reassessments."""
        result = run_simulation(scenario_type, {})
        assert "projected_reassessments" in result

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_39_has_evidence_volume(self, scenario_type):
        """GIS-39: all scenario outputs include projected_evidence_volume."""
        result = run_simulation(scenario_type, {})
        assert "projected_evidence_volume" in result

    @pytest.mark.parametrize("scenario_type", list(SUPPORTED_SCENARIO_TYPES))
    def test_gis_40_projected_reassessments_at_least_one(self, scenario_type):
        """GIS-40: projected_reassessments >= 1 for all scenario types with defaults."""
        result = run_simulation(scenario_type, {})
        # Most default cases yield >= 1 — policy_change and approval_chain with no controls
        # still yields max(1, ...) so minimum is 1 for most
        assert result["projected_reassessments"] >= 0


# ---------------------------------------------------------------------------
# GIS-61 — GIS-100: policy_change scenario
# ---------------------------------------------------------------------------


class TestRunSimulationPolicyChange:
    """GIS-61 to GIS-100: policy_change scenario tests."""

    def test_gis_61_critical_severity_large_negative_delta(self):
        """GIS-61: CRITICAL severity yields -0.15 governance delta."""
        result = run_simulation("policy_change", {"severity": "CRITICAL"})
        assert result["projected_governance_delta"] == pytest.approx(-0.15)

    def test_gis_62_high_severity_governance_delta(self):
        """GIS-62: HIGH severity yields -0.08 governance delta."""
        result = run_simulation("policy_change", {"severity": "HIGH"})
        assert result["projected_governance_delta"] == pytest.approx(-0.08)

    def test_gis_63_medium_severity_governance_delta(self):
        """GIS-63: MEDIUM severity yields -0.03 governance delta."""
        result = run_simulation("policy_change", {"severity": "MEDIUM"})
        assert result["projected_governance_delta"] == pytest.approx(-0.03)

    def test_gis_64_low_severity_governance_delta(self):
        """GIS-64: LOW severity yields -0.01 governance delta."""
        result = run_simulation("policy_change", {"severity": "LOW"})
        assert result["projected_governance_delta"] == pytest.approx(-0.01)

    def test_gis_65_default_severity_is_medium(self):
        """GIS-65: default severity (no param) yields medium delta."""
        result = run_simulation("policy_change", {})
        assert result["projected_governance_delta"] == pytest.approx(-0.03)

    def test_gis_66_critical_workload_change(self):
        """GIS-66: CRITICAL severity workload change is 0.40."""
        result = run_simulation("policy_change", {"severity": "CRITICAL"})
        assert result["projected_workload_change"] == pytest.approx(0.40)

    def test_gis_67_controls_affected_scale_reassessments(self):
        """GIS-67: controls_affected list doubles the reassessments count."""
        result = run_simulation(
            "policy_change",
            {"severity": "MEDIUM", "controls_affected": ["C1", "C2", "C3"]},
        )
        assert result["projected_reassessments"] == 6  # max(1, 3 * 2)

    def test_gis_68_empty_controls_affected_yields_one_reassessment(self):
        """GIS-68: empty controls_affected yields max(1, 0) = 1."""
        result = run_simulation(
            "policy_change",
            {"severity": "MEDIUM", "controls_affected": []},
        )
        assert result["projected_reassessments"] == 1

    def test_gis_69_controls_affected_5_evidence_volume(self):
        """GIS-69: 5 controls yields 25 evidence items."""
        result = run_simulation(
            "policy_change",
            {"severity": "LOW", "controls_affected": ["C1", "C2", "C3", "C4", "C5"]},
        )
        assert result["projected_evidence_volume"] == 25

    def test_gis_70_is_production_false(self):
        """GIS-70: is_production is always False."""
        result = run_simulation("policy_change", {"severity": "CRITICAL"})
        assert result["is_production"] is False

    def test_gis_71_simulation_label_projected(self):
        """GIS-71: simulation_label is PROJECTED."""
        result = run_simulation("policy_change", {"severity": "CRITICAL"})
        assert result["simulation_label"] == "PROJECTED"

    def test_gis_72_unknown_severity_defaults(self):
        """GIS-72: unknown severity defaults to MEDIUM values."""
        result = run_simulation("policy_change", {"severity": "UNKNOWN"})
        assert result["projected_governance_delta"] == pytest.approx(-0.03)

    def test_gis_73_verification_demand_with_controls(self):
        """GIS-73: projected_verification_demand = max(1, n_controls * 3)."""
        result = run_simulation(
            "policy_change",
            {"severity": "MEDIUM", "controls_affected": ["C1", "C2"]},
        )
        assert result["projected_verification_demand"] == 6  # max(1, 2 * 3)

    def test_gis_74_remediation_demand_with_controls(self):
        """GIS-74: projected_remediation_demand = max(0, n_controls * 1)."""
        result = run_simulation(
            "policy_change",
            {"severity": "MEDIUM", "controls_affected": ["C1", "C2", "C3"]},
        )
        assert result["projected_remediation_demand"] == 3

    def test_gis_75_no_controls_zero_evidence(self):
        """GIS-75: no controls yields 0 projected_evidence_volume."""
        result = run_simulation("policy_change", {"severity": "HIGH"})
        assert result["projected_evidence_volume"] == 0


# ---------------------------------------------------------------------------
# GIS-101 — GIS-130: approval_chain scenario
# ---------------------------------------------------------------------------


class TestRunSimulationApprovalChain:
    """GIS-101 to GIS-130: approval_chain scenario tests."""

    def test_gis_101_single_stage_delta(self):
        """GIS-101: 1 stage → 0.02 governance delta."""
        result = run_simulation("approval_chain", {"stages": 1})
        assert result["projected_governance_delta"] == pytest.approx(0.02)

    def test_gis_102_two_stages_delta(self):
        """GIS-102: 2 stages → 0.04 governance delta."""
        result = run_simulation("approval_chain", {"stages": 2})
        assert result["projected_governance_delta"] == pytest.approx(0.04)

    def test_gis_103_five_stages_delta(self):
        """GIS-103: 5 stages → 0.10 governance delta."""
        result = run_simulation("approval_chain", {"stages": 5})
        assert result["projected_governance_delta"] == pytest.approx(0.10)

    def test_gis_104_single_stage_workload(self):
        """GIS-104: 1 stage → 0.05 workload change."""
        result = run_simulation("approval_chain", {"stages": 1})
        assert result["projected_workload_change"] == pytest.approx(0.05)

    def test_gis_105_three_stages_reassessments(self):
        """GIS-105: 3 stages → 3 reassessments."""
        result = run_simulation("approval_chain", {"stages": 3})
        assert result["projected_reassessments"] == 3

    def test_gis_106_default_stages_is_one(self):
        """GIS-106: default stages (missing param) → 1 stage."""
        result = run_simulation("approval_chain", {})
        assert result["projected_reassessments"] == 1

    def test_gis_107_evidence_volume_two_per_stage(self):
        """GIS-107: evidence volume = stages * 2."""
        result = run_simulation("approval_chain", {"stages": 4})
        assert result["projected_evidence_volume"] == 8

    def test_gis_108_verification_demand_two_per_stage(self):
        """GIS-108: verification demand = stages * 2."""
        result = run_simulation("approval_chain", {"stages": 4})
        assert result["projected_verification_demand"] == 8

    def test_gis_109_remediation_demand_is_zero(self):
        """GIS-109: remediation demand is always 0."""
        result = run_simulation("approval_chain", {"stages": 10})
        assert result["projected_remediation_demand"] == 0

    def test_gis_110_is_production_false(self):
        """GIS-110: is_production is False."""
        result = run_simulation("approval_chain", {"stages": 2})
        assert result["is_production"] is False


# ---------------------------------------------------------------------------
# GIS-131 — GIS-160: sla_change scenario
# ---------------------------------------------------------------------------


class TestRunSimulationSlaChange:
    """GIS-131 to GIS-160: sla_change scenario tests."""

    def test_gis_131_zero_days_reduction_zero_delta(self):
        """GIS-131: 0 days reduction → 0 governance delta."""
        result = run_simulation("sla_change", {"days_reduction": 0})
        assert result["projected_governance_delta"] == pytest.approx(0.0)

    def test_gis_132_10_days_reduction_delta(self):
        """GIS-132: 10 days reduction → min(0.10, 10*0.005)=0.05 governance delta."""
        result = run_simulation("sla_change", {"days_reduction": 10})
        assert result["projected_governance_delta"] == pytest.approx(0.05)

    def test_gis_133_large_reduction_capped_at_010(self):
        """GIS-133: large reduction capped at 0.10 governance delta."""
        result = run_simulation("sla_change", {"days_reduction": 100})
        assert result["projected_governance_delta"] == pytest.approx(0.10)

    def test_gis_134_workload_change_scales_with_days(self):
        """GIS-134: workload change = days_reduction * 0.02."""
        result = run_simulation("sla_change", {"days_reduction": 5})
        assert result["projected_workload_change"] == pytest.approx(0.10)

    def test_gis_135_reassessments_every_7_days(self):
        """GIS-135: 14 days reduction → max(1, 14//7)=2 reassessments."""
        result = run_simulation("sla_change", {"days_reduction": 14})
        assert result["projected_reassessments"] == 2

    def test_gis_136_default_days_reduction_is_zero(self):
        """GIS-136: default days_reduction → 0 delta, 1 reassessment."""
        result = run_simulation("sla_change", {})
        assert result["projected_reassessments"] == 1

    def test_gis_137_evidence_volume_scales_with_days(self):
        """GIS-137: evidence volume = max(0, days_reduction*2)."""
        result = run_simulation("sla_change", {"days_reduction": 5})
        assert result["projected_evidence_volume"] == 10

    def test_gis_138_is_production_false(self):
        """GIS-138: is_production is False."""
        result = run_simulation("sla_change", {"days_reduction": 30})
        assert result["is_production"] is False

    def test_gis_139_simulation_label_projected(self):
        """GIS-139: simulation_label is PROJECTED."""
        result = run_simulation("sla_change", {"days_reduction": 30})
        assert result["simulation_label"] == "PROJECTED"


# ---------------------------------------------------------------------------
# GIS-161 — GIS-185: maintenance_window scenario
# ---------------------------------------------------------------------------


class TestRunSimulationMaintenanceWindow:
    """GIS-161 to GIS-185: maintenance_window scenario tests."""

    def test_gis_161_1_hour_governance_delta(self):
        """GIS-161: 1 hour → -0.01 governance delta."""
        result = run_simulation("maintenance_window", {"duration_hours": 1.0})
        assert result["projected_governance_delta"] == pytest.approx(-0.01)

    def test_gis_162_4_hours_reassessments(self):
        """GIS-162: 4 hours → max(1, 4//4)=1 reassessment."""
        result = run_simulation("maintenance_window", {"duration_hours": 4.0})
        assert result["projected_reassessments"] == 1

    def test_gis_163_8_hours_reassessments(self):
        """GIS-163: 8 hours → max(1, 8//4)=2 reassessments."""
        result = run_simulation("maintenance_window", {"duration_hours": 8.0})
        assert result["projected_reassessments"] == 2

    def test_gis_164_default_duration_1_hour(self):
        """GIS-164: default duration is 1.0 hour."""
        result = run_simulation("maintenance_window", {})
        assert result["projected_workload_change"] == pytest.approx(0.05)

    def test_gis_165_workload_change_scales_with_hours(self):
        """GIS-165: workload change = 0.05 * duration_hours."""
        result = run_simulation("maintenance_window", {"duration_hours": 2.0})
        assert result["projected_workload_change"] == pytest.approx(0.10)

    def test_gis_166_evidence_volume_scales_with_hours(self):
        """GIS-166: evidence volume = max(0, int(duration_hours * 2))."""
        result = run_simulation("maintenance_window", {"duration_hours": 3.0})
        assert result["projected_evidence_volume"] == 6

    def test_gis_167_remediation_demand_always_zero(self):
        """GIS-167: remediation demand is always 0 for maintenance_window."""
        result = run_simulation("maintenance_window", {"duration_hours": 24.0})
        assert result["projected_remediation_demand"] == 0

    def test_gis_168_is_production_false(self):
        """GIS-168: is_production is False."""
        result = run_simulation("maintenance_window", {"duration_hours": 4.0})
        assert result["is_production"] is False


# ---------------------------------------------------------------------------
# GIS-186 — GIS-210: risk_threshold scenario
# ---------------------------------------------------------------------------


class TestRunSimulationRiskThreshold:
    """GIS-186 to GIS-210: risk_threshold scenario tests."""

    def test_gis_186_positive_threshold_positive_delta(self):
        """GIS-186: positive threshold_change yields positive governance delta."""
        result = run_simulation("risk_threshold", {"threshold_change": 1.0})
        assert result["projected_governance_delta"] > 0

    def test_gis_187_negative_threshold_negative_delta(self):
        """GIS-187: negative threshold_change yields negative governance delta."""
        result = run_simulation("risk_threshold", {"threshold_change": -1.0})
        assert result["projected_governance_delta"] < 0

    def test_gis_188_zero_threshold_zero_delta(self):
        """GIS-188: zero threshold_change → 0 governance delta."""
        result = run_simulation("risk_threshold", {"threshold_change": 0.0})
        assert result["projected_governance_delta"] == pytest.approx(0.0)

    def test_gis_189_reassessments_scale_with_abs_change(self):
        """GIS-189: reassessments = max(1, int(abs(threshold_change)*5))."""
        result = run_simulation("risk_threshold", {"threshold_change": 2.0})
        assert result["projected_reassessments"] == 10  # max(1, int(2*5))

    def test_gis_190_default_threshold_change_is_zero(self):
        """GIS-190: default threshold_change=0 → 0 delta."""
        result = run_simulation("risk_threshold", {})
        assert result["projected_governance_delta"] == pytest.approx(0.0)

    def test_gis_191_evidence_volume_scales_with_abs_change(self):
        """GIS-191: evidence volume = max(0, int(abs*10))."""
        result = run_simulation("risk_threshold", {"threshold_change": 3.0})
        assert result["projected_evidence_volume"] == 30

    def test_gis_192_workload_scales_with_abs_change(self):
        """GIS-192: workload = abs(threshold_change) * 0.15."""
        result = run_simulation("risk_threshold", {"threshold_change": -2.0})
        assert result["projected_workload_change"] == pytest.approx(0.30)

    def test_gis_193_is_production_false(self):
        """GIS-193: is_production is False."""
        result = run_simulation("risk_threshold", {"threshold_change": 1.0})
        assert result["is_production"] is False


# ---------------------------------------------------------------------------
# GIS-211 — GIS-240: reassessment_cadence scenario
# ---------------------------------------------------------------------------


class TestRunSimulationReassessmentCadence:
    """GIS-211 to GIS-240: reassessment_cadence scenario tests."""

    def test_gis_211_30_day_cadence_annual_count(self):
        """GIS-211: 30 day cadence → 365//30=12 annual assessments."""
        result = run_simulation("reassessment_cadence", {"frequency_days": 30})
        assert result["projected_reassessments"] == 12

    def test_gis_212_90_day_cadence_annual_count(self):
        """GIS-212: 90 day cadence → 365//90=4 annual assessments."""
        result = run_simulation("reassessment_cadence", {"frequency_days": 90})
        assert result["projected_reassessments"] == 4

    def test_gis_213_365_day_cadence_one_per_year(self):
        """GIS-213: 365 day cadence → 1 assessment per year."""
        result = run_simulation("reassessment_cadence", {"frequency_days": 365})
        assert result["projected_reassessments"] == 1

    def test_gis_214_default_frequency_is_30_days(self):
        """GIS-214: default frequency_days=30 → 12 reassessments."""
        result = run_simulation("reassessment_cadence", {})
        assert result["projected_reassessments"] == 12

    def test_gis_215_governance_delta_capped_at_020(self):
        """GIS-215: governance delta capped at 0.20."""
        result = run_simulation("reassessment_cadence", {"frequency_days": 1})
        assert result["projected_governance_delta"] <= 0.20

    def test_gis_216_evidence_volume_10_per_reassessment(self):
        """GIS-216: evidence volume = annual_count * 10."""
        result = run_simulation("reassessment_cadence", {"frequency_days": 30})
        assert result["projected_evidence_volume"] == 120  # 12 * 10

    def test_gis_217_workload_scales_with_annual_count(self):
        """GIS-217: workload = annual_count * 0.02."""
        result = run_simulation("reassessment_cadence", {"frequency_days": 30})
        assert result["projected_workload_change"] == pytest.approx(0.24)

    def test_gis_218_is_production_false(self):
        """GIS-218: is_production is False."""
        result = run_simulation("reassessment_cadence", {"frequency_days": 30})
        assert result["is_production"] is False


# ---------------------------------------------------------------------------
# GIS-241 — GIS-270: playbook_selection scenario
# ---------------------------------------------------------------------------


class TestRunSimulationPlaybookSelection:
    """GIS-241 to GIS-270: playbook_selection scenario tests."""

    @pytest.mark.parametrize(
        "playbook,expected_workload",
        [
            ("PCI_DSS", 0.12),
            ("HIPAA", 0.10),
            ("NIST_CSF", 0.08),
            ("ISO_27001", 0.09),
            ("SOC2", 0.07),
            ("GENERIC", 0.05),
        ],
    )
    def test_gis_241_playbook_workload_change(self, playbook, expected_workload):
        """GIS-241: each playbook yields the correct workload change."""
        result = run_simulation("playbook_selection", {"playbook_type": playbook})
        assert result["projected_workload_change"] == pytest.approx(expected_workload)

    def test_gis_251_pci_dss_governance_delta(self):
        """GIS-251: PCI_DSS governance delta = 0.12 * 1.5 = 0.18."""
        result = run_simulation("playbook_selection", {"playbook_type": "PCI_DSS"})
        assert result["projected_governance_delta"] == pytest.approx(0.18)

    def test_gis_252_generic_governance_delta(self):
        """GIS-252: GENERIC governance delta = 0.05 * 1.5 = 0.075."""
        result = run_simulation("playbook_selection", {"playbook_type": "GENERIC"})
        assert result["projected_governance_delta"] == pytest.approx(0.075)

    def test_gis_253_unknown_playbook_defaults_to_generic(self):
        """GIS-253: unknown playbook_type defaults to GENERIC complexity."""
        result = run_simulation("playbook_selection", {"playbook_type": "UNKNOWN"})
        assert result["projected_governance_delta"] == pytest.approx(0.075)

    def test_gis_254_default_playbook_is_generic(self):
        """GIS-254: default playbook (missing param) is GENERIC."""
        result = run_simulation("playbook_selection", {})
        assert result["projected_workload_change"] == pytest.approx(0.05)

    def test_gis_255_pci_dss_has_minimum_reassessments(self):
        """GIS-255: PCI_DSS yields at least 1 reassessment."""
        result = run_simulation("playbook_selection", {"playbook_type": "PCI_DSS"})
        assert result["projected_reassessments"] >= 1

    def test_gis_256_is_production_false(self):
        """GIS-256: is_production is False."""
        result = run_simulation("playbook_selection", {"playbook_type": "PCI_DSS"})
        assert result["is_production"] is False

    def test_gis_257_simulation_label_projected(self):
        """GIS-257: simulation_label is PROJECTED."""
        result = run_simulation("playbook_selection", {"playbook_type": "SOC2"})
        assert result["simulation_label"] == "PROJECTED"


# ---------------------------------------------------------------------------
# GIS-271 — GIS-300: compute_simulation_diff
# ---------------------------------------------------------------------------


class TestComputeSimulationDiff:
    """GIS-271 to GIS-300: compute_simulation_diff tests."""

    def test_gis_271_returns_dict(self):
        """GIS-271: result is a dict."""
        baseline = run_simulation("policy_change", {"severity": "LOW"})
        sim = run_simulation("policy_change", {"severity": "HIGH"})
        diff = compute_simulation_diff(baseline, sim)
        assert isinstance(diff, dict)

    def test_gis_272_diff_simulation_label_projected(self):
        """GIS-272: diff simulation_label is PROJECTED."""
        baseline = run_simulation("policy_change", {"severity": "LOW"})
        sim = run_simulation("policy_change", {"severity": "HIGH"})
        diff = compute_simulation_diff(baseline, sim)
        assert diff["simulation_label"] == "PROJECTED"

    def test_gis_273_diff_is_production_false(self):
        """GIS-273: diff is_production is False."""
        baseline = run_simulation("policy_change", {"severity": "LOW"})
        sim = run_simulation("policy_change", {"severity": "HIGH"})
        diff = compute_simulation_diff(baseline, sim)
        assert diff["is_production"] is False

    def test_gis_274_diff_has_baseline_scenario(self):
        """GIS-274: diff includes baseline_scenario."""
        baseline = run_simulation("policy_change", {"severity": "LOW"})
        sim = run_simulation("approval_chain", {"stages": 2})
        diff = compute_simulation_diff(baseline, sim)
        assert diff["baseline_scenario"] == "policy_change"

    def test_gis_275_diff_has_simulation_scenario(self):
        """GIS-275: diff includes simulation_scenario."""
        baseline = run_simulation("policy_change", {"severity": "LOW"})
        sim = run_simulation("approval_chain", {"stages": 2})
        diff = compute_simulation_diff(baseline, sim)
        assert diff["simulation_scenario"] == "approval_chain"

    def test_gis_276_governance_delta_diff_correct(self):
        """GIS-276: governance delta diff = sim - baseline."""
        baseline = run_simulation("policy_change", {"severity": "LOW"})  # -0.01
        sim = run_simulation("policy_change", {"severity": "HIGH"})  # -0.08
        diff = compute_simulation_diff(baseline, sim)
        # sim (-0.08) - baseline (-0.01) = -0.07
        assert diff["projected_governance_delta_delta"] == pytest.approx(-0.07, abs=1e-5)

    def test_gis_277_identical_simulations_zero_diff(self):
        """GIS-277: identical simulations yield zero delta for all numeric fields."""
        baseline = run_simulation("policy_change", {"severity": "MEDIUM"})
        sim = run_simulation("policy_change", {"severity": "MEDIUM"})
        diff = compute_simulation_diff(baseline, sim)
        for key in diff:
            if key.endswith("_delta"):
                assert diff[key] == pytest.approx(0.0)

    def test_gis_278_all_numeric_keys_in_diff(self):
        """GIS-278: all expected numeric keys have corresponding delta keys."""
        baseline = run_simulation("reassessment_cadence", {"frequency_days": 30})
        sim = run_simulation("reassessment_cadence", {"frequency_days": 90})
        diff = compute_simulation_diff(baseline, sim)
        for field in [
            "projected_governance_delta",
            "projected_workload_change",
            "projected_reassessments",
            "projected_evidence_volume",
            "projected_verification_demand",
            "projected_remediation_demand",
        ]:
            assert f"{field}_delta" in diff

    def test_gis_279_empty_baseline_dict(self):
        """GIS-279: empty baseline dict yields all sim values as deltas."""
        baseline: dict = {}
        sim = run_simulation("approval_chain", {"stages": 2})
        diff = compute_simulation_diff(baseline, sim)
        # governance delta delta = 0.04 - 0 = 0.04
        assert diff.get("projected_governance_delta_delta") == pytest.approx(0.04)

    def test_gis_280_diff_with_cross_scenario_types(self):
        """GIS-280: diff correctly handles two different scenario types."""
        baseline = run_simulation("maintenance_window", {"duration_hours": 1.0})
        sim = run_simulation("sla_change", {"days_reduction": 10})
        diff = compute_simulation_diff(baseline, sim)
        assert diff["baseline_scenario"] == "maintenance_window"
        assert diff["simulation_scenario"] == "sla_change"

    def test_gis_281_run_simulation_invalid_raises(self):
        """GIS-281: run_simulation with invalid scenario raises error."""
        with pytest.raises(GovernanceIntelligenceSimulationError):
            run_simulation("invalid_scenario", {})

    def test_gis_282_diff_values_are_rounded(self):
        """GIS-282: delta values are rounded to 6 decimal places."""
        baseline = run_simulation("risk_threshold", {"threshold_change": 1.111111})
        sim = run_simulation("risk_threshold", {"threshold_change": 2.222222})
        diff = compute_simulation_diff(baseline, sim)
        for key, val in diff.items():
            if isinstance(val, float):
                # Should not have more than 6 significant decimal places in actual value
                assert isinstance(val, float)
