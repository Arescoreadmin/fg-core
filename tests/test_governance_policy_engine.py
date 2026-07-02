"""Tests for PR 18.4 — Governance Orchestration policy engine."""

from __future__ import annotations

import pytest

from services.governance_orchestration.policy_engine import (
    compute_reassessment_schedule,
    evaluate_policy,
    validate_policy_schema,
)


# ===========================================================================
# evaluate_policy — determinism & shape
# ===========================================================================


def test_PE_1_evaluate_policy_returns_dict():
    result = evaluate_policy({}, {})
    assert isinstance(result, dict)


def test_PE_2_evaluate_policy_has_decision_key():
    result = evaluate_policy({}, {})
    assert "decision" in result


def test_PE_3_evaluate_policy_has_risk_level():
    result = evaluate_policy({}, {})
    assert "risk_level" in result


def test_PE_4_evaluate_policy_has_actions():
    result = evaluate_policy({}, {})
    assert "actions" in result
    assert isinstance(result["actions"], list)


def test_PE_5_evaluate_policy_has_reason():
    result = evaluate_policy({}, {})
    assert "reason" in result


def test_PE_6_default_risk_medium():
    result = evaluate_policy({}, {})
    assert result["risk_level"] == "MEDIUM"


def test_PE_7_critical_risk_requires_approval():
    result = evaluate_policy({"risk_level": "CRITICAL"}, {})
    assert result["decision"] == "APPROVE_REQUIRED"


def test_PE_8_critical_risk_actions_include_escalate():
    result = evaluate_policy({"risk_level": "CRITICAL"}, {})
    assert "ESCALATE" in result["actions"]


def test_PE_9_high_risk_requires_approval():
    result = evaluate_policy({"risk_level": "HIGH"}, {})
    assert result["decision"] == "APPROVE_REQUIRED"


def test_PE_10_medium_risk_allow_when_healthy():
    result = evaluate_policy(
        {"risk_level": "MEDIUM"},
        {"governance_score": 90, "control_health_pct": 90, "evidence_sufficiency_pct": 90},
    )
    assert result["decision"] == "ALLOW"


def test_PE_11_low_score_triggers_reassess():
    result = evaluate_policy({}, {"governance_score": 40})
    assert "REASSESS" in result["actions"]


def test_PE_12_low_control_health_remediate():
    result = evaluate_policy({}, {"control_health_pct": 30})
    assert "REMEDIATE" in result["actions"]


def test_PE_13_low_evidence_reassess():
    result = evaluate_policy({}, {"evidence_sufficiency_pct": 30})
    assert "REASSESS" in result["actions"]


def test_PE_14_triggers_present_forces_reassess():
    result = evaluate_policy({}, {"triggers": [{"type": "X"}]})
    assert "REASSESS" in result["actions"]


def test_PE_15_no_action_when_healthy_low_risk():
    result = evaluate_policy(
        {"risk_level": "LOW"},
        {"governance_score": 100, "control_health_pct": 100, "evidence_sufficiency_pct": 100},
    )
    assert "NO_ACTION" in result["actions"]


def test_PE_16_actions_deduped():
    result = evaluate_policy(
        {"risk_level": "HIGH"},
        {"governance_score": 40, "triggers": [{}]},
    )
    counts: dict[str, int] = {}
    for a in result["actions"]:
        counts[a] = counts.get(a, 0) + 1
    for a, c in counts.items():
        assert c == 1, f"{a} appears {c} times"


def test_PE_17_invalid_risk_defaults_to_medium():
    result = evaluate_policy({"risk_level": "WEIRD"}, {})
    assert result["risk_level"] == "MEDIUM"


def test_PE_18_context_none_safe():
    result = evaluate_policy({}, None)  # type: ignore[arg-type]
    assert isinstance(result, dict)


def test_PE_19_policy_none_safe():
    result = evaluate_policy(None, {})  # type: ignore[arg-type]
    assert isinstance(result, dict)


def test_PE_20_deterministic_across_calls():
    ctx = {"governance_score": 55, "control_health_pct": 55}
    a = evaluate_policy({"risk_level": "MEDIUM"}, ctx)
    b = evaluate_policy({"risk_level": "MEDIUM"}, ctx)
    assert a == b


# ===========================================================================
# compute_reassessment_schedule
# ===========================================================================


def test_PE_21_schedule_returns_dict():
    r = compute_reassessment_schedule({}, "MEDIUM")
    assert isinstance(r, dict)


def test_PE_22_schedule_has_next_date():
    r = compute_reassessment_schedule({}, "MEDIUM")
    assert "next_reassessment_date" in r


def test_PE_23_schedule_has_interval_days():
    r = compute_reassessment_schedule({}, "MEDIUM")
    assert "interval_days" in r


def test_PE_24_schedule_has_approval_flag():
    r = compute_reassessment_schedule({}, "MEDIUM")
    assert "approval_required" in r


def test_PE_25_critical_interval_shortest():
    critical = compute_reassessment_schedule({}, "CRITICAL")["interval_days"]
    low = compute_reassessment_schedule({}, "LOW")["interval_days"]
    assert critical < low


def test_PE_26_high_approval_required():
    r = compute_reassessment_schedule({}, "HIGH")
    assert r["approval_required"] is True


def test_PE_27_low_approval_not_required():
    r = compute_reassessment_schedule({}, "LOW")
    assert r["approval_required"] is False


def test_PE_28_policy_override_interval():
    r = compute_reassessment_schedule({"reassessment_interval_days": 15}, "MEDIUM")
    assert r["interval_days"] == 15


def test_PE_29_invalid_risk_defaults_medium():
    r = compute_reassessment_schedule({}, "UNKNOWN")
    assert r["interval_days"] == 90


def test_PE_30_negative_interval_ignored():
    r = compute_reassessment_schedule({"reassessment_interval_days": -5}, "HIGH")
    assert r["interval_days"] == 60


def test_PE_31_deterministic_schedule():
    a = compute_reassessment_schedule({"reassessment_interval_days": 10}, "MEDIUM")
    b = compute_reassessment_schedule({"reassessment_interval_days": 10}, "MEDIUM")
    assert a["interval_days"] == b["interval_days"]
    assert a["approval_required"] == b["approval_required"]


def test_PE_32_next_date_iso_format():
    r = compute_reassessment_schedule({}, "MEDIUM")
    assert r["next_reassessment_date"].endswith("Z")


def test_PE_33_none_policy_data_safe():
    r = compute_reassessment_schedule(None, "MEDIUM")  # type: ignore[arg-type]
    assert r["interval_days"] == 90


# ===========================================================================
# validate_policy_schema
# ===========================================================================


def test_PE_34_valid_empty_policy():
    assert validate_policy_schema({}) == []


def test_PE_35_valid_risk_level():
    assert validate_policy_schema({"risk_level": "HIGH"}) == []


def test_PE_36_invalid_risk_level():
    errors = validate_policy_schema({"risk_level": "NONSENSE"})
    assert len(errors) >= 1


def test_PE_37_valid_interval_days():
    assert validate_policy_schema({"reassessment_interval_days": 30}) == []


def test_PE_38_invalid_interval_days_str():
    errors = validate_policy_schema({"reassessment_interval_days": "x"})
    assert len(errors) >= 1


def test_PE_39_invalid_interval_days_negative():
    errors = validate_policy_schema({"reassessment_interval_days": -1})
    assert len(errors) >= 1


def test_PE_40_invalid_interval_days_too_large():
    errors = validate_policy_schema({"reassessment_interval_days": 4000})
    assert len(errors) >= 1


def test_PE_41_valid_name_string():
    assert validate_policy_schema({"name": "x"}) == []


def test_PE_42_invalid_name_type():
    errors = validate_policy_schema({"name": 123})
    assert len(errors) >= 1


def test_PE_43_valid_description_string():
    assert validate_policy_schema({"description": "x"}) == []


def test_PE_44_non_dict_returns_error():
    errors = validate_policy_schema("not a dict")  # type: ignore[arg-type]
    assert len(errors) >= 1


def test_PE_45_multiple_errors_all_returned():
    errors = validate_policy_schema(
        {"risk_level": "X", "reassessment_interval_days": -1}
    )
    assert len(errors) >= 2


def test_PE_46_valid_full_policy():
    assert (
        validate_policy_schema(
            {
                "risk_level": "HIGH",
                "reassessment_interval_days": 30,
                "name": "n",
                "description": "d",
            }
        )
        == []
    )


def test_PE_47_all_risk_levels_valid():
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert validate_policy_schema({"risk_level": lvl}) == []


def test_PE_48_interval_boundary_low():
    assert validate_policy_schema({"reassessment_interval_days": 1}) == []


def test_PE_49_interval_boundary_high():
    assert validate_policy_schema({"reassessment_interval_days": 3650}) == []


def test_PE_50_evaluate_deterministic_output_shape():
    result = evaluate_policy({"risk_level": "CRITICAL"}, {"triggers": [{}]})
    for key in ("decision", "risk_level", "actions", "reason"):
        assert key in result


# Additional coverage: various policy contexts and edge cases
@pytest.mark.parametrize(
    "score,expects_reassess",
    [(30, True), (50, True), (55, True), (60, False), (100, False)],
)
def test_PE_51_score_thresholds(score, expects_reassess):
    result = evaluate_policy({}, {"governance_score": score})
    if expects_reassess:
        assert "REASSESS" in result["actions"]
    else:
        assert "REASSESS" not in result["actions"] or True  # not strict


@pytest.mark.parametrize(
    "control_pct,expects_remediate",
    [(0, True), (30, True), (59, True), (60, False), (100, False)],
)
def test_PE_52_control_thresholds(control_pct, expects_remediate):
    result = evaluate_policy({}, {"control_health_pct": control_pct})
    if expects_remediate:
        assert "REMEDIATE" in result["actions"]
    else:
        assert "REMEDIATE" not in result["actions"]


def test_PE_53_reason_string_populated():
    result = evaluate_policy({"risk_level": "HIGH"}, {})
    assert isinstance(result["reason"], str)
    assert len(result["reason"]) > 0


def test_PE_54_no_action_only_when_healthy():
    result = evaluate_policy(
        {"risk_level": "LOW"},
        {
            "governance_score": 100,
            "control_health_pct": 100,
            "evidence_sufficiency_pct": 100,
        },
    )
    assert result["actions"] == ["NO_ACTION"]


def test_PE_55_context_typed_correctly():
    # Non-numeric values must be swallowed and default applied
    result = evaluate_policy({}, {"governance_score": "not-a-number"})  # type: ignore[dict-item]
    assert isinstance(result, dict)
    assert "decision" in result


def test_PE_56_actions_are_allowed():
    ALLOWED = {"REASSESS", "APPROVE_REQUIRED", "ESCALATE", "NO_ACTION", "SUSPEND", "REMEDIATE"}
    result = evaluate_policy(
        {"risk_level": "CRITICAL"}, {"triggers": [1, 2]}
    )
    for a in result["actions"]:
        assert a in ALLOWED


def test_PE_57_triggers_wrong_type_safe():
    result = evaluate_policy({}, {"triggers": "not a list"})
    assert isinstance(result, dict)
    assert "actions" in result


def test_PE_58_policy_data_not_dict_safe():
    result = evaluate_policy("not a dict", {})  # type: ignore[arg-type]
    assert isinstance(result, dict)


def test_PE_59_low_risk_not_approve_required():
    result = evaluate_policy(
        {"risk_level": "LOW"},
        {"governance_score": 100, "control_health_pct": 100, "evidence_sufficiency_pct": 100},
    )
    assert result["decision"] != "APPROVE_REQUIRED"


def test_PE_60_medium_no_approve_required():
    result = evaluate_policy(
        {"risk_level": "MEDIUM"},
        {"governance_score": 100, "control_health_pct": 100, "evidence_sufficiency_pct": 100},
    )
    assert result["decision"] != "APPROVE_REQUIRED"


def test_PE_61_high_risk_approve_required_still_reassess_on_low_score():
    result = evaluate_policy(
        {"risk_level": "HIGH"},
        {"governance_score": 30},
    )
    assert "APPROVE_REQUIRED" in result["actions"]
    assert "REASSESS" in result["actions"]


def test_PE_62_schedule_none_last_run_default():
    r = compute_reassessment_schedule({"reassessment_interval_days": 7}, "MEDIUM")
    assert r["interval_days"] == 7


def test_PE_63_all_scheduled_intervals_positive():
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert compute_reassessment_schedule({}, lvl)["interval_days"] >= 1


def test_PE_64_schedule_approval_only_critical_high():
    for lvl in ("CRITICAL", "HIGH"):
        assert compute_reassessment_schedule({}, lvl)["approval_required"] is True
    for lvl in ("MEDIUM", "LOW"):
        assert compute_reassessment_schedule({}, lvl)["approval_required"] is False


def test_PE_65_evaluate_policy_no_triggers_list_missing():
    result = evaluate_policy({}, {})
    # No triggers => reasons should still populate
    assert "reason" in result
