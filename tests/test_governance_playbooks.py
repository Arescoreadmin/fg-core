"""Tests for PR 18.4 — Governance Orchestration playbook library."""

from __future__ import annotations

import pytest

from services.governance_orchestration.models import PlaybookType
from services.governance_orchestration.playbooks import (
    PLAYBOOK_TEMPLATES,
    compute_playbook_coverage,
    get_playbook_template,
    validate_playbook,
)


# ---------------------------------------------------------------------------
# Templates present
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "playbook_type",
    [
        "PCI_DSS",
        "HIPAA",
        "NIST_CSF",
        "ISO_27001",
        "SOC2",
        "MICROSOFT_SECURE_SCORE",
        "CIS_CONTROLS",
    ],
)
def test_PB_1_template_exists(playbook_type):
    assert playbook_type in PLAYBOOK_TEMPLATES


def test_PB_2_all_playbook_types_have_templates():
    for member in PlaybookType:
        assert member.value in PLAYBOOK_TEMPLATES


def test_PB_3_get_template_returns_dict():
    assert isinstance(get_playbook_template("PCI_DSS"), dict)


def test_PB_4_unknown_playbook_raises():
    with pytest.raises(KeyError):
        get_playbook_template("UNKNOWN")


def test_PB_5_template_has_controls():
    tpl = get_playbook_template("PCI_DSS")
    assert isinstance(tpl.get("controls"), list)


def test_PB_6_template_has_name():
    tpl = get_playbook_template("HIPAA")
    assert isinstance(tpl.get("name"), str)


def test_PB_7_template_has_description():
    tpl = get_playbook_template("NIST_CSF")
    assert "description" in tpl


def test_PB_8_template_reassessment_interval():
    tpl = get_playbook_template("SOC2")
    assert isinstance(tpl.get("reassessment_interval_days"), int)


def test_PB_9_template_approval_flag():
    tpl = get_playbook_template("ISO_27001")
    assert isinstance(tpl.get("approval_required"), bool)


# ---------------------------------------------------------------------------
# Per-template checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "playbook_type",
    list(PLAYBOOK_TEMPLATES.keys()),
)
def test_PB_10_template_shape(playbook_type):
    tpl = get_playbook_template(playbook_type)
    for key in ("name", "controls", "reassessment_interval_days", "approval_required"):
        assert key in tpl


@pytest.mark.parametrize("playbook_type", list(PLAYBOOK_TEMPLATES.keys()))
def test_PB_11_template_controls_nonempty(playbook_type):
    tpl = get_playbook_template(playbook_type)
    assert len(tpl["controls"]) > 0


@pytest.mark.parametrize("playbook_type", list(PLAYBOOK_TEMPLATES.keys()))
def test_PB_12_template_interval_positive(playbook_type):
    tpl = get_playbook_template(playbook_type)
    assert tpl["reassessment_interval_days"] > 0


def test_PB_13_pci_dss_control_count():
    tpl = get_playbook_template("PCI_DSS")
    assert len(tpl["controls"]) >= 5


def test_PB_14_hipaa_control_count():
    tpl = get_playbook_template("HIPAA")
    assert len(tpl["controls"]) >= 3


def test_PB_15_nist_csf_control_count():
    tpl = get_playbook_template("NIST_CSF")
    assert len(tpl["controls"]) >= 5


def test_PB_16_iso_27001_control_count():
    tpl = get_playbook_template("ISO_27001")
    assert len(tpl["controls"]) >= 5


def test_PB_17_soc2_control_count():
    tpl = get_playbook_template("SOC2")
    assert len(tpl["controls"]) >= 5


def test_PB_18_mss_control_count():
    tpl = get_playbook_template("MICROSOFT_SECURE_SCORE")
    assert len(tpl["controls"]) >= 3


def test_PB_19_cis_control_count():
    tpl = get_playbook_template("CIS_CONTROLS")
    assert len(tpl["controls"]) >= 5


def test_PB_20_template_returns_copy():
    tpl1 = get_playbook_template("PCI_DSS")
    tpl1["mutated"] = True
    tpl2 = get_playbook_template("PCI_DSS")
    assert "mutated" not in tpl2


# ---------------------------------------------------------------------------
# validate_playbook
# ---------------------------------------------------------------------------


def test_PB_21_validate_empty():
    errors = validate_playbook({})
    assert len(errors) >= 1


def test_PB_22_validate_missing_name():
    errors = validate_playbook({"controls": []})
    assert any("name" in e for e in errors)


def test_PB_23_validate_missing_controls():
    errors = validate_playbook({"name": "n"})
    assert any("controls" in e for e in errors)


def test_PB_24_validate_controls_not_list():
    errors = validate_playbook({"name": "n", "controls": "not a list"})
    assert len(errors) >= 1


def test_PB_25_validate_valid_playbook():
    errors = validate_playbook({"name": "n", "controls": ["a", "b"]})
    assert errors == []


def test_PB_26_validate_invalid_interval():
    errors = validate_playbook(
        {"name": "n", "controls": [], "reassessment_interval_days": -1}
    )
    assert len(errors) >= 1


def test_PB_27_validate_valid_interval():
    errors = validate_playbook(
        {"name": "n", "controls": [], "reassessment_interval_days": 30}
    )
    assert errors == []


def test_PB_28_validate_non_dict():
    errors = validate_playbook("not a dict")  # type: ignore[arg-type]
    assert len(errors) >= 1


def test_PB_29_validate_all_templates_valid():
    for playbook_type in PLAYBOOK_TEMPLATES:
        errors = validate_playbook(get_playbook_template(playbook_type))
        assert errors == [], f"Template {playbook_type} invalid: {errors}"


# ---------------------------------------------------------------------------
# compute_playbook_coverage
# ---------------------------------------------------------------------------


def test_PB_30_coverage_returns_dict():
    result = compute_playbook_coverage(None, "tenant-x", "PCI_DSS")
    assert isinstance(result, dict)


def test_PB_31_coverage_has_playbook_type():
    result = compute_playbook_coverage(None, "tenant-x", "PCI_DSS")
    assert result["playbook_type"] == "PCI_DSS"


def test_PB_32_coverage_has_total_controls():
    result = compute_playbook_coverage(None, "tenant-x", "PCI_DSS")
    assert "total_controls" in result


def test_PB_33_coverage_total_matches_template():
    tpl = get_playbook_template("HIPAA")
    result = compute_playbook_coverage(None, "tenant-x", "HIPAA")
    assert result["total_controls"] == len(tpl["controls"])


def test_PB_34_coverage_unknown_raises():
    with pytest.raises(KeyError):
        compute_playbook_coverage(None, "tenant-x", "UNKNOWN")


def test_PB_35_coverage_has_coverage_pct():
    result = compute_playbook_coverage(None, "tenant-x", "SOC2")
    assert "coverage_pct" in result


def test_PB_36_coverage_has_controls_list():
    result = compute_playbook_coverage(None, "tenant-x", "SOC2")
    assert isinstance(result["controls"], list)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_PB_37_deterministic_templates_shape():
    a = get_playbook_template("PCI_DSS")
    b = get_playbook_template("PCI_DSS")
    assert a == b


def test_PB_38_template_types_frozen():
    # Ensure PLAYBOOK_TEMPLATES has exactly 7 entries.
    assert len(PLAYBOOK_TEMPLATES) == 7


def test_PB_39_all_intervals_at_least_30_days():
    for playbook_type in PLAYBOOK_TEMPLATES:
        tpl = get_playbook_template(playbook_type)
        assert tpl["reassessment_interval_days"] >= 30
