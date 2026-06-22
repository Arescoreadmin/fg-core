"""Tests for governance workflow template registry."""

from __future__ import annotations

from services.governance_workflows.templates import (
    get_template,
    list_templates,
)

_ALL_NAMES = {
    "finding_remediation",
    "attestation_renewal",
    "asset_decommission",
    "escalation",
}


class TestGetTemplate:
    def test_finding_remediation(self) -> None:
        t = get_template("finding_remediation")
        assert t is not None
        assert t.name == "finding_remediation"

    def test_attestation_renewal(self) -> None:
        t = get_template("attestation_renewal")
        assert t is not None
        assert t.escalation_after_days == 30

    def test_asset_decommission_requires_finding_ref(self) -> None:
        t = get_template("asset_decommission")
        assert t is not None
        assert "finding_ref" in t.required_evidence_types

    def test_escalation_is_critical_priority(self) -> None:
        t = get_template("escalation")
        assert t is not None
        assert t.default_priority == "critical"

    def test_unknown_returns_none(self) -> None:
        assert get_template("nonexistent") is None

    def test_escalation_has_shortest_window(self) -> None:
        days = {n: get_template(n).escalation_after_days for n in _ALL_NAMES}  # type: ignore[union-attr]
        assert days["escalation"] == min(days.values())

    def test_list_templates_returns_all_four(self) -> None:
        templates = list_templates()
        names = {t.name for t in templates}
        assert names == _ALL_NAMES

    def test_templates_are_frozen(self) -> None:
        t = get_template("finding_remediation")
        assert t is not None
        try:
            t.name = "mutated"  # type: ignore[misc]
            assert False, "should have raised"
        except (AttributeError, TypeError):
            pass
