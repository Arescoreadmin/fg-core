"""Tests for deterministic workflow routing."""

from __future__ import annotations

from services.governance_workflows.routing import RoutingDecision, route_workflow


class TestRouteWorkflow:
    def test_critical_routes_to_governance_admin(self) -> None:
        r = route_workflow(template_name="finding_remediation", severity="critical")
        assert r.assigned_to_role == "governance_admin"
        assert r.priority == "critical"

    def test_high_routes_to_governance_admin(self) -> None:
        r = route_workflow(template_name="finding_remediation", severity="high")
        assert r.assigned_to_role == "governance_admin"

    def test_medium_routes_to_analyst(self) -> None:
        r = route_workflow(template_name="finding_remediation", severity="medium")
        assert r.assigned_to_role == "analyst"

    def test_low_routes_to_analyst(self) -> None:
        r = route_workflow(template_name="finding_remediation", severity="low")
        assert r.assigned_to_role == "analyst"

    def test_unknown_severity_defaults_to_analyst(self) -> None:
        r = route_workflow(template_name="finding_remediation", severity="bogus")
        assert r.assigned_to_role == "analyst"

    def test_escalation_template_always_governance_admin(self) -> None:
        r = route_workflow(template_name="escalation", severity="low")
        assert r.assigned_to_role == "governance_admin"
        assert r.priority == "critical"

    def test_asset_decommission_low_escalates_to_governance_admin(self) -> None:
        r = route_workflow(template_name="asset_decommission", severity="low")
        assert r.assigned_to_role == "governance_admin"

    def test_routing_decision_is_frozen(self) -> None:
        r = route_workflow(template_name="finding_remediation", severity="high")
        assert isinstance(r, RoutingDecision)
        try:
            r.assigned_to_role = "mutated"  # type: ignore[misc]
            assert False, "should have raised"
        except (AttributeError, TypeError):
            pass

    def test_escalation_path_is_ordered(self) -> None:
        r = route_workflow(template_name="finding_remediation", severity="medium")
        assert "analyst" in r.escalation_path
        assert "governance_admin" in r.escalation_path
        assert "tenant_admin" in r.escalation_path
