"""Deterministic workflow routing by severity and template type.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

No AI, no config reads at runtime. All routing is a pure function of the
template name and severity. Assigned roles are real RBAC role slugs from
api/tenant_rbac.py: governance_admin, analyst.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RoutingDecision:
    assigned_to_role: str
    priority: str
    escalation_path: tuple[str, ...]


_SEVERITY_ROLE: dict[str, str] = {
    "critical": "governance_admin",
    "high": "governance_admin",
    "medium": "analyst",
    "low": "analyst",
    "informational": "analyst",
}

_ESCALATION_PATH: tuple[str, ...] = ("analyst", "governance_admin", "tenant_admin")


def route_workflow(
    *,
    template_name: str,
    severity: str,
    context: dict | None = None,
) -> RoutingDecision:
    """Return a deterministic routing decision for a new workflow.

    severity: critical | high | medium | low | informational
    Escalation template always routes to governance_admin regardless of severity.
    """
    if template_name == "escalation":
        role = "governance_admin"
        priority = "critical"
    else:
        role = _SEVERITY_ROLE.get(severity.lower(), "analyst")
        if template_name == "asset_decommission" and role == "analyst":
            role = "governance_admin"
        priority = severity.lower() if severity.lower() in (
            "critical", "high", "medium", "low"
        ) else "medium"

    return RoutingDecision(
        assigned_to_role=role,
        priority=priority,
        escalation_path=_ESCALATION_PATH,
    )
