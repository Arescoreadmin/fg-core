"""Governance workflow template registry.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Templates are frozen dataclasses — no DB access, no runtime config reads.
Every template defines the evidence types required before a workflow can resolve.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkflowTemplate:
    name: str
    description: str
    required_evidence_types: tuple[str, ...]
    default_priority: str
    escalation_after_days: int


_TEMPLATES: dict[str, WorkflowTemplate] = {
    "finding_remediation": WorkflowTemplate(
        name="finding_remediation",
        description=(
            "Finding → owner assigned → remediation evidence required → "
            "verification → closed."
        ),
        required_evidence_types=("link", "text"),
        default_priority="high",
        escalation_after_days=7,
    ),
    "attestation_renewal": WorkflowTemplate(
        name="attestation_renewal",
        description=(
            "Asset overdue → attestor notified (record) → attestation submitted "
            "→ verified."
        ),
        required_evidence_types=("link",),
        default_priority="medium",
        escalation_after_days=30,
    ),
    "asset_decommission": WorkflowTemplate(
        name="asset_decommission",
        description=(
            "Asset flagged → owner confirms → evidence gathered → graph updated "
            "→ archived."
        ),
        required_evidence_types=("link", "finding_ref"),
        default_priority="high",
        escalation_after_days=14,
    ),
    "escalation": WorkflowTemplate(
        name="escalation",
        description=("Finding unactioned X days → escalates to manager role → logged."),
        required_evidence_types=("text",),
        default_priority="critical",
        escalation_after_days=3,
    ),
}


def get_template(name: str) -> WorkflowTemplate | None:
    return _TEMPLATES.get(name)


def list_templates() -> list[WorkflowTemplate]:
    return list(_TEMPLATES.values())
