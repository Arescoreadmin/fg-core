"""Deterministic field-assessment execution playbooks.

Playbooks define governance execution requirements only. They do not read or
write storage and they intentionally avoid assessor-authored freeform state.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


PLAYBOOK_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class EvidenceExpectation:
    """Minimum evidence expectation for a required evidence class."""

    evidence_type: str
    minimum_count: int
    freshness_days: int | None = None
    blocks_statuses: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceLinkRequirement:
    """Required linkage from a governance source to evidence."""

    source_entity_type: str
    evidence_entity_type: str
    minimum_count: int
    blocks_statuses: tuple[str, ...] = ()


@dataclass(frozen=True)
class FieldAssessmentPlaybook:
    """Versioned deterministic execution requirements for an assessment type."""

    playbook_id: str
    assessment_type: str
    version: str
    required_steps: tuple[str, ...]
    required_scan_sources: tuple[str, ...]
    required_document_classes: tuple[str, ...]
    required_interview_roles: tuple[str, ...]
    required_observation_domains: tuple[str, ...]
    required_evidence_links: tuple[EvidenceLinkRequirement, ...]
    required_asset_candidate_sources: tuple[str, ...]
    blocking_gates: tuple[str, ...]
    minimum_evidence_expectations: tuple[EvidenceExpectation, ...]
    status_transition_requirements: MappingProxyType[str, tuple[str, ...]]


AI_GOVERNANCE_PLAYBOOK = FieldAssessmentPlaybook(
    playbook_id="field_assessment.ai_governance.v1",
    assessment_type="ai_governance",
    version="1.0",
    required_steps=(
        "scan.microsoft_graph.import",
        "scan.oauth_inventory.import",
        "document.ai_policy.register",
        "document.data_governance.register",
        "document.vendor_risk.register",
        "interview.ai_system_owner.capture",
        "interview.security_owner.capture",
        "interview.legal_or_compliance.capture",
        "observation.ai_governance.capture",
        "observation.data_security.capture",
        "observation.vendor_management.capture",
        "evidence.graph.link",
        "finding.evidence.validate",
    ),
    required_scan_sources=("microsoft_graph", "oauth_inventory"),
    required_document_classes=("ai_policy", "data_governance", "vendor_risk"),
    required_interview_roles=(
        "ai_system_owner",
        "security_owner",
        "legal_or_compliance",
    ),
    required_observation_domains=(
        "ai_governance",
        "data_security",
        "vendor_management",
    ),
    required_evidence_links=(
        EvidenceLinkRequirement(
            source_entity_type="finding",
            evidence_entity_type="scan_result",
            minimum_count=1,
            blocks_statuses=("report_generation", "delivered"),
        ),
        EvidenceLinkRequirement(
            source_entity_type="finding",
            evidence_entity_type="document_analysis",
            minimum_count=1,
            blocks_statuses=("report_generation", "delivered"),
        ),
        EvidenceLinkRequirement(
            source_entity_type="finding",
            evidence_entity_type="field_observation",
            minimum_count=1,
            blocks_statuses=("report_generation", "delivered"),
        ),
    ),
    required_asset_candidate_sources=("microsoft_graph", "oauth_inventory"),
    blocking_gates=(
        "scan.microsoft_graph.required",
        "scan.oauth_inventory.required",
        "document.ai_policy.required",
        "document.data_governance.required",
        "document.vendor_risk.required",
        "interview.ai_system_owner.required",
        "interview.security_owner.required",
        "interview.legal_or_compliance.required",
        "evidence.link.required",
        "finding.evidence.required",
        "finding.remediation.required",
    ),
    minimum_evidence_expectations=(
        EvidenceExpectation(
            evidence_type="document.ai_policy",
            minimum_count=1,
            freshness_days=365,
            blocks_statuses=("report_generation", "delivered"),
        ),
        EvidenceExpectation(
            evidence_type="document.data_governance",
            minimum_count=1,
            freshness_days=365,
            blocks_statuses=("report_generation", "delivered"),
        ),
        EvidenceExpectation(
            evidence_type="document.vendor_risk",
            minimum_count=1,
            freshness_days=365,
            blocks_statuses=("report_generation", "delivered"),
        ),
    ),
    status_transition_requirements=MappingProxyType(
        {
            "evidence_collected": (
                "scan.microsoft_graph.required",
                "scan.oauth_inventory.required",
                "document.ai_policy.required",
                "document.data_governance.required",
                "document.vendor_risk.required",
                "interview.ai_system_owner.required",
                "interview.security_owner.required",
                "interview.legal_or_compliance.required",
            ),
            "report_generation": (
                "evidence.link.required",
                "finding.evidence.required",
                "finding.remediation.required",
            ),
            "delivered": (
                "evidence.link.required",
                "finding.evidence.required",
                "finding.remediation.required",
                "escalation.critical.required",
            ),
        }
    ),
)


COMPREHENSIVE_PLAYBOOK = FieldAssessmentPlaybook(
    playbook_id="field_assessment.comprehensive.v1",
    assessment_type="comprehensive",
    version="1.0",
    required_steps=(
        "scan.microsoft_graph.import",
        "scan.oauth_inventory.import",
        "scan.endpoint_inventory.import",
        "scan.network_scan.import",
        "document.ai_policy.register",
        "document.data_governance.register",
        "document.incident_response.register",
        "document.vendor_risk.register",
        "document.access_control.register",
        "document.training_records.register",
        "interview.executive_sponsor.capture",
        "interview.security_owner.capture",
        "interview.compliance_owner.capture",
        "interview.system_owner.capture",
        "observation.ai_governance.capture",
        "observation.data_security.capture",
        "observation.access_management.capture",
        "observation.operational_security.capture",
        "observation.compliance.capture",
        "observation.vendor_management.capture",
        "evidence.graph.link",
        "finding.evidence.validate",
    ),
    required_scan_sources=(
        "microsoft_graph",
        "oauth_inventory",
        "endpoint_inventory",
        "network_scan",
    ),
    required_document_classes=(
        "ai_policy",
        "data_governance",
        "incident_response",
        "vendor_risk",
        "access_control",
        "training_records",
    ),
    required_interview_roles=(
        "executive_sponsor",
        "security_owner",
        "compliance_owner",
        "system_owner",
    ),
    required_observation_domains=(
        "ai_governance",
        "data_security",
        "access_management",
        "operational_security",
        "compliance",
        "vendor_management",
    ),
    required_evidence_links=AI_GOVERNANCE_PLAYBOOK.required_evidence_links,
    required_asset_candidate_sources=(
        "microsoft_graph",
        "oauth_inventory",
        "endpoint_inventory",
        "network_scan",
    ),
    blocking_gates=AI_GOVERNANCE_PLAYBOOK.blocking_gates
    + (
        "scan.endpoint_inventory.required",
        "scan.network_scan.required",
        "document.incident_response.required",
        "document.access_control.required",
        "document.training_records.required",
    ),
    minimum_evidence_expectations=AI_GOVERNANCE_PLAYBOOK.minimum_evidence_expectations
    + (
        EvidenceExpectation(
            evidence_type="document.incident_response",
            minimum_count=1,
            freshness_days=365,
            blocks_statuses=("report_generation", "delivered"),
        ),
        EvidenceExpectation(
            evidence_type="document.access_control",
            minimum_count=1,
            freshness_days=365,
            blocks_statuses=("report_generation", "delivered"),
        ),
        EvidenceExpectation(
            evidence_type="document.training_records",
            minimum_count=1,
            freshness_days=365,
            blocks_statuses=("report_generation", "delivered"),
        ),
    ),
    status_transition_requirements=MappingProxyType(
        {
            "evidence_collected": AI_GOVERNANCE_PLAYBOOK.status_transition_requirements[
                "evidence_collected"
            ]
            + (
                "scan.endpoint_inventory.required",
                "scan.network_scan.required",
                "document.incident_response.required",
                "document.access_control.required",
                "document.training_records.required",
            ),
            "report_generation": AI_GOVERNANCE_PLAYBOOK.status_transition_requirements[
                "report_generation"
            ],
            "delivered": AI_GOVERNANCE_PLAYBOOK.status_transition_requirements[
                "delivered"
            ],
        }
    ),
)


_PLAYBOOKS: MappingProxyType[str, FieldAssessmentPlaybook] = MappingProxyType(
    {
        "ai_governance": AI_GOVERNANCE_PLAYBOOK,
        "comprehensive": COMPREHENSIVE_PLAYBOOK,
    }
)

_FALLBACK_PLAYBOOK_BY_ASSESSMENT_TYPE: MappingProxyType[str, str] = MappingProxyType(
    {
        "cmmc": "comprehensive",
        "hipaa": "comprehensive",
        "soc2": "comprehensive",
        "iso27001": "comprehensive",
    }
)


def get_playbook(assessment_type: str) -> FieldAssessmentPlaybook:
    """Return a deterministic playbook for the assessment type."""

    key = assessment_type.strip().lower()
    playbook_key = (
        key if key in _PLAYBOOKS else _FALLBACK_PLAYBOOK_BY_ASSESSMENT_TYPE.get(key)
    )
    if playbook_key is None:
        return COMPREHENSIVE_PLAYBOOK
    return _PLAYBOOKS[playbook_key]
