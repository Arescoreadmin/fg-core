"""Tests for the HIPAA and SOC 2 dedicated playbooks (PR 29).

Verifies:
- get_playbook("hipaa") returns HIPAA_PLAYBOOK, not COMPREHENSIVE_PLAYBOOK
- HIPAA-specific document classes, interview roles, observation domains are present
- HIPAA-specific blocking gates are present
- Evidence freshness constraints are correct
- Status transition requirements include privacy/security officer gates
- Case-insensitive dispatch works
- Existing playbooks are unaffected (regression)
- Playbook is immutable (frozen dataclass)
"""

from __future__ import annotations

import pytest

from services.field_assessment.playbooks import (
    AI_GOVERNANCE_PLAYBOOK,
    COMPREHENSIVE_PLAYBOOK,
    HIPAA_PLAYBOOK,
    SOC2_PLAYBOOK,
    get_playbook,
)


class TestHipaaPlaybookIdentity:
    def test_get_playbook_hipaa_returns_hipaa(self) -> None:
        assert get_playbook("hipaa") is HIPAA_PLAYBOOK

    def test_get_playbook_hipaa_not_comprehensive(self) -> None:
        assert get_playbook("hipaa") is not COMPREHENSIVE_PLAYBOOK

    def test_get_playbook_hipaa_case_insensitive(self) -> None:
        assert get_playbook("HIPAA") is HIPAA_PLAYBOOK
        assert get_playbook("Hipaa") is HIPAA_PLAYBOOK

    def test_hipaa_playbook_id(self) -> None:
        assert HIPAA_PLAYBOOK.playbook_id == "field_assessment.hipaa.v1"

    def test_hipaa_assessment_type(self) -> None:
        assert HIPAA_PLAYBOOK.assessment_type == "hipaa"

    def test_hipaa_playbook_is_frozen(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            HIPAA_PLAYBOOK.playbook_id = "tampered"  # type: ignore[misc]


class TestHipaaDocumentClasses:
    def test_baa_required(self) -> None:
        assert "hipaa_baa" in HIPAA_PLAYBOOK.required_document_classes

    def test_phi_inventory_required(self) -> None:
        assert "hipaa_phi_inventory" in HIPAA_PLAYBOOK.required_document_classes

    def test_risk_analysis_required(self) -> None:
        assert "hipaa_risk_analysis" in HIPAA_PLAYBOOK.required_document_classes

    def test_sanction_policy_required(self) -> None:
        assert "hipaa_sanction_policy" in HIPAA_PLAYBOOK.required_document_classes

    def test_incident_response_required(self) -> None:
        assert "incident_response" in HIPAA_PLAYBOOK.required_document_classes

    def test_training_records_required(self) -> None:
        assert "training_records" in HIPAA_PLAYBOOK.required_document_classes

    def test_access_control_policy_required(self) -> None:
        assert "hipaa_access_control_policy" in HIPAA_PLAYBOOK.required_document_classes


class TestHipaaInterviewRoles:
    def test_privacy_officer_required(self) -> None:
        assert "privacy_officer" in HIPAA_PLAYBOOK.required_interview_roles

    def test_security_officer_required(self) -> None:
        assert "security_officer" in HIPAA_PLAYBOOK.required_interview_roles

    def test_compliance_owner_required(self) -> None:
        assert "compliance_owner" in HIPAA_PLAYBOOK.required_interview_roles


class TestHipaaObservationDomains:
    def test_phi_handling_required(self) -> None:
        assert "phi_handling" in HIPAA_PLAYBOOK.required_observation_domains

    def test_breach_response_required(self) -> None:
        assert "breach_response" in HIPAA_PLAYBOOK.required_observation_domains

    def test_audit_logging_required(self) -> None:
        assert "audit_logging" in HIPAA_PLAYBOOK.required_observation_domains


class TestHipaaBlockingGates:
    def test_baa_gate(self) -> None:
        assert "document.hipaa_baa.required" in HIPAA_PLAYBOOK.blocking_gates

    def test_phi_inventory_gate(self) -> None:
        assert "document.hipaa_phi_inventory.required" in HIPAA_PLAYBOOK.blocking_gates

    def test_risk_analysis_gate(self) -> None:
        assert "document.hipaa_risk_analysis.required" in HIPAA_PLAYBOOK.blocking_gates

    def test_sanction_policy_gate(self) -> None:
        assert (
            "document.hipaa_sanction_policy.required" in HIPAA_PLAYBOOK.blocking_gates
        )

    def test_access_control_policy_gate(self) -> None:
        # Regression: was in required_document_classes but absent from blocking_gates,
        # allowing evidence_collected transition despite missing this required document.
        assert (
            "document.hipaa_access_control_policy.required"
            in HIPAA_PLAYBOOK.blocking_gates
        )

    def test_privacy_officer_gate(self) -> None:
        assert "interview.privacy_officer.required" in HIPAA_PLAYBOOK.blocking_gates

    def test_security_officer_gate(self) -> None:
        assert "interview.security_officer.required" in HIPAA_PLAYBOOK.blocking_gates

    def test_compliance_owner_gate(self) -> None:
        assert "interview.compliance_owner.required" in HIPAA_PLAYBOOK.blocking_gates

    def test_standard_evidence_gates_present(self) -> None:
        assert "evidence.link.required" in HIPAA_PLAYBOOK.blocking_gates
        assert "finding.evidence.required" in HIPAA_PLAYBOOK.blocking_gates
        assert "finding.remediation.required" in HIPAA_PLAYBOOK.blocking_gates


class TestHipaaEvidenceFreshness:
    def _expectation(self, evidence_type: str):
        return next(
            (
                e
                for e in HIPAA_PLAYBOOK.minimum_evidence_expectations
                if e.evidence_type == evidence_type
            ),
            None,
        )

    def test_risk_analysis_annual(self) -> None:
        e = self._expectation("document.hipaa_risk_analysis")
        assert e is not None
        assert e.freshness_days == 365

    def test_phi_inventory_annual(self) -> None:
        e = self._expectation("document.hipaa_phi_inventory")
        assert e is not None
        assert e.freshness_days == 365

    def test_baa_no_expiry(self) -> None:
        e = self._expectation("document.hipaa_baa")
        assert e is not None
        assert e.freshness_days is None

    def test_training_records_annual(self) -> None:
        e = self._expectation("document.training_records")
        assert e is not None
        assert e.freshness_days == 365

    def test_risk_analysis_blocks_report_generation(self) -> None:
        e = self._expectation("document.hipaa_risk_analysis")
        assert e is not None
        assert "report_generation" in e.blocks_statuses
        assert "delivered" in e.blocks_statuses

    def test_access_control_policy_has_freshness_expectation(self) -> None:
        # Regression: was missing from minimum_evidence_expectations entirely.
        e = self._expectation("document.hipaa_access_control_policy")
        assert e is not None
        assert e.freshness_days == 365
        assert "report_generation" in e.blocks_statuses
        assert "delivered" in e.blocks_statuses


class TestHipaaStatusTransitions:
    def test_evidence_collected_requires_privacy_officer(self) -> None:
        reqs = HIPAA_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "interview.privacy_officer.required" in reqs

    def test_evidence_collected_requires_security_officer(self) -> None:
        reqs = HIPAA_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "interview.security_officer.required" in reqs

    def test_evidence_collected_requires_baa(self) -> None:
        reqs = HIPAA_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "document.hipaa_baa.required" in reqs

    def test_evidence_collected_requires_risk_analysis(self) -> None:
        reqs = HIPAA_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "document.hipaa_risk_analysis.required" in reqs

    def test_evidence_collected_requires_access_control_policy(self) -> None:
        # Regression: absent from transition requirements caused the API to advance
        # engagements to evidence_collected even when this document was missing.
        reqs = HIPAA_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "document.hipaa_access_control_policy.required" in reqs

    def test_report_generation_transition(self) -> None:
        reqs = HIPAA_PLAYBOOK.status_transition_requirements["report_generation"]
        assert "evidence.link.required" in reqs
        assert "finding.evidence.required" in reqs

    def test_delivered_requires_escalation_clearance(self) -> None:
        reqs = HIPAA_PLAYBOOK.status_transition_requirements["delivered"]
        assert "escalation.critical.required" in reqs
        assert "report.qa.approved" in reqs


class TestExistingPlaybooksUnaffected:
    def test_ai_governance_unchanged(self) -> None:
        assert get_playbook("ai_governance") is AI_GOVERNANCE_PLAYBOOK

    def test_comprehensive_unchanged(self) -> None:
        assert get_playbook("comprehensive") is COMPREHENSIVE_PLAYBOOK

    def test_cmmc_still_falls_back_to_comprehensive(self) -> None:
        assert get_playbook("cmmc") is COMPREHENSIVE_PLAYBOOK

    def test_unknown_type_falls_back_to_comprehensive(self) -> None:
        assert get_playbook("unknown_type") is COMPREHENSIVE_PLAYBOOK


# ---------------------------------------------------------------------------
# SOC 2 playbook
# ---------------------------------------------------------------------------


class TestSoc2PlaybookIdentity:
    def test_get_playbook_soc2_returns_soc2(self) -> None:
        assert get_playbook("soc2") is SOC2_PLAYBOOK

    def test_get_playbook_soc2_not_comprehensive(self) -> None:
        assert get_playbook("soc2") is not COMPREHENSIVE_PLAYBOOK

    def test_get_playbook_soc2_case_insensitive(self) -> None:
        assert get_playbook("SOC2") is SOC2_PLAYBOOK
        assert get_playbook("Soc2") is SOC2_PLAYBOOK

    def test_soc2_playbook_id(self) -> None:
        assert SOC2_PLAYBOOK.playbook_id == "field_assessment.soc2.v1"

    def test_soc2_assessment_type(self) -> None:
        assert SOC2_PLAYBOOK.assessment_type == "soc2"

    def test_soc2_playbook_is_frozen(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            SOC2_PLAYBOOK.playbook_id = "tampered"  # type: ignore[misc]


class TestSoc2DocumentClasses:
    def test_security_policy_required(self) -> None:
        assert "security_policy" in SOC2_PLAYBOOK.required_document_classes

    def test_access_control_policy_required(self) -> None:
        assert "access_control_policy" in SOC2_PLAYBOOK.required_document_classes

    def test_incident_response_required(self) -> None:
        assert "incident_response" in SOC2_PLAYBOOK.required_document_classes

    def test_change_management_required(self) -> None:
        assert "change_management" in SOC2_PLAYBOOK.required_document_classes

    def test_vendor_risk_required(self) -> None:
        assert "vendor_risk" in SOC2_PLAYBOOK.required_document_classes

    def test_business_continuity_required(self) -> None:
        assert "business_continuity" in SOC2_PLAYBOOK.required_document_classes

    def test_cryptography_policy_required(self) -> None:
        assert "cryptography_policy" in SOC2_PLAYBOOK.required_document_classes

    def test_risk_assessment_required(self) -> None:
        assert "risk_assessment" in SOC2_PLAYBOOK.required_document_classes


class TestSoc2InterviewRoles:
    def test_executive_sponsor_required(self) -> None:
        assert "executive_sponsor" in SOC2_PLAYBOOK.required_interview_roles

    def test_security_owner_required(self) -> None:
        assert "security_owner" in SOC2_PLAYBOOK.required_interview_roles

    def test_compliance_owner_required(self) -> None:
        assert "compliance_owner" in SOC2_PLAYBOOK.required_interview_roles

    def test_system_owner_required(self) -> None:
        assert "system_owner" in SOC2_PLAYBOOK.required_interview_roles


class TestSoc2ObservationDomains:
    def test_logical_access_required(self) -> None:
        assert "logical_access" in SOC2_PLAYBOOK.required_observation_domains

    def test_change_management_required(self) -> None:
        assert "change_management" in SOC2_PLAYBOOK.required_observation_domains

    def test_availability_monitoring_required(self) -> None:
        assert "availability_monitoring" in SOC2_PLAYBOOK.required_observation_domains

    def test_encryption_required(self) -> None:
        assert "encryption" in SOC2_PLAYBOOK.required_observation_domains


class TestSoc2BlockingGates:
    def test_security_policy_gate(self) -> None:
        assert "document.security_policy.required" in SOC2_PLAYBOOK.blocking_gates

    def test_risk_assessment_gate(self) -> None:
        assert "document.risk_assessment.required" in SOC2_PLAYBOOK.blocking_gates

    def test_change_management_gate(self) -> None:
        assert "document.change_management.required" in SOC2_PLAYBOOK.blocking_gates

    def test_executive_sponsor_gate(self) -> None:
        assert "interview.executive_sponsor.required" in SOC2_PLAYBOOK.blocking_gates

    def test_standard_evidence_gates_present(self) -> None:
        assert "evidence.link.required" in SOC2_PLAYBOOK.blocking_gates
        assert "finding.evidence.required" in SOC2_PLAYBOOK.blocking_gates
        assert "finding.remediation.required" in SOC2_PLAYBOOK.blocking_gates


class TestSoc2EvidenceFreshness:
    def _expectation(self, evidence_type: str):
        return next(
            (
                e
                for e in SOC2_PLAYBOOK.minimum_evidence_expectations
                if e.evidence_type == evidence_type
            ),
            None,
        )

    def test_security_policy_annual(self) -> None:
        e = self._expectation("document.security_policy")
        assert e is not None
        assert e.freshness_days == 365

    def test_risk_assessment_annual(self) -> None:
        e = self._expectation("document.risk_assessment")
        assert e is not None
        assert e.freshness_days == 365

    def test_business_continuity_annual(self) -> None:
        e = self._expectation("document.business_continuity")
        assert e is not None
        assert e.freshness_days == 365

    def test_security_policy_blocks_report_generation(self) -> None:
        e = self._expectation("document.security_policy")
        assert e is not None
        assert "report_generation" in e.blocks_statuses


class TestSoc2StatusTransitions:
    def test_evidence_collected_requires_executive_sponsor(self) -> None:
        reqs = SOC2_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "interview.executive_sponsor.required" in reqs

    def test_evidence_collected_requires_security_policy(self) -> None:
        reqs = SOC2_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "document.security_policy.required" in reqs

    def test_evidence_collected_requires_risk_assessment(self) -> None:
        reqs = SOC2_PLAYBOOK.status_transition_requirements["evidence_collected"]
        assert "document.risk_assessment.required" in reqs

    def test_delivered_requires_qa_approval(self) -> None:
        reqs = SOC2_PLAYBOOK.status_transition_requirements["delivered"]
        assert "report.qa.approved" in reqs
