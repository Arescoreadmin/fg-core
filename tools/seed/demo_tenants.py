#!/usr/bin/env python3
"""Seed production-shaped demo tenants and delivered field assessments.

Creates three tenant-scoped demo engagements:
- demo-bank
- demo-healthcare
- demo-law

The script writes only synthetic demo evidence. Connector-shaped evidence is
labeled as demo connector output and uses fields that the active connector set
can collect when a real client authorizes the scan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.auth_scopes.helpers import _b64url, hash_key  # noqa: E402
from api.db import get_engine, get_sessionmaker, reset_engine_cache, set_tenant_context  # noqa: E402
from api.db_models import ApiKey, TenantUser  # noqa: E402
from api.db_models_field_assessment import FaEngagement  # noqa: E402
from api.db_models_governance_report import GovernanceReportRecord  # noqa: E402
from api.db_models_portal import PortalGrant  # noqa: E402
from services.field_assessment.models import EvidenceLinkDuplicate  # noqa: E402
from services.field_assessment.playbooks import get_playbook  # noqa: E402
from services.field_assessment.promotion import promote_engagement_to_governance  # noqa: E402
from services.field_assessment.questionnaire_store import (  # noqa: E402
    get_or_create_questionnaire,
    list_responses,
    submit_questionnaire,
    update_response,
)
from services.field_assessment.store import (  # noqa: E402
    create_document_analysis,
    create_engagement,
    create_evidence_link,
    create_finding,
    create_observation,
    create_scan_result,
    list_document_analyses,
    list_observations,
)
from services.portal_grant_service import portal_grant_svc  # noqa: E402


DEMO_SCOPES = (
    "governance:read",
    "governance:write",
    "governance:qa_approve",
    "ui:read",
    "control-plane:read",
    "audit:read",
    "audit:export",
    "decisions:read",
    "feed:read",
    "ingest:write",
    "keys:read",
    "keys:write",
    "admin:read",
)


@dataclass(frozen=True)
class DemoTenant:
    tenant_id: str
    tenant_label: str
    client_name: str
    client_domain: str
    sector: str
    assessment_type: str
    portal_username: str
    portal_ai_enabled: bool = True


DEMO_TENANTS: tuple[DemoTenant, ...] = (
    DemoTenant(
        tenant_id="demo-bank",
        tenant_label="Bank Demo Tenant",
        client_name="Northstar Community Bank",
        client_domain="bank.demo.frostgate.ai",
        sector="banking",
        assessment_type="soc2",
        portal_username="demo-bank",
    ),
    DemoTenant(
        tenant_id="demo-healthcare",
        tenant_label="Healthcare Demo Tenant",
        client_name="Evergreen Care Network",
        client_domain="healthcare.demo.frostgate.ai",
        sector="healthcare",
        assessment_type="hipaa",
        portal_username="demo-healthcare",
    ),
    DemoTenant(
        tenant_id="demo-law",
        tenant_label="Law Office Demo Tenant",
        client_name="Summit Legal Group",
        client_domain="law.demo.frostgate.ai",
        sector="legal",
        assessment_type="ai_governance",
        portal_username="demo-law",
    ),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _sha256_json(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _source_payload(source: str, tenant: DemoTenant) -> dict[str, Any]:
    base = {
        "demo_seed": True,
        "source_provenance": "demo_connector_output",
        "tenant_sector": tenant.sector,
        "connector_capability_note": (
            "Synthetic demo data shaped like evidence the active FrostGate connector "
            "can gather when authorized by a real client."
        ),
    }
    if source == "microsoft_graph":
        return {
            **base,
            "users": [
                {"id": "u-exec", "department": "Executive", "mfa_registered": True},
                {"id": "u-ops", "department": "Operations", "mfa_registered": True},
                {"id": "u-vendor", "department": "Vendor Access", "mfa_registered": False},
            ],
            "directory_roles": ["Global Reader", "Security Reader"],
            "conditional_access_policies": ["Require MFA for admins", "Block legacy auth"],
        }
    if source == "oauth_inventory":
        return {
            **base,
            "apps": [
                {"app_id": "crm-ai-assistant", "publisher_verified": True, "high_privilege_scopes": []},
                {"app_id": "meeting-summary-tool", "publisher_verified": False, "high_privilege_scopes": ["Files.Read.All"]},
            ],
        }
    if source == "endpoint_inventory":
        return {
            **base,
            "endpoints": [
                {"device_id": "lap-001", "managed": True, "edr_status": "healthy"},
                {"device_id": "lap-002", "managed": True, "edr_status": "healthy"},
                {"device_id": "contractor-01", "managed": False, "edr_status": "unknown"},
            ],
        }
    if source == "network_scan":
        return {
            **base,
            "hosts": [
                {"host": tenant.client_domain, "ports": [443], "tls": "valid"},
                {"host": f"vpn.{tenant.client_domain}", "ports": [443], "tls": "valid"},
            ],
        }
    return {**base, "objects": []}


def _required_doc_title(doc_class: str, tenant: DemoTenant) -> str:
    return f"{tenant.client_name} {doc_class.replace('_', ' ').title()}"


def _doc_findings(doc_class: str, tenant: DemoTenant) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings = [
        {
            "summary": f"{doc_class} is present for the {tenant.sector} demo assessment.",
            "source": "demo_policy_register",
        }
    ]
    gaps: list[dict[str, Any]] = []
    if doc_class in {"vendor_risk", "hipaa_baa", "risk_assessment"}:
        gaps.append(
            {
                "summary": "Review cadence should be evidenced with owner sign-off in the next cycle.",
                "severity": "medium",
            }
        )
    return findings, gaps


def _create_or_update_document(db: Session, tenant: DemoTenant, engagement_id: str, doc_class: str):
    existing = [
        d
        for d in list_document_analyses(db, engagement_id=engagement_id, tenant_id=tenant.tenant_id, limit=100)
        if d.document_classification == doc_class
    ]
    analysis_findings, gaps = _doc_findings(doc_class, tenant)
    if existing:
        doc = existing[0]
        doc.document_name = _required_doc_title(doc_class, tenant)
        doc.version_label = "demo-current"
        doc.approved_by = "FrostGate Demo Governance Lead"
        doc.approval_date = _now_iso()
        doc.freshness_date = _now_iso()
        doc.analysis_findings = analysis_findings
        doc.gaps_identified = gaps
        doc.updated_at = _now_iso()
        db.flush()
        return doc
    return create_document_analysis(
        db,
        tenant_id=tenant.tenant_id,
        engagement_id=engagement_id,
        document_name=_required_doc_title(doc_class, tenant),
        document_classification=doc_class,
        document_hash=_sha256_json({"tenant": tenant.tenant_id, "doc_class": doc_class}),
        version_label="demo-current",
        approved_by="FrostGate Demo Governance Lead",
        approval_date=_now_iso(),
        freshness_date=_now_iso(),
        analysis_findings=analysis_findings,
        gaps_identified=gaps,
    )


def _create_or_update_observation(
    db: Session,
    *,
    tenant: DemoTenant,
    engagement_id: str,
    domain: str,
    observation_type: str,
    title: str,
    description: str,
    interview_role: str | None,
    severity: str = "low",
):
    existing = [
        row
        for row in list_observations(db, engagement_id=engagement_id, tenant_id=tenant.tenant_id, limit=100)
        if row.title == title and row.observation_type == observation_type
    ]
    evidence = {
        "demo_seed": True,
        "source_provenance": "structured_assessor_observation",
        "sector": tenant.sector,
    }
    if existing:
        obs = existing[0]
        obs.domain = domain
        obs.severity = severity
        obs.description = description
        obs.interview_role = interview_role
        obs.structured_evidence = evidence
        obs.updated_at = _now_iso()
        db.flush()
        return obs
    return create_observation(
        db,
        tenant_id=tenant.tenant_id,
        engagement_id=engagement_id,
        domain=domain,
        observation_type=observation_type,
        severity=severity,
        title=title,
        description=description,
        interview_role=interview_role,
        structured_evidence=evidence,
        linked_finding_ids=[],
        assessor_id="demo_seed",
    )


def _link(db: Session, *, tenant_id: str, engagement_id: str, source_type: str, source_id: str, evidence_type: str, evidence_id: str) -> None:
    try:
        create_evidence_link(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_entity_type=source_type,
            source_entity_id=source_id,
            evidence_entity_type=evidence_type,
            evidence_entity_id=evidence_id,
            link_metadata={"demo_seed": True, "link_reason": "demo_evidence_lineage"},
        )
    except EvidenceLinkDuplicate:
        set_tenant_context(db, tenant_id)


def _upsert_engagement(db: Session, tenant: DemoTenant):
    engagement_id = f"{tenant.tenant_id}-assessment-2026"
    existing = db.execute(
        select(FaEngagement).where(
            FaEngagement.id == engagement_id,
            FaEngagement.tenant_id == tenant.tenant_id,
        )
    ).scalar_one_or_none()
    metadata = {
        "demo_seed": True,
        "tenant_label": tenant.tenant_label,
        "sector": tenant.sector,
        "portal_ai_enabled": tenant.portal_ai_enabled,
        "evidence_boundary": (
            "Demo assessment includes connector-shaped synthetic evidence and "
            "structured questionnaire/observation evidence. It does not claim a "
            "live scan of a real external institution."
        ),
    }
    if existing:
        existing.client_name = tenant.client_name
        existing.client_domain = tenant.client_domain
        existing.assessment_type = tenant.assessment_type
        existing.status = "in_progress"
        existing.engagement_metadata = metadata
        existing.updated_at = _now_iso()
        db.flush()
        return existing
    eng = create_engagement(
        db,
        tenant_id=tenant.tenant_id,
        client_name=tenant.client_name,
        client_domain=tenant.client_domain,
        assessor_id="demo_seed",
        assessment_type=tenant.assessment_type,
        scheduled_date=_now_iso(),
        engagement_metadata=metadata,
        actor="demo_seed",
    )
    eng.id = engagement_id
    db.flush()
    return eng


def _seed_assessment(db: Session, tenant: DemoTenant) -> tuple[str, str]:
    set_tenant_context(db, tenant.tenant_id)
    eng = _upsert_engagement(db, tenant)
    playbook = get_playbook(tenant.assessment_type)

    scans = {}
    for source in playbook.required_scan_sources:
        payload = _source_payload(source, tenant)
        scan = create_scan_result(
            db,
            tenant_id=tenant.tenant_id,
            engagement_id=eng.id,
            source_type=source,
            schema_version="1.0",
            collected_at=_now_iso(),
            raw_payload=payload,
            normalized_payload={
                "demo_seed": True,
                "summary": f"{source} demo evidence for {tenant.client_name}",
                "risk_signals": ["review_required"] if source == "oauth_inventory" else [],
            },
            object_count=len(payload.get("users") or payload.get("apps") or payload.get("endpoints") or payload.get("hosts") or []),
        )
        scans[source] = scan

    docs = {doc_class: _create_or_update_document(db, tenant, eng.id, doc_class) for doc_class in playbook.required_document_classes}

    observations = []
    for role in playbook.required_interview_roles:
        observations.append(
            _create_or_update_observation(
                db,
                tenant=tenant,
                engagement_id=eng.id,
                domain="compliance" if tenant.sector != "legal" else "ai_governance",
                observation_type="interview",
                title=f"{role.replace('_', ' ').title()} Interview",
                description=f"Structured demo interview for {tenant.client_name}; no personal data captured.",
                interview_role=role,
                severity="info",
            )
        )
    for domain in playbook.required_observation_domains:
        observations.append(
            _create_or_update_observation(
                db,
                tenant=tenant,
                engagement_id=eng.id,
                domain=domain,
                observation_type="finding",
                title=f"{domain.replace('_', ' ').title()} Control Observation",
                description=f"Demo observation showing current-state {domain.replace('_', ' ')} evidence for {tenant.sector} operations.",
                interview_role=None,
                severity="low",
            )
        )

    primary_scan = next(iter(scans.values()))
    primary_doc = next(iter(docs.values()))
    primary_obs = observations[0]

    # Each spec: (finding_type, severity, title, description, nist_rmf_control, framework_mappings, remediation_hint)
    _SOC2 = "soc2"
    _HIPAA = "hipaa"
    _AIGO = "ai_governance"
    _FFIEC = "ffiec_cat"

    _FINDING_SPECS: dict[str, list[tuple[str, str, str, str, str, list[dict[str, str]], str]]] = {
        "demo-bank": [
            (
                "bank.ai.unclassified_data_use",
                "critical",
                "AI tool (ChatGPT/Copilot) used with unclassified customer data",
                "Microsoft Graph and OAuth scans show staff uploading loan and account data to external AI tools "
                "without a data-classification policy or approved exception. FFIEC CAT Baseline requires controls "
                "over data leaving the institution's boundary.",
                "GOVERN-1.1",
                [{"framework": _SOC2, "control_id": "CC6.7"}, {"framework": _FFIEC, "control_id": "IS.B.1"}],
                "Establish a data-classification policy covering NPI and PII before AI tool use; block unapproved "
                "third-party AI uploads via DLP rule and conditional access policy.",
            ),
            (
                "bank.vendor.no_contract_ai",
                "high",
                "AI vendor lacks formal contract with data processing obligations",
                "OAuth inventory found an AI meeting-summary tool (meeting-summary-tool) with Files.Read.All scope "
                "and no executed vendor agreement documenting data retention, deletion, and breach notification.",
                "GOVERN-4.1",
                [{"framework": _SOC2, "control_id": "CC9.2"}, {"framework": _FFIEC, "control_id": "VM.B.1"}],
                "Execute a vendor data processing agreement covering AI output retention, deletion SLA, and "
                "breach notification within 72 hours before the tool is permitted to access production data.",
            ),
            (
                "bank.access.vendor_no_mfa",
                "high",
                "Vendor account lacks MFA — FFIEC CAT Baseline not met",
                "Microsoft Graph shows a user in the Vendor Access department with mfa_registered=false. FFIEC CAT "
                "Baseline requires MFA for privileged and remote access; SOC 2 CC6.1 requires logical access controls.",
                "GOVERN-2.1",
                [{"framework": _SOC2, "control_id": "CC6.1"}, {"framework": _FFIEC, "control_id": "AM.B.2"}],
                "Enforce MFA for all vendor accounts via Conditional Access policy and confirm registration within "
                "7 days. Flag non-compliant accounts for offboarding until resolved.",
            ),
            (
                "bank.ai.output_review_gap",
                "medium",
                "AI-generated customer communications not reviewed before send",
                "Field interviews with AI system owner confirm AI draft emails are sent without a human-in-the-loop "
                "review step, creating accuracy and fair-lending risk. NIST AI RMF MAP-5.1 requires operator controls "
                "on AI output before it reaches end users.",
                "MAP-5.1",
                [{"framework": _SOC2, "control_id": "CC5.2"}],
                "Implement a mandatory reviewer step in the CRM workflow before AI-generated content is delivered "
                "to customers. Log approval decisions for audit trail.",
            ),
            (
                "bank.oauth.overprivileged_scope",
                "medium",
                "OAuth app with Files.Read.All scope lacks formal business approval",
                "The meeting-summary-tool holds Files.Read.All, granting access to all SharePoint and OneDrive files. "
                "No business justification or approval record was found in the vendor risk register.",
                "GOVERN-5.1",
                [{"framework": _SOC2, "control_id": "CC6.6"}],
                "Conduct a scope-reduction review; downgrade to Mail.Read or Calendar.Read if meeting context is "
                "sufficient. Require re-authorization with documented business justification.",
            ),
            (
                "bank.training.coverage_gap",
                "medium",
                "Annual security training completion below 95% FFIEC CAT threshold",
                "Training records document 84% completion for the current cycle. FFIEC CAT Baseline and SOC 2 CC2.2 "
                "require documented awareness training for all personnel with system access.",
                "MAP-4.1",
                [{"framework": _SOC2, "control_id": "CC2.2"}, {"framework": _FFIEC, "control_id": "TS.B.1"}],
                "Identify non-compliant users, escalate to their managers, and complete training within 30 days. "
                "Add automated reminders at 60- and 30-day marks in the LMS.",
            ),
            (
                "bank.ir.ai_scenario_missing",
                "low",
                "Incident response plan does not cover AI-specific failure scenarios",
                "The existing IR plan covers data breach and system outage but lacks runbooks for AI model failure, "
                "AI-assisted fraud, and adversarial prompt injection. MANAGE-4.1 requires documented IR covering "
                "AI system events.",
                "MANAGE-4.1",
                [{"framework": _SOC2, "control_id": "CC7.3"}],
                "Add AI-specific annexes to the IR plan: AI output failure, model poisoning, and prompt injection. "
                "Tabletop test within 90 days.",
            ),
            (
                "bank.policy.review_cadence",
                "low",
                "AI and data governance policy missing dated owner sign-off",
                "Policy documents are present and current, but the document register lacks an owner signature and "
                "confirmed next-review date. SOC 2 CC5.3 and FFIEC require evidenced policy maintenance.",
                "GOVERN-6.1",
                [{"framework": _SOC2, "control_id": "CC5.3"}, {"framework": _FFIEC, "control_id": "IS.B.2"}],
                "Add owner sign-off field and next-review date to the policy register. Set a calendar reminder "
                "90 days before the next review cycle.",
            ),
        ],
        "demo-healthcare": [
            (
                "hc.ai.phi_in_transcription_no_baa",
                "critical",
                "AI transcription tool processes PHI without executed Business Associate Agreement",
                "OAuth inventory identifies an AI transcription tool used in clinical visit notes. No BAA was found "
                "in the document register. HIPAA §164.308(b)(1) requires a BAA with any business associate who "
                "creates, receives, maintains, or transmits PHI on the covered entity's behalf.",
                "GOVERN-1.1",
                [{"framework": _HIPAA, "control_id": "§164.308(b)(1)"}, {"framework": _HIPAA, "control_id": "§164.314(a)(1)"}],
                "Immediately restrict PHI input to the transcription tool. Obtain an executed BAA from the vendor "
                "or disable the tool until a compliant agreement is in place.",
            ),
            (
                "hc.ai.clinical_decision_no_risk_analysis",
                "critical",
                "Clinical AI decision support tool deployed without formal HIPAA risk analysis",
                "Interview with the Privacy Officer confirms the clinical AI tool was adopted without a formal "
                "risk analysis per §164.308(a)(1)(ii)(A). NIST AI RMF MAP-1.1 requires documented impact "
                "categorization before deployment in sensitive domains.",
                "MAP-1.1",
                [{"framework": _HIPAA, "control_id": "§164.308(a)(1)(ii)(A)"}],
                "Commission a HIPAA risk analysis specific to the AI tool, documenting data flows, PHI categories "
                "processed, threat scenarios, and residual risk before next clinical use.",
            ),
            (
                "hc.access.phi_on_unmanaged_device",
                "high",
                "PHI accessible from unmanaged contractor device",
                "Microsoft Graph shows a contractor device (contractor-01) with managed=false and edr_status=unknown "
                "that has access to EHR-linked SharePoint. HIPAA §164.312(a)(2)(i) requires unique user IDs and "
                "device access controls for workstations that access PHI.",
                "GOVERN-2.1",
                [{"framework": _HIPAA, "control_id": "§164.312(a)(2)(i)"}, {"framework": _HIPAA, "control_id": "§164.310(c)"}],
                "Enroll the contractor device in MDM or revoke its access to PHI-adjacent SharePoint sites. "
                "Establish a policy requiring managed devices for all PHI access within 14 days.",
            ),
            (
                "hc.training.ai_tool_no_hipaa_training",
                "high",
                "Staff using AI tools without HIPAA-specific AI awareness training",
                "Training records confirm no HIPAA-specific AI awareness module exists. Workforce members using "
                "the AI transcription and chatbot tools have not received training on PHI handling in AI contexts. "
                "§164.308(a)(5)(ii)(A) requires a security awareness training program.",
                "MAP-4.1",
                [{"framework": _HIPAA, "control_id": "§164.308(a)(5)(ii)(A)"}],
                "Develop and deploy an AI-specific HIPAA training module covering PHI in AI tools, BAA obligations, "
                "and breach reporting. Complete training for all AI tool users within 45 days.",
            ),
            (
                "hc.audit.ai_decisions_not_logged",
                "medium",
                "AI-assisted clinical decisions not captured in audit logs",
                "Audit log review shows no records of AI-assisted diagnostic suggestions or care plan modifications "
                "attributed to the AI tool. §164.312(b) requires audit controls that record and examine activity "
                "in information systems containing PHI.",
                "MEASURE-2.5",
                [{"framework": _HIPAA, "control_id": "§164.312(b)"}],
                "Configure the AI tool to emit structured audit events (user_id, patient_id_hash, decision_type, "
                "timestamp) to the SIEM. Retain logs for 6 years per HIPAA retention requirements.",
            ),
            (
                "hc.vendor.baa_missing_ai_chatbot",
                "medium",
                "Business Associate Agreement missing for patient-facing AI chatbot vendor",
                "The patient scheduling chatbot is operated by a third-party SaaS vendor. No BAA was located in "
                "the document register. The chatbot collects appointment details that may constitute PHI.",
                "GOVERN-5.1",
                [{"framework": _HIPAA, "control_id": "§164.308(b)(1)"}],
                "Obtain a fully executed BAA from the chatbot vendor. If the vendor cannot or will not sign, "
                "disable PHI collection features or replace the vendor.",
            ),
            (
                "hc.access.ehr_lockout_policy",
                "medium",
                "EHR system does not enforce automatic session lock after inactivity",
                "Field observation of workstation access shows EHR sessions remaining unlocked after 30+ minutes "
                "of inactivity in clinical areas. §164.312(a)(2)(iii) requires automatic logoff for workstations "
                "with access to PHI.",
                "GOVERN-3.1",
                [{"framework": _HIPAA, "control_id": "§164.312(a)(2)(iii)"}],
                "Configure EHR system to enforce session lock after 15 minutes of inactivity and require "
                "re-authentication. Validate in all clinical areas within 30 days.",
            ),
            (
                "hc.policy.sanction_ai_misuse",
                "low",
                "Workforce sanction policy does not address AI tool misuse",
                "The current sanction policy covers PHI disclosure and system misuse but lacks specific language "
                "for AI tool misuse scenarios (e.g., uploading patient data to unapproved AI services). "
                "§164.308(a)(1)(ii)(C) requires sanctions for policy violations.",
                "MANAGE-2.2",
                [{"framework": _HIPAA, "control_id": "§164.308(a)(1)(ii)(C)"}],
                "Update the workforce sanction policy to include AI-specific violation categories and graduated "
                "consequences. Communicate the update at the next all-staff training.",
            ),
        ],
        "demo-law": [
            (
                "law.ai.client_data_in_public_llm",
                "critical",
                "Confidential client matter data uploaded to public LLM without consent",
                "Interview with AI system owner and OAuth inventory confirm attorneys are using personal ChatGPT "
                "accounts and the firm's Microsoft Copilot without data isolation policies. Client matter files "
                "were confirmed uploaded for drafting assistance. ABA Formal Opinion 512 (2023) requires "
                "competence measures to prevent inadvertent disclosure of client confidences. NIST AI RMF "
                "GOVERN-1.1 requires organizational policies governing AI use with sensitive data.",
                "GOVERN-1.1",
                [{"framework": _AIGO, "control_id": "GOVERN-1.1"}, {"framework": "aba_ethics", "control_id": "ABA_FO_512_2023"}],
                "Immediately prohibit uploading client matter data to public LLMs without an executed data "
                "processing agreement and client consent. Deploy firm-managed Copilot with data-residency controls. "
                "Issue emergency ethics advisory to all attorneys within 5 business days.",
            ),
            (
                "law.ai.unvalidated_research",
                "high",
                "AI-generated legal research used in filings without supervising attorney review",
                "Field observation confirms junior associates submitting AI-generated case citations directly to "
                "court documents without independent verification. Several AI hallucinated citations have been "
                "identified in draft work product. NIST AI RMF MAP-5.1 requires operator controls on AI output "
                "accuracy before use in consequential decisions.",
                "MAP-5.1",
                [{"framework": _AIGO, "control_id": "GOVERN-4.1"}, {"framework": "aba_ethics", "control_id": "ABA_Model_Rule_5.1"}],
                "Establish a mandatory human-in-the-loop review policy requiring supervising attorney sign-off "
                "on all AI-generated research before use in filings. Create a citation verification checklist "
                "and add AI source disclosure to document metadata.",
            ),
            (
                "law.gov.no_ai_tool_inventory",
                "high",
                "No documented AI tool inventory for the firm",
                "The firm has no centralized record of AI tools in use across practice groups. OAuth inventory "
                "discovered 7 distinct AI tools not tracked in any vendor register. Without an inventory, the "
                "firm cannot assess data exposure, ethics conflicts, or jurisdiction-specific restrictions. "
                "NIST AI RMF GOVERN-1.2 requires organizations to maintain an inventory of AI systems.",
                "GOVERN-1.2",
                [{"framework": _AIGO, "control_id": "GOVERN-1.2"}],
                "Create an AI tool registry capturing: tool name, vendor, data access, practice group, "
                "ethics review status, and jurisdiction restrictions. Require registration before firm adoption. "
                "Complete initial inventory within 30 days.",
            ),
            (
                "law.vendor.no_data_retention_clause",
                "medium",
                "AI vendor contracts lack data retention and deletion obligations",
                "Legal review of the three primary AI vendor agreements found no provisions governing training "
                "data use, retention limits, or deletion on contract termination. Client data submitted to AI "
                "tools may persist in vendor training pipelines. GOVERN-5.1 requires contractual controls on "
                "AI system data lifecycle.",
                "GOVERN-5.1",
                [{"framework": _AIGO, "control_id": "GOVERN-5.1"}],
                "Amend or re-negotiate AI vendor contracts to include: prohibition on training data use from "
                "firm inputs, data deletion within 30 days of contract termination, and audit rights. "
                "Engage outside counsel to review DPA adequacy.",
            ),
            (
                "law.policy.jurisdiction_gaps",
                "medium",
                "Firm AI policy lacks jurisdiction-specific restrictions on AI in legal practice",
                "The AI use policy does not address state bar guidance. As of the assessment date, 6 states and "
                "the EU AI Act impose disclosure or competence obligations on AI-assisted legal work. "
                "GOVERN-6.2 requires policies to account for applicable legal and regulatory constraints.",
                "GOVERN-6.2",
                [{"framework": _AIGO, "control_id": "GOVERN-6.2"}],
                "Map active matter jurisdictions against state bar AI opinions and EU AI Act obligations. "
                "Update the AI use policy with jurisdiction-specific guidance and assign a partner responsible "
                "for monitoring regulatory developments quarterly.",
            ),
            (
                "law.access.personal_ai_accounts",
                "medium",
                "Staff using personal ChatGPT/AI accounts for firm work",
                "Interviews with three practice group leads confirm associates routinely use personal (free-tier) "
                "ChatGPT accounts for drafting and research. Personal accounts lack enterprise data controls, "
                "audit logging, or data isolation. NIST AI RMF MAP-3.1 requires identification of data at risk "
                "from AI system deployment context.",
                "MAP-3.1",
                [{"framework": _AIGO, "control_id": "MAP-3.1"}],
                "Block consumer ChatGPT via DNS filtering and conditional access policy. Provision firm-managed "
                "AI tools with contractual DPA and attorney-client privilege protections as the approved "
                "alternative.",
            ),
            (
                "law.disclosure.client_not_notified",
                "low",
                "AI assistance in work product not disclosed to clients as required by 6 state bars",
                "The firm does not have a standard disclosure template for AI-assisted work product. "
                "6 state bars (FL, CA, NY, TX, IL, CO) have issued guidance requiring client disclosure "
                "of material AI use. GOVERN-3.1 requires transparency mechanisms for AI-affected stakeholders.",
                "GOVERN-3.1",
                [{"framework": _AIGO, "control_id": "GOVERN-3.1"}],
                "Develop an AI disclosure addendum for engagement letters and matter-specific communications. "
                "Work with the ethics partner to define materiality thresholds for disclosure requirements.",
            ),
            (
                "law.measure.conflict_check_currency",
                "low",
                "Conflict-check AI tool relies on training data without currency disclosure",
                "The conflict-check AI tool's training data cutoff is 18 months prior to the assessment date. "
                "Recent lateral hires and matter history are not reflected. No disclosure to users about the "
                "data currency limitation. NIST AI RMF MEASURE-1.1 requires documentation of AI system "
                "limitations for operators.",
                "MEASURE-1.1",
                [{"framework": _AIGO, "control_id": "MEASURE-1.1"}],
                "Display a training data cutoff notice in the conflict-check UI. Implement a supplemental manual "
                "check for matters within the gap window. Negotiate a contract update with the vendor for "
                "quarterly training data refreshes.",
            ),
        ],
    }

    finding_specs_raw = _FINDING_SPECS.get(tenant.tenant_id, [])
    findings = []
    for ftype, severity, title, desc, nist_control, fw_maps, remediation in finding_specs_raw:
        finding = create_finding(
            db,
            tenant_id=tenant.tenant_id,
            engagement_id=eng.id,
            finding_type=ftype,
            source_ref=f"{tenant.tenant_id}:{ftype}",
            severity=severity,
            title=title,
            description=desc,
            source_attribution=f"demo_seed:{tenant.tenant_id}",
            confidence_score=88,
            framework_mappings=fw_maps,
            nist_ai_rmf_mappings=[{"control_id": nist_control}],
            evidence_ref_ids=[primary_scan.id, primary_doc.id, primary_obs.id],
            remediation_hint=remediation,
        )
        findings.append(finding)
        _link(db, tenant_id=tenant.tenant_id, engagement_id=eng.id, source_type="normalized_finding", source_id=finding.id, evidence_type="scan_result", evidence_id=primary_scan.id)
        _link(db, tenant_id=tenant.tenant_id, engagement_id=eng.id, source_type="normalized_finding", source_id=finding.id, evidence_type="document_analysis", evidence_id=primary_doc.id)
        _link(db, tenant_id=tenant.tenant_id, engagement_id=eng.id, source_type="normalized_finding", source_id=finding.id, evidence_type="field_observation", evidence_id=primary_obs.id)

    q, _created = get_or_create_questionnaire(
        db,
        tenant_id=tenant.tenant_id,
        engagement_id=eng.id,
        assessor_id="demo_seed",
    )
    if q.status == "draft":
        for idx, response in enumerate(list_responses(db, questionnaire_id=q.id, tenant_id=tenant.tenant_id)):
            if idx % 7 == 0:
                status = "partial"
            elif idx % 11 == 0:
                status = "not_applicable"
            else:
                status = "implemented"
            update_response(
                db,
                questionnaire_id=q.id,
                control_id=response.control_id,
                tenant_id=tenant.tenant_id,
                engagement_id=eng.id,
                response_status=status,
                evidence_text=(
                    f"Demo evidence for {tenant.client_name}: {response.control_name}. "
                    "Evidence comes from seeded connector-shaped outputs, document register, and structured observations."
                ),
                confidence_score=0.86,
                assessor_id="demo_seed",
            )
        submit_questionnaire(db, questionnaire_id=q.id, tenant_id=tenant.tenant_id, engagement_id=eng.id, actor="demo_seed")

    report = _upsert_report(db, tenant, eng.id, findings)
    now = _now_iso()
    eng.status = "delivered"
    eng.updated_at = now
    report.qa_approved_by = "FrostGate Demo QA"
    report.qa_approved_at = now
    db.flush()
    try:
        promote_engagement_to_governance(
            db,
            tenant_id=tenant.tenant_id,
            engagement_id=eng.id,
            gate_snapshot={"demo_seed": True, "readiness_score": 100},
            baseline_readiness_score=100,
        )
    except Exception:
        set_tenant_context(db, tenant.tenant_id)
    return eng.id, report.id


def _upsert_report(db: Session, tenant: DemoTenant, engagement_id: str, findings: list[Any]) -> GovernanceReportRecord:
    import json as _json

    report_id = f"{tenant.tenant_id}-report-v1"
    generated_at = _now_iso()
    concerns = [f.title for f in findings if f.severity in {"medium", "high", "critical"}]
    report_json = {
        "report_id": report_id,
        "assessment_id": engagement_id,
        "tenant_id": tenant.tenant_id,
        "engagement_id": engagement_id,
        "report_type": "executive_summary",
        "version": 1,
        "schema_version": "1.0",
        "generated_at": generated_at,
        "executive_summary": {
            "narrative": (
                f"{tenant.client_name} demo assessment is delivered with tenant-scoped evidence, "
                "normalized findings, NIST AI RMF questionnaire coverage, and a portal grant. "
                "The data is synthetic but uses evidence categories FrostGate can collect or register in live work."
            ),
            "risk_posture": "medium" if concerns else "low",
            "key_concerns": concerns,
            "generation_note": "Demo report generated by tools/seed/demo_tenants.py.",
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "source_attribution": f.source_attribution,
                "remediation_hint": f.remediation_hint,
            }
            for f in findings
        ],
    }
    canonical = _json.dumps(report_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    manifest_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    section_hashes = {
        "executive_summary": _sha256_json(report_json["executive_summary"]),
        "findings": _sha256_json(report_json["findings"]),
    }
    signature = None
    try:
        from services.governance.report.signing import sign_report

        signature = sign_report(canonical)
    except Exception:
        signature = None

    existing = db.execute(
        select(GovernanceReportRecord).where(
            GovernanceReportRecord.id == report_id,
            GovernanceReportRecord.tenant_id == tenant.tenant_id,
        )
    ).scalar_one_or_none()
    if existing:
        if existing.is_finalized:
            # Postgres trigger blocks manifest_hash / report_json updates on
            # finalized reports — skip update and return as-is.
            return existing
        existing.assessment_id = engagement_id
        existing.engagement_id = engagement_id
        existing.version = 1
        existing.report_type = "executive_summary"
        existing.compiled_by = "demo_seed"
        existing.manifest_hash = manifest_hash
        existing.report_json = report_json
        existing.section_hashes = section_hashes
        existing.signature = signature
        existing.generated_at = generated_at
        existing.is_finalized = True
        db.flush()
        return existing
    record = GovernanceReportRecord(
        id=report_id,
        assessment_id=engagement_id,
        tenant_id=tenant.tenant_id,
        engagement_id=engagement_id,
        version=1,
        schema_version="1.0",
        report_type="executive_summary",
        compiled_by="demo_seed",
        manifest_hash=manifest_hash,
        report_json=report_json,
        section_hashes=section_hashes,
        signature=signature,
        generated_at=generated_at,
        is_finalized=True,
    )
    db.add(record)
    db.flush()
    return record


def _create_portal_grant(db: Session, tenant: DemoTenant, engagement_id: str) -> tuple[str, str, str]:
    now_iso = _now_iso()
    active = db.execute(
        select(PortalGrant).where(
            PortalGrant.tenant_id == tenant.tenant_id,
            PortalGrant.engagement_id == engagement_id,
            PortalGrant.status == "active",
            PortalGrant.revoked_at.is_(None),
        )
    ).scalars().all()
    for grant in active:
        grant.status = "revoked"
        grant.revoked_at = now_iso
        grant.revoked_by = "demo_seed_rotate"
    db.flush()
    result = portal_grant_svc.create_grant(
        db,
        tenant_id=tenant.tenant_id,
        client_id=tenant.client_name,
        engagement_id=engagement_id,
        created_by="demo_seed",
        ttl_days=365,
    )
    return result.grant.id, result.raw_secret, result.grant.expires_at


def _ensure_tenant_user(db: Session, tenant: DemoTenant) -> None:
    email = f"{tenant.portal_username}@demo.frostgate.ai"
    existing = db.execute(
        select(TenantUser).where(
            TenantUser.tenant_id == tenant.tenant_id,
            TenantUser.email == email,
        )
    ).scalar_one_or_none()
    if existing:
        existing.display_name = tenant.client_name
        existing.role = "viewer"
        existing.active = True
        existing.updated_at = _now()
        db.flush()
        return
    db.add(
        TenantUser(
            id=f"{tenant.tenant_id}-portal-user",
            tenant_id=tenant.tenant_id,
            email=email,
            display_name=tenant.client_name,
            role="viewer",
            active=True,
        )
    )
    db.flush()


def _table_has_column(table_name: str, column_name: str) -> bool:
    engine = get_engine()
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            row = conn.execute(
                text("SELECT 1 FROM information_schema.columns WHERE table_name = :table AND column_name = :column"),
                {"table": table_name, "column": column_name},
            ).first()
            return row is not None
        rows = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
        return any(row[1] == column_name for row in rows)


def _create_demo_api_key(tenant: DemoTenant, *, force_rotate: bool = False) -> tuple[str | None, str]:
    """Return (raw_key, status) where status is 'created', 'rotated', or 'unchanged'.

    When status is 'unchanged' raw_key is None — the plaintext was never stored
    and can't be recovered.  The caller should preserve the existing Vercel value.
    Pass force_rotate=True to explicitly replace the key (e.g. suspected compromise).
    """
    name = "demo-bff-key"
    engine = get_engine()

    if not force_rotate:
        # Check for an already-enabled key; if found, skip rotation entirely.
        if engine.dialect.name == "postgresql":
            with engine.begin() as conn:
                conn.execute(text("SELECT set_config('app.tenant_id', :tenant_id, true)"), {"tenant_id": tenant.tenant_id})
                row = conn.execute(
                    text("SELECT 1 FROM api_keys WHERE tenant_id = :tid AND name = :name AND enabled = true LIMIT 1"),
                    {"tid": tenant.tenant_id, "name": name},
                ).first()
            if row is not None:
                return None, "unchanged"
        else:
            SessionLocal = get_sessionmaker()
            with SessionLocal() as db:
                set_tenant_context(db, tenant.tenant_id)
                existing = db.execute(
                    select(ApiKey).where(
                        ApiKey.tenant_id == tenant.tenant_id,
                        ApiKey.name == name,
                        ApiKey.enabled.is_(True),
                    )
                ).scalar_one_or_none()
            if existing is not None:
                return None, "unchanged"

    now_i = int(time.time())
    exp_i = now_i + 365 * 24 * 60 * 60
    secret = secrets.token_urlsafe(32)
    token = _b64url(
        json.dumps(
            {"scopes": list(DEMO_SCOPES), "tenant_id": tenant.tenant_id, "iat": now_i, "exp": exp_i},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    key_hash, hash_alg, hash_params, key_lookup = hash_key(secret)
    raw_key = f"fgk.{token}.{secret}"
    is_rotate = force_rotate

    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('app.tenant_id', :tenant_id, true)"), {"tenant_id": tenant.tenant_id})
            conn.execute(
                text("UPDATE api_keys SET enabled = false WHERE tenant_id = :tenant_id AND name = :name"),
                {"tenant_id": tenant.tenant_id, "name": name},
            )
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('app.tenant_id', :tenant_id, true)"), {"tenant_id": tenant.tenant_id})
            conn.execute(
                text(
                    """
                    INSERT INTO api_keys
                      (name, prefix, key_hash, key_lookup, hash_alg, hash_params,
                       scopes_csv, enabled, tenant_id, created_at, expires_at,
                       version, use_count)
                    VALUES
                      (:name, :prefix, :key_hash, :key_lookup, :hash_alg, CAST(:hash_params AS jsonb),
                       :scopes_csv, :enabled, :tenant_id, :created_at, :expires_at,
                       :version, :use_count)
                    """
                ),
                {
                    "name": name,
                    "prefix": "fgk",
                    "key_hash": key_hash,
                    "key_lookup": key_lookup,
                    "hash_alg": hash_alg,
                    "hash_params": json.dumps(hash_params, sort_keys=True, separators=(",", ":")),
                    "scopes_csv": ",".join(DEMO_SCOPES),
                    "enabled": True,
                    "tenant_id": tenant.tenant_id,
                    "created_at": datetime.fromtimestamp(now_i, tz=timezone.utc),
                    "expires_at": datetime.fromtimestamp(exp_i, tz=timezone.utc),
                    "version": 1,
                    "use_count": 0,
                },
            )
        if _table_has_column("api_keys", "role"):
            with engine.begin() as conn:
                conn.execute(text("SELECT set_config('app.tenant_id', :tenant_id, true)"), {"tenant_id": tenant.tenant_id})
                conn.execute(
                    text("UPDATE api_keys SET role = 'tenant_admin' WHERE tenant_id = :tenant_id AND key_lookup = :key_lookup"),
                    {"tenant_id": tenant.tenant_id, "key_lookup": key_lookup},
                )
        return raw_key, "rotated" if is_rotate else "created"

    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        set_tenant_context(db, tenant.tenant_id)
        rows = db.execute(
            select(ApiKey).where(ApiKey.tenant_id == tenant.tenant_id, ApiKey.name == name)
        ).scalars().all()
        for row in rows:
            row.enabled = False
        db.add(
            ApiKey(
                name=name,
                prefix="fgk",
                key_hash=key_hash,
                key_lookup=key_lookup,
                hash_alg=hash_alg,
                hash_params=hash_params,
                scopes_csv=",".join(DEMO_SCOPES),
                enabled=True,
                tenant_id=tenant.tenant_id,
                expires_at=datetime.fromtimestamp(exp_i, tz=timezone.utc),
                created_by="demo_seed",
                description="Demo BFF tenant key",
            )
        )
        db.commit()
    return raw_key, "rotated" if is_rotate else "created"


def seed(*, dry_run: bool, rotate_keys: bool = False) -> dict[str, Any]:
    if dry_run:
        return {
            "dry_run": True,
            "tenants": [tenant.__dict__ for tenant in DEMO_TENANTS],
            "would_create": ["tenant API keys", "delivered engagements", "reports", "portal grants"],
        }

    reset_engine_cache()
    SessionLocal = get_sessionmaker()
    output: dict[str, Any] = {
        "generated_at": _now_iso(),
        "portal_demo_tenants": ",".join(t.tenant_id for t in DEMO_TENANTS),
        "console_demo_tenants": ",".join(t.tenant_id for t in DEMO_TENANTS),
        "tenants": [],
    }
    new_key_map: dict[str, str] = {}
    unchanged_tenants: list[str] = []
    for tenant in DEMO_TENANTS:
        api_key, key_status = _create_demo_api_key(tenant, force_rotate=rotate_keys)
        if api_key is not None:
            new_key_map[tenant.tenant_id] = api_key
        else:
            unchanged_tenants.append(tenant.tenant_id)
        with SessionLocal() as db:
            set_tenant_context(db, tenant.tenant_id)
            engagement_id, report_id = _seed_assessment(db, tenant)
            _ensure_tenant_user(db, tenant)
            grant_id, portal_secret, portal_expires_at = _create_portal_grant(db, tenant, engagement_id)
            db.commit()
        output["tenants"].append(
            {
                "tenant_id": tenant.tenant_id,
                "tenant_label": tenant.tenant_label,
                "client_name": tenant.client_name,
                "sector": tenant.sector,
                "assessment_type": tenant.assessment_type,
                "engagement_id": engagement_id,
                "report_id": report_id,
                "status": "delivered",
                "api_key_status": key_status,
                "portal_username": tenant.portal_username,
                "portal_password": portal_secret,
                "portal_grant_id": grant_id,
                "portal_grant_expires_at": portal_expires_at,
                "portal_url": f"https://app.frostgate.ai/login?tenant_id={tenant.tenant_id}",
                "console_url": f"https://console.frostgate.ai/field-assessment/{engagement_id}?tenant_id={tenant.tenant_id}",
            }
        )
    if new_key_map:
        output["demo_tenant_api_key_map_json"] = json.dumps(new_key_map, sort_keys=True)
        output["demo_tenant_api_key_note"] = (
            "Update FG_PORTAL_DEMO_TENANT_KEYS in Vercel with this JSON (merge with existing if some keys are unchanged)."
        )
    if unchanged_tenants:
        output["demo_tenant_unchanged_keys"] = unchanged_tenants
        output["demo_tenant_unchanged_note"] = (
            "These tenants already have an active API key — existing Vercel value is still valid. "
            "Run with --rotate-keys to force rotation."
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed FrostGate demo tenants")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rotate-keys", action="store_true", help="Force-rotate API keys even if an active key exists")
    parser.add_argument("--output", default="", help="Optional path for credentials JSON")
    args = parser.parse_args()
    result = seed(dry_run=args.dry_run, rotate_keys=args.rotate_keys)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
