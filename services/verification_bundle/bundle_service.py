"""PR 52.5: VerificationBundleService — regulatory-grade verification bundle generation.

A verification bundle captures a deterministic, hashed snapshot of all engagement
components at a point in time. PR 52.5 adds regulatory-defensible hardening:

  - SHA-256 hashes per component for integrity verification
  - Tamper detection (broken evidence refs, orphaned governance objects,
    evidence_snapshot_hash mismatches on governance decisions)
  - coverage_status field (complete/partial/missing_report/missing_evidence/
    missing_decisions/tampered)
  - Engagement audit events as a separate bundle component (H2)
  - Bundle signature metadata record — attribution metadata, not cryptographic (H4)
  - report_artifact_hash + report_artifact_hash_status (H5)
  - chain_of_custody component from FaEvidenceLifecycleEvent + FaLegalHold (H6)
  - H14 evidence_snapshot_hash validation against current evidence state (H7)
  - regulatory_context manifest section (H9)
  - governance_activity chronological timeline (H10)
  - Offline verification package (ZIP with manifest.json, bundle.json,
    verification_report.json) + pure verify_bundle_file() (H3)
  - Manifest for auditor-facing verification without full data download

Components captured:
  1. manifest              — bundle metadata
  2. findings              — FaNormalizedFinding records
  3. evidence              — FaEvidenceLink records
  4. interviews            — FaFieldObservation where observation_type='interview'
  5. decisions             — FaGovernanceDecision records
  6. risk_acceptances      — FaRiskAcceptance records
  7. exceptions            — FaGovernanceException records
  8. scan_audit_trail      — FaScanAuditEvent records (last 500)
  9. engagement_audit_trail — FaEngagementAuditEvent records (all)
 10. chain_of_custody      — FaEvidenceLifecycleEvent + FaLegalHold per evidence item
 11. report                — GovernanceReportRecord (latest finalized version)

Verification status:
  verified         — all checks pass, report present
  incomplete       — no finalized report for this engagement yet
  tamper_detected  — one or more integrity issues found

Not standalone — coordinates with:
  - H13 (AuditAtomicityService) for audit event atomicity
  - H14 (GovernanceDecisionService) for governance decision ledger
  - H15 (EvidenceLifecycleService) for evidence chain-of-custody
"""

from __future__ import annotations

import hashlib
import io
import json
import uuid
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaEngagement,
    FaEngagementAuditEvent,
    FaEvidenceLifecycleEvent,
    FaEvidenceLink,
    FaFieldObservation,
    FaLegalHold,
    FaNormalizedFinding,
    FaScanAuditEvent,
)
from api.db_models_governance_decision import (
    FaGovernanceDecision,
    FaGovernanceException,
    FaRiskAcceptance,
)
from api.db_models_external_ai_risk import FaExternalAiRiskRecord
from api.db_models_governance_report import GovernanceReportRecord
from api.db_models_verification_bundle import FaVerificationBundle
from services.canonical import utc_iso8601_z_now

_AUDIT_EVENT_LIMIT = 500
_GOVERNANCE_ACTIVITY_LIMIT = 200


def _sha256_of(data: Any) -> str:
    """SHA-256 of the canonical JSON representation of data."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _coverage_status(
    *,
    has_report: bool,
    evidence_count: int,
    decision_count: int,
    finding_count: int,
    tamper_issues: list[str],
) -> str:
    if tamper_issues:
        return "tampered"
    if not has_report:
        return "missing_report"
    if evidence_count == 0:
        return "missing_evidence"
    if decision_count == 0:
        return "missing_decisions"
    if finding_count == 0:
        return "partial"
    return "complete"


class BundleNotFound(Exception):
    pass


class VerificationBundleService:
    """Single write authority for verification bundle generation."""

    def generate_bundle(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        actor_id: str,
    ) -> FaVerificationBundle:
        """Generate and persist a verification bundle for an engagement.

        Collects all components, hashes each, runs tamper detection (including
        evidence snapshot validation), computes coverage_status, and writes one
        FaVerificationBundle record.
        Returns the new record (unflushed but added to session — caller commits).
        """
        now = utc_iso8601_z_now()
        bundle_id = uuid.uuid4().hex[:32]

        # ── Engagement metadata (for regulatory_context) ──────────────────────
        engagement_obj = db.execute(
            select(FaEngagement).where(
                FaEngagement.id == engagement_id,
                FaEngagement.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        eng_meta = engagement_obj.engagement_metadata if engagement_obj else {}

        # ── 1. Findings ───────────────────────────────────────────────────────
        findings = (
            db.execute(
                select(FaNormalizedFinding).where(
                    FaNormalizedFinding.engagement_id == engagement_id,
                    FaNormalizedFinding.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        findings_data = [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "status": f.status,
                "findings_hash": f.findings_hash,
                "evidence_ref_ids": f.evidence_ref_ids or [],
            }
            for f in findings
        ]
        findings_hash = _sha256_of(sorted([f["id"] for f in findings_data]))

        # ── 2. Evidence links ─────────────────────────────────────────────────
        evidence_links = (
            db.execute(
                select(FaEvidenceLink).where(
                    FaEvidenceLink.engagement_id == engagement_id,
                    FaEvidenceLink.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        evidence_ids = {e.id for e in evidence_links}
        evidence_data = [
            {
                "id": e.id,
                "source_entity_type": e.source_entity_type,
                "source_entity_id": e.source_entity_id,
                "evidence_entity_type": e.evidence_entity_type,
                "evidence_entity_id": e.evidence_entity_id,
            }
            for e in evidence_links
        ]
        evidence_hash = _sha256_of(sorted([e["id"] for e in evidence_data]))

        # ── 3. Interviews ─────────────────────────────────────────────────────
        interviews = (
            db.execute(
                select(FaFieldObservation).where(
                    FaFieldObservation.engagement_id == engagement_id,
                    FaFieldObservation.tenant_id == tenant_id,
                    FaFieldObservation.observation_type == "interview",
                    FaFieldObservation.deleted_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        interviews_data = [
            {
                "id": obs.id,
                "interview_role": obs.interview_role,
                "created_at": obs.created_at,
            }
            for obs in interviews
        ]
        interviews_hash = _sha256_of(sorted([i["id"] for i in interviews_data]))

        # ── 4. Governance decisions ───────────────────────────────────────────
        decisions = (
            db.execute(
                select(FaGovernanceDecision).where(
                    FaGovernanceDecision.engagement_id == engagement_id,
                    FaGovernanceDecision.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        decision_ids = {d.id for d in decisions}
        decisions_data = [
            {
                "id": d.id,
                "decision_type": d.decision_type,
                "entity_type": d.entity_type,
                "entity_id": d.entity_id,
                "actor_id": d.actor_id,
                "decision_at": d.decision_at,
            }
            for d in decisions
        ]
        decisions_hash = _sha256_of(sorted([d["id"] for d in decisions_data]))

        # ── 5. Risk acceptances ───────────────────────────────────────────────
        risk_acceptances = (
            db.execute(
                select(FaRiskAcceptance).where(
                    FaRiskAcceptance.engagement_id == engagement_id,
                    FaRiskAcceptance.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        ra_data = [
            {
                "id": ra.id,
                "decision_id": ra.decision_id,
                "finding_id": ra.finding_id,
                "status": ra.status,
                "expires_at": ra.expires_at,
            }
            for ra in risk_acceptances
        ]
        risk_acceptances_hash = _sha256_of(sorted([r["id"] for r in ra_data]))

        # ── 6. Exceptions ─────────────────────────────────────────────────────
        exceptions = (
            db.execute(
                select(FaGovernanceException).where(
                    FaGovernanceException.engagement_id == engagement_id,
                    FaGovernanceException.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        exc_data = [
            {
                "id": ex.id,
                "decision_id": ex.decision_id,
                "exception_type": ex.exception_type,
                "status": ex.status,
                "expires_at": ex.expires_at,
            }
            for ex in exceptions
        ]
        exceptions_hash = _sha256_of(sorted([e["id"] for e in exc_data]))

        # ── 7. Scan audit trail (last 500 events) ─────────────────────────────
        scan_audit_events = (
            db.execute(
                select(FaScanAuditEvent)
                .where(
                    FaScanAuditEvent.engagement_id == engagement_id,
                    FaScanAuditEvent.tenant_id == tenant_id,
                )
                .order_by(FaScanAuditEvent.created_at.desc())
                .limit(_AUDIT_EVENT_LIMIT)
            )
            .scalars()
            .all()
        )
        scan_audit_data = [
            {
                "id": ev.id,
                "event_type": ev.event_type,
                "actor": ev.actor,
                "created_at": ev.created_at,
            }
            for ev in scan_audit_events
        ]
        scan_audit_hash = _sha256_of(sorted([a["id"] for a in scan_audit_data]))

        # ── 8. Engagement audit trail (H2 — separate from scan audit) ─────────
        eng_audit_events = (
            db.execute(
                select(FaEngagementAuditEvent).where(
                    FaEngagementAuditEvent.engagement_id == engagement_id,
                    FaEngagementAuditEvent.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        eng_audit_data = [
            {
                "id": ev.id,
                "event_type": ev.event_type,
                "actor": ev.actor,
                "created_at": ev.created_at,
            }
            for ev in eng_audit_events
        ]
        eng_audit_hash = _sha256_of(sorted([a["id"] for a in eng_audit_data]))

        # ── 9. Chain of custody (H6) ──────────────────────────────────────────
        lifecycle_events = (
            db.execute(
                select(FaEvidenceLifecycleEvent).where(
                    FaEvidenceLifecycleEvent.engagement_id == engagement_id,
                    FaEvidenceLifecycleEvent.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        legal_holds = (
            db.execute(
                select(FaLegalHold).where(
                    FaLegalHold.engagement_id == engagement_id,
                    FaLegalHold.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        # Determine active legal holds per evidence item
        hold_applied: set[tuple[str, str]] = set()
        for lh in sorted(legal_holds, key=lambda x: x.created_at):
            key = (lh.evidence_type, lh.evidence_id)
            if lh.action == "applied":
                hold_applied.add(key)
            else:
                hold_applied.discard(key)

        # Group lifecycle events by (evidence_type, evidence_id)
        lce_by_evidence: dict[tuple[str, str], list] = defaultdict(list)
        for lce in lifecycle_events:
            lce_by_evidence[(lce.evidence_type, lce.evidence_id)].append(lce)

        chain_of_custody = []
        for (ev_type, ev_id), events in sorted(lce_by_evidence.items()):
            sorted_events = sorted(events, key=lambda e: e.created_at)
            latest = sorted_events[-1]
            locked_at = next(
                (e.created_at for e in sorted_events if e.new_state == "locked"), None
            )
            chain_of_custody.append(
                {
                    "evidence_type": ev_type,
                    "evidence_id": ev_id,
                    "lifecycle_state": latest.new_state,
                    "locked_at": locked_at,
                    "legal_hold": (ev_type, ev_id) in hold_applied,
                    "event_count": len(events),
                    "event_ids": [e.id for e in sorted_events],
                }
            )
        chain_of_custody_hash = _sha256_of(
            sorted([c["evidence_id"] for c in chain_of_custody])
        )

        # ── 10. AI Risk Register records ──────────────────────────────────────
        ai_risk_records = (
            db.execute(
                select(FaExternalAiRiskRecord).where(
                    FaExternalAiRiskRecord.engagement_id == engagement_id,
                    FaExternalAiRiskRecord.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        ai_risk_data = [
            {
                "id": r.id,
                "tool_name": r.tool_name,
                "vendor": r.vendor,
                "risk_score": r.risk_score,
                "risk_category": r.risk_category,
                "risk_categories": r.risk_categories or [],
                "review_status": r.review_status,
                "business_owner": r.business_owner,
                "technical_owner": r.technical_owner,
                # Addition 1 — ownership
                "risk_owner": r.risk_owner,
                "owner_type": getattr(r, "owner_type", "Unknown"),
                # Addition 2 — governance state
                "governance_state": getattr(r, "governance_state", "unknown"),
                # Addition 3 — decision linkage
                "decision_refs": getattr(r, "decision_refs", None) or [],
                "risk_acceptance_refs": getattr(r, "risk_acceptance_refs", None) or [],
                "exception_refs": getattr(r, "exception_refs", None) or [],
                "approval_refs": getattr(r, "approval_refs", None) or [],
                # Addition 4 — vendor governance status
                "vendor_review_status": getattr(
                    r, "vendor_review_status", "not_reviewed"
                ),
                "vendor_dpa_status": getattr(r, "vendor_dpa_status", "unknown"),
                "vendor_baa_status": getattr(r, "vendor_baa_status", "unknown"),
                "vendor_last_reviewed_at": getattr(r, "vendor_last_reviewed_at", None),
                # Addition 5 — regulatory flags
                "regulatory_flags": getattr(r, "regulatory_flags", None) or [],
                # Addition 6 — risk aging
                "risk_age_days": getattr(r, "risk_age_days", None),
                "first_detected_at": getattr(r, "first_detected_at", None),
                "last_reviewed_at": getattr(r, "last_reviewed_at", None),
                # Addition 7 — remediation
                "remediation_status": getattr(r, "remediation_status", "not_started"),
                "evidence_refs": r.evidence_refs or [],
                "finding_refs": r.finding_refs or [],
                "graph_node_id": r.graph_node_id,
                # Addition 10 — graph node identifiers
                "risk_node_id": getattr(r, "risk_node_id", None),
                "vendor_node_id": getattr(r, "vendor_node_id", None),
                "governance_node_id": getattr(r, "governance_node_id", None),
            }
            for r in ai_risk_records
        ]
        ai_risk_hash = _sha256_of(sorted([r["id"] for r in ai_risk_data]))

        # ── 11. AI Vendor Governance records ─────────────────────────────────
        from api.db_models_ai_vendor_governance import (
            FaAiVendorGovernanceDecision,
            FaAiVendorGovernanceRecord,
        )

        gov_records = (
            db.execute(
                select(FaAiVendorGovernanceRecord).where(
                    FaAiVendorGovernanceRecord.engagement_id == engagement_id,
                    FaAiVendorGovernanceRecord.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        gov_data = [
            {
                "id": r.id,
                "vendor": r.vendor,
                "tool_name": r.tool_name,
                "target_type": getattr(r, "target_type", "ai_tool"),
                "workflow_state": r.workflow_state,
                "governance_readiness": r.governance_readiness,
                "business_owner": r.business_owner,
                "technical_owner": r.technical_owner,
                "executive_sponsor": getattr(r, "executive_sponsor", None),
                "dpa_status": getattr(r, "dpa_status", "unknown"),
                "baa_status": getattr(r, "baa_status", "unknown"),
                "contract_status": getattr(r, "contract_status", "unknown"),
                "security_review_status": getattr(
                    r, "security_review_status", "not_started"
                ),
                "privacy_review_status": getattr(
                    r, "privacy_review_status", "not_started"
                ),
                "soc2_available": getattr(r, "soc2_available", False),
                "iso27001_available": getattr(r, "iso27001_available", False),
                "risk_acceptance_status": getattr(
                    r, "risk_acceptance_status", "unknown"
                ),
                "risk_score": r.risk_score,
                "risk_categories": r.risk_categories or [],
                "regulatory_flags": r.regulatory_flags or [],
                "review_due_date": getattr(r, "review_due_date", None),
                "last_reviewed_at": getattr(r, "last_reviewed_at", None),
                "updated_at": r.updated_at,
            }
            for r in gov_records
        ]
        gov_hash = _sha256_of(sorted([r["id"] for r in gov_data]))

        gov_decisions = (
            db.execute(
                select(FaAiVendorGovernanceDecision).where(
                    FaAiVendorGovernanceDecision.engagement_id == engagement_id,
                    FaAiVendorGovernanceDecision.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )
        gov_decision_data = [
            {
                "decision_id": d.decision_id,
                "vendor": d.vendor,
                "tool_name": d.tool_name,
                "decision": d.decision,
                "previous_state": d.previous_state,
                "new_state": d.new_state,
                "actor_name": d.actor_name,
                "created_at": d.created_at,
            }
            for d in gov_decisions
        ]
        gov_decision_hash = _sha256_of(
            sorted([d["decision_id"] for d in gov_decision_data])
        )

        # ── 12. Report (latest finalized version) ─────────────────────────────
        report = db.execute(
            select(GovernanceReportRecord)
            .where(
                GovernanceReportRecord.assessment_id == engagement_id,
                GovernanceReportRecord.tenant_id == tenant_id,
                GovernanceReportRecord.is_finalized.is_(True),
            )
            .order_by(GovernanceReportRecord.version.desc())
            .limit(1)
        ).scalar_one_or_none()
        has_report = report is not None
        report_data = (
            {
                "id": report.id,
                "version": report.version,
                "manifest_hash": report.manifest_hash,
                "generated_at": report.generated_at,
            }
            if report
            else None
        )
        report_hash = _sha256_of(report_data)

        # H5 — report artifact hash
        if report is not None:
            report_artifact_hash = report.manifest_hash
            report_artifact_hash_status = "available"
        else:
            report_artifact_hash = None
            report_artifact_hash_status = "not_available"

        # ── 12. Tamper detection ──────────────────────────────────────────────
        tamper_issues: list[str] = []

        # Broken finding evidence refs
        for f in findings:
            for ref_id in f.evidence_ref_ids or []:
                if ref_id not in evidence_ids:
                    tamper_issues.append(
                        f"finding:{f.id} references non-existent evidence:{ref_id}"
                    )

        # Orphaned risk acceptances
        for ra in risk_acceptances:
            if ra.decision_id not in decision_ids:
                tamper_issues.append(
                    f"risk_acceptance:{ra.id} references orphaned decision:{ra.decision_id}"
                )

        # Orphaned exceptions
        for ex in exceptions:
            if ex.decision_id not in decision_ids:
                tamper_issues.append(
                    f"exception:{ex.id} references orphaned decision:{ex.decision_id}"
                )

        # H7 — evidence_snapshot_hash validation
        snapshot_validation_results: list[str] = []
        for d in decisions:
            if d.evidence_snapshot_hash is None:
                snapshot_validation_results.append(
                    f"decision:{d.id} snapshot_validation_unavailable"
                )
                continue
            try:
                refs = (
                    json.loads(d.evidence_refs)
                    if isinstance(d.evidence_refs, str)
                    else (d.evidence_refs or [])
                )
            except Exception:
                refs = []
            if not refs:
                snapshot_validation_results.append(
                    f"decision:{d.id} snapshot_validation_unavailable"
                )
                continue
            current_evidence = sorted(
                [e for e in evidence_links if e.id in refs], key=lambda e: e.id
            )
            current_hash = _sha256_of(
                [
                    {
                        "id": e.id,
                        "source_entity_type": e.source_entity_type,
                        "source_entity_id": e.source_entity_id,
                        "evidence_entity_type": e.evidence_entity_type,
                        "evidence_entity_id": e.evidence_entity_id,
                    }
                    for e in current_evidence
                ]
            )
            if current_hash != d.evidence_snapshot_hash:
                tamper_issues.append(f"decision:{d.id} evidence_snapshot_hash mismatch")

        # ── 13. Verification status ───────────────────────────────────────────
        if tamper_issues:
            verification_status = "tamper_detected"
        elif not has_report:
            verification_status = "incomplete"
        else:
            verification_status = "verified"

        # ── 14. Coverage status (H8) ──────────────────────────────────────────
        cov_status = _coverage_status(
            has_report=has_report,
            evidence_count=len(evidence_links),
            decision_count=len(decisions),
            finding_count=len(findings),
            tamper_issues=tamper_issues,
        )

        # ── 15. Regulatory context (H9) ───────────────────────────────────────
        all_framework_mappings: list[str] = []
        for f in findings:
            for fm in f.framework_mappings or []:
                if isinstance(fm, str) and fm not in all_framework_mappings:
                    all_framework_mappings.append(fm)
                elif isinstance(fm, dict):
                    label = fm.get("framework") or fm.get("id") or str(fm)
                    if label not in all_framework_mappings:
                        all_framework_mappings.append(label)

        regulatory_context = {
            "frameworks": eng_meta.get("frameworks", all_framework_mappings[:10]),
            "jurisdiction": eng_meta.get("jurisdiction"),
            "industry": eng_meta.get("industry"),
            "assessment_type": engagement_obj.assessment_type
            if engagement_obj
            else None,
            "generated_for": engagement_obj.client_name if engagement_obj else None,
        }

        # ── 16. Governance activity timeline (H10) ────────────────────────────
        gov_activity: list[dict] = []
        for d in decisions:
            gov_activity.append(
                {
                    "at": d.decision_at,
                    "type": f"governance.decision.{d.decision_type}",
                    "actor": d.actor_id,
                    "entity_type": d.entity_type,
                    "entity_id": d.entity_id,
                    "decision_id": d.id,
                }
            )
        for ra in risk_acceptances:
            gov_activity.append(
                {
                    "at": ra.created_at,
                    "type": "governance.risk_acceptance.created",
                    "finding_id": ra.finding_id,
                    "decision_id": ra.decision_id,
                    "status": ra.status,
                }
            )
        for ex in exceptions:
            gov_activity.append(
                {
                    "at": ex.created_at,
                    "type": "governance.exception.created",
                    "exception_type": ex.exception_type,
                    "decision_id": ex.decision_id,
                    "status": ex.status,
                }
            )
        for lh in legal_holds:
            gov_activity.append(
                {
                    "at": lh.created_at,
                    "type": f"evidence.legal_hold.{lh.action}",
                    "actor": lh.actor,
                    "evidence_type": lh.evidence_type,
                    "evidence_id": lh.evidence_id,
                }
            )
        for lce in lifecycle_events:
            if lce.new_state in ("locked", "legal_hold"):
                gov_activity.append(
                    {
                        "at": lce.created_at,
                        "type": f"evidence.lifecycle.{lce.new_state}",
                        "actor": lce.actor,
                        "evidence_type": lce.evidence_type,
                        "evidence_id": lce.evidence_id,
                    }
                )
        gov_activity.sort(key=lambda x: str(x.get("at", "")))
        gov_activity = gov_activity[:_GOVERNANCE_ACTIVITY_LIMIT]

        # ── 17. Assemble manifest ─────────────────────────────────────────────
        component_summary = [
            {"name": "findings", "count": len(findings), "hash": findings_hash},
            {"name": "evidence", "count": len(evidence_links), "hash": evidence_hash},
            {"name": "interviews", "count": len(interviews), "hash": interviews_hash},
            {"name": "decisions", "count": len(decisions), "hash": decisions_hash},
            {
                "name": "risk_acceptances",
                "count": len(risk_acceptances),
                "hash": risk_acceptances_hash,
            },
            {"name": "exceptions", "count": len(exceptions), "hash": exceptions_hash},
            {
                "name": "scan_audit_trail",
                "count": len(scan_audit_events),
                "hash": scan_audit_hash,
            },
            {
                "name": "engagement_audit_trail",
                "count": len(eng_audit_events),
                "hash": eng_audit_hash,
            },
            {
                "name": "chain_of_custody",
                "count": len(chain_of_custody),
                "hash": chain_of_custody_hash,
            },
            {
                "name": "ai_risk_register",
                "count": len(ai_risk_records),
                "hash": ai_risk_hash,
            },
            {
                "name": "ai_vendor_governance",
                "count": len(gov_records),
                "hash": gov_hash,
            },
            {
                "name": "ai_vendor_governance_decisions",
                "count": len(gov_decisions),
                "hash": gov_decision_hash,
            },
            {
                "name": "report",
                "count": 1 if has_report else 0,
                "hash": report_hash,
            },
        ]

        try:
            from services.field_assessment.trust_enforcement_adapter import (  # noqa: PLC0415
                derive_engagement_trust_inputs,
            )

            _bt = derive_engagement_trust_inputs(
                db, tenant_id=tenant_id, engagement_id=engagement_id
            )
            _trust_enforcement_section: dict = {
                "chain_valid": _bt.chain_valid,
                "signature_valid": _bt.signature_valid,
                "link_valid": _bt.link_valid,
                "replay_valid": _bt.replay_valid,
                "is_legacy": _bt.is_legacy,
            }
        except Exception:
            _trust_enforcement_section = {"error": "derivation_failed"}

        manifest = {
            "bundle_id": bundle_id,
            "engagement_id": engagement_id,
            "tenant_id": tenant_id,
            "generated_at": now,
            "generated_by": actor_id,
            "verification_status": verification_status,
            "coverage_status": cov_status,
            "components": component_summary,
            "regulatory_context": regulatory_context,
            "snapshot_validation": snapshot_validation_results,
            "trust_enforcement": _trust_enforcement_section,
        }
        manifest_hash = _sha256_of(manifest)

        # H4 — signature metadata (attribution record, not cryptographic)
        # Assembled after manifest_hash and bundle_hash are known
        # We set bundle_hash below; build a placeholder then overwrite after
        bundle_doc_partial = {
            "manifest": manifest,
            "manifest_hash": manifest_hash,
            "chain_of_custody": chain_of_custody,
            "governance_activity": gov_activity,
            "ai_risk_register": ai_risk_data,
            "ai_vendor_governance": gov_data,
            "ai_vendor_governance_decisions": gov_decision_data,
        }
        bundle_hash = _sha256_of(bundle_doc_partial)

        signature_metadata = {
            "generated_by": actor_id,
            "generated_by_email": None,
            "generated_by_role": None,
            "generated_at": now,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "bundle_hash": bundle_hash,
            "manifest_hash": manifest_hash,
            "signature_version": "1.0",
        }

        bundle_doc = {
            **bundle_doc_partial,
            "signature_metadata": signature_metadata,
        }

        # ── 18. Persist ───────────────────────────────────────────────────────
        record = FaVerificationBundle(
            id=bundle_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            bundle_hash=bundle_hash,
            manifest_hash=manifest_hash,
            verification_status=verification_status,
            generated_by=actor_id,
            generated_at=now,
            finding_count=len(findings),
            evidence_count=len(evidence_links),
            interview_count=len(interviews),
            decision_count=len(decisions),
            risk_acceptance_count=len(risk_acceptances),
            exception_count=len(exceptions),
            audit_event_count=len(scan_audit_events),
            has_report=has_report,
            engagement_audit_event_count=len(eng_audit_events),
            coverage_status=cov_status,
            report_artifact_hash=report_artifact_hash,
            report_artifact_hash_status=report_artifact_hash_status,
            chain_of_custody_count=len(chain_of_custody),
            signature_metadata=json.dumps(signature_metadata),
            regulatory_context=json.dumps(regulatory_context),
            governance_activity=json.dumps(gov_activity),
            tamper_details=json.dumps(tamper_issues) if tamper_issues else None,
            component_summary=json.dumps(component_summary),
            bundle_json=json.dumps(bundle_doc),
        )
        db.add(record)

        try:
            from services.trust_monitoring.timeline_emitter import (  # noqa: PLC0415
                emit_verification_bundle_generated,
            )

            emit_verification_bundle_generated(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                bundle_id=record.id,
                verification_status=record.verification_status,
                coverage_status=record.coverage_status,
                occurred_at=record.generated_at,
            )
        except Exception:
            import logging as _log  # noqa: PLC0415

            _log.getLogger("frostgate.tim.timeline").warning(
                "emit_verification_bundle_generated failed (non-blocking)",
                exc_info=True,
            )

        try:
            from services.trust_arc.orchestrator import generate_and_persist_trust_arc  # noqa: PLC0415

            generate_and_persist_trust_arc(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
            )
        except Exception:
            import logging as _log  # noqa: PLC0415

            _log.getLogger("frostgate.trust_arc").warning(
                "trust_arc generation failed during bundle generation (non-blocking)",
                exc_info=True,
            )

        return record

    def get_latest_bundle(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
    ) -> FaVerificationBundle | None:
        return db.execute(
            select(FaVerificationBundle)
            .where(
                FaVerificationBundle.engagement_id == engagement_id,
                FaVerificationBundle.tenant_id == tenant_id,
            )
            .order_by(FaVerificationBundle.generated_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    def export_bundle_zip(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
    ) -> bytes:
        """Build and return the offline verification ZIP for the latest bundle.

        The ZIP contains three files:
          manifest.json            — human-readable manifest section
          bundle.json              — full bundle document
          verification_report.json — self-contained verification summary

        Raises BundleNotFound if no bundle exists for the engagement.
        """
        bundle = self.get_latest_bundle(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )
        if bundle is None:
            raise BundleNotFound(
                f"No verification bundle for engagement {engagement_id}"
            )

        bundle_doc = json.loads(bundle.bundle_json)
        manifest = bundle_doc.get("manifest", {})

        verification_report = {
            "bundle_id": bundle.id,
            "bundle_hash": bundle.bundle_hash,
            "manifest_hash": bundle.manifest_hash,
            "verification_status": bundle.verification_status,
            "coverage_status": bundle.coverage_status,
            "generated_at": bundle.generated_at,
            "generated_by": bundle.generated_by,
            "report_artifact_hash": bundle.report_artifact_hash,
            "report_artifact_hash_status": bundle.report_artifact_hash_status,
            "tamper_details": (
                json.loads(bundle.tamper_details) if bundle.tamper_details else []
            ),
            "regulatory_context": (
                json.loads(bundle.regulatory_context)
                if bundle.regulatory_context
                else {}
            ),
            "component_counts": {
                "findings": bundle.finding_count,
                "evidence": bundle.evidence_count,
                "interviews": bundle.interview_count,
                "decisions": bundle.decision_count,
                "risk_acceptances": bundle.risk_acceptance_count,
                "exceptions": bundle.exception_count,
                "scan_audit_events": bundle.audit_event_count,
                "engagement_audit_events": bundle.engagement_audit_event_count,
                "chain_of_custody": bundle.chain_of_custody_count,
                "has_report": bundle.has_report,
            },
            "signature_metadata": (
                json.loads(bundle.signature_metadata)
                if bundle.signature_metadata
                else {}
            ),
        }

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
            zf.writestr("bundle.json", json.dumps(bundle_doc, indent=2, default=str))
            zf.writestr(
                "verification_report.json",
                json.dumps(verification_report, indent=2, default=str),
            )
        return buf.getvalue()


def verify_bundle_file(path_or_bytes: "str | bytes | Path") -> dict:
    """Pure offline verifier — no DB access required.

    Accepts a filesystem path (str/Path) or raw ZIP bytes. Returns:
      {
        "verified": bool,
        "tamper_detected": bool,
        "coverage_status": str,
        "issues": list[str],
      }
    """
    if isinstance(path_or_bytes, (str, Path)):
        with open(path_or_bytes, "rb") as fh:
            data = fh.read()
    else:
        data = path_or_bytes

    issues: list[str] = []
    coverage_status = "unknown"
    tamper_details: list[str] = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()

            if "bundle.json" not in names:
                issues.append("missing bundle.json")
                return {
                    "verified": False,
                    "tamper_detected": False,
                    "coverage_status": coverage_status,
                    "issues": issues,
                }

            bundle_doc = json.loads(zf.read("bundle.json"))
            recorded_manifest_hash = bundle_doc.get("manifest_hash")
            manifest = bundle_doc.get("manifest", {})

            # Re-derive manifest hash
            derived_manifest_hash = _sha256_of(manifest)
            if derived_manifest_hash != recorded_manifest_hash:
                issues.append(
                    f"manifest_hash mismatch: recorded={recorded_manifest_hash}, "
                    f"computed={derived_manifest_hash}"
                )

            # Re-derive bundle hash from partial doc (chain_of_custody, governance_activity)
            bundle_doc_for_hash = {
                "manifest": manifest,
                "manifest_hash": recorded_manifest_hash,
                "chain_of_custody": bundle_doc.get("chain_of_custody", []),
                "governance_activity": bundle_doc.get("governance_activity", []),
                "ai_risk_register": bundle_doc.get("ai_risk_register", []),
                "ai_vendor_governance": bundle_doc.get("ai_vendor_governance", []),
                "ai_vendor_governance_decisions": bundle_doc.get(
                    "ai_vendor_governance_decisions", []
                ),
            }
            derived_bundle_hash = _sha256_of(bundle_doc_for_hash)

            if "verification_report.json" in names:
                vr = json.loads(zf.read("verification_report.json"))
                recorded_bundle_hash = vr.get("bundle_hash")
                if recorded_bundle_hash and derived_bundle_hash != recorded_bundle_hash:
                    issues.append(
                        f"bundle_hash mismatch: recorded={recorded_bundle_hash}, "
                        f"computed={derived_bundle_hash}"
                    )
                coverage_status = vr.get("coverage_status", "unknown")
                tamper_details = vr.get("tamper_details", [])
            else:
                issues.append("missing verification_report.json")
                coverage_status = manifest.get("coverage_status", "unknown")

            if "manifest.json" not in names:
                issues.append("missing manifest.json")

    except Exception as exc:
        issues.append(f"zip parse error: {exc}")
        return {
            "verified": False,
            "tamper_detected": False,
            "coverage_status": coverage_status,
            "issues": issues,
        }

    tamper_detected = bool(tamper_details) or any("mismatch" in i for i in issues)
    verified = not issues and not tamper_detected
    return {
        "verified": verified,
        "tamper_detected": tamper_detected,
        "coverage_status": coverage_status,
        "issues": issues,
    }


verification_bundle_svc = VerificationBundleService()
