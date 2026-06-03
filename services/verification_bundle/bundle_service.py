"""PR 52: VerificationBundleService — verification bundle generation.

A verification bundle captures a deterministic, hashed snapshot of all 9
engagement components at a point in time. It supports:

  - SHA-256 hashes per component for integrity verification
  - Tamper detection (broken evidence refs, orphaned governance objects)
  - Manifest for auditor-facing verification without full data download

Components (9):
  1. manifest        — bundle metadata
  2. findings        — FaNormalizedFinding records
  3. evidence        — FaEvidenceLink records
  4. interviews      — FaFieldObservation where observation_type='interview'
  5. decisions       — FaGovernanceDecision records
  6. risk_acceptances — FaRiskAcceptance records
  7. exceptions      — FaGovernanceException records
  8. audit_trail     — FaScanAuditEvent records (last 500)
  9. report          — GovernanceReportRecord (latest finalized version)

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
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaEvidenceLink,
    FaFieldObservation,
    FaNormalizedFinding,
    FaScanAuditEvent,
)
from api.db_models_governance_decision import (
    FaGovernanceDecision,
    FaGovernanceException,
    FaRiskAcceptance,
)
from api.db_models_governance_report import GovernanceReportRecord
from api.db_models_verification_bundle import FaVerificationBundle
from services.canonical import utc_iso8601_z_now

_AUDIT_EVENT_LIMIT = 500


def _sha256_of(data: Any) -> str:
    """SHA-256 of the canonical JSON representation of data."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


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

        Collects all 9 components, hashes each, runs tamper detection, computes
        the overall bundle hash, and writes one FaVerificationBundle record.
        Returns the new record (unflushed but added to session — caller commits).
        """
        now = utc_iso8601_z_now()
        bundle_id = uuid.uuid4().hex[:32]

        # ── 1. Findings ──────────────────────────────────────────────────────
        findings = db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == engagement_id,
                FaNormalizedFinding.tenant_id == tenant_id,
            )
        ).scalars().all()
        finding_ids = {f.id for f in findings}
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
        evidence_links = db.execute(
            select(FaEvidenceLink).where(
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.tenant_id == tenant_id,
            )
        ).scalars().all()
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
        interviews = db.execute(
            select(FaFieldObservation).where(
                FaFieldObservation.engagement_id == engagement_id,
                FaFieldObservation.tenant_id == tenant_id,
                FaFieldObservation.observation_type == "interview",
                FaFieldObservation.deleted_at.is_(None),
            )
        ).scalars().all()
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
        decisions = db.execute(
            select(FaGovernanceDecision).where(
                FaGovernanceDecision.engagement_id == engagement_id,
                FaGovernanceDecision.tenant_id == tenant_id,
            )
        ).scalars().all()
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
        risk_acceptances = db.execute(
            select(FaRiskAcceptance).where(
                FaRiskAcceptance.engagement_id == engagement_id,
                FaRiskAcceptance.tenant_id == tenant_id,
            )
        ).scalars().all()
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
        exceptions = db.execute(
            select(FaGovernanceException).where(
                FaGovernanceException.engagement_id == engagement_id,
                FaGovernanceException.tenant_id == tenant_id,
            )
        ).scalars().all()
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

        # ── 7. Audit trail (last 500 events) ──────────────────────────────────
        audit_events = db.execute(
            select(FaScanAuditEvent)
            .where(
                FaScanAuditEvent.engagement_id == engagement_id,
                FaScanAuditEvent.tenant_id == tenant_id,
            )
            .order_by(FaScanAuditEvent.created_at.desc())
            .limit(_AUDIT_EVENT_LIMIT)
        ).scalars().all()
        audit_data = [
            {
                "id": ev.id,
                "event_type": ev.event_type,
                "actor": ev.actor,
                "created_at": ev.created_at,
            }
            for ev in audit_events
        ]
        audit_hash = _sha256_of(sorted([a["id"] for a in audit_data]))

        # ── 8. Report (latest finalized version) ──────────────────────────────
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

        # ── 9. Tamper detection ───────────────────────────────────────────────
        tamper_issues: list[str] = []

        # Broken finding evidence refs — ref IDs that don't exist in evidence_ids
        for f in findings:
            for ref_id in (f.evidence_ref_ids or []):
                if ref_id not in evidence_ids:
                    tamper_issues.append(
                        f"finding:{f.id} references non-existent evidence:{ref_id}"
                    )

        # Orphaned risk acceptances — decision_id not in this engagement's decisions
        for ra in risk_acceptances:
            if ra.decision_id not in decision_ids:
                tamper_issues.append(
                    f"risk_acceptance:{ra.id} references orphaned decision:{ra.decision_id}"
                )

        # Orphaned exceptions — same check
        for ex in exceptions:
            if ex.decision_id not in decision_ids:
                tamper_issues.append(
                    f"exception:{ex.id} references orphaned decision:{ex.decision_id}"
                )

        # ── 10. Determine verification status ─────────────────────────────────
        if tamper_issues:
            verification_status = "tamper_detected"
        elif not has_report:
            verification_status = "incomplete"
        else:
            verification_status = "verified"

        # ── 11. Assemble manifest ─────────────────────────────────────────────
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
                "name": "audit_trail",
                "count": len(audit_events),
                "hash": audit_hash,
            },
            {
                "name": "report",
                "count": 1 if has_report else 0,
                "hash": report_hash,
            },
        ]

        manifest = {
            "bundle_id": bundle_id,
            "engagement_id": engagement_id,
            "tenant_id": tenant_id,
            "generated_at": now,
            "generated_by": actor_id,
            "verification_status": verification_status,
            "components": component_summary,
        }
        manifest_hash = _sha256_of(manifest)

        bundle_doc = {
            "manifest": manifest,
            "manifest_hash": manifest_hash,
        }
        bundle_hash = _sha256_of(bundle_doc)

        # ── 12. Persist ───────────────────────────────────────────────────────
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
            audit_event_count=len(audit_events),
            has_report=has_report,
            tamper_details=json.dumps(tamper_issues) if tamper_issues else None,
            component_summary=json.dumps(component_summary),
            bundle_json=json.dumps(bundle_doc),
        )
        db.add(record)
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


verification_bundle_svc = VerificationBundleService()
