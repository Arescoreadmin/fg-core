"""Import bridge — AI Vendor Governance → Field Assessment DB (PR 4).

Not standalone. This module is not standalone. It requires the fg-core API,
auth layer, and Postgres substrate.

Reads existing PR 3 (External AI Risk Register) scan results and generates
FaAiVendorGovernanceRecord entries with an append-only
FaAiVendorGovernanceDecision for the initial governance_initiated action.

Idempotency:
  stable_ts = pr3_scan.collected_at
  → compute_evidence_hash(raw_payload)
  → create_scan_result dedup on (engagement_id, tenant_id, evidence_hash)
  → upsert governance records preserving exception_granted workflow_state
  → create_finding dedup via findings_hash

Exception preservation:
  workflow_state="exception_granted" is never overwritten on re-scan.
  All other states are re-evaluated from PR3 evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.connectors.ai_vendor_governance.governance_engine import (
    compute_governance_readiness,
)
from services.connectors.ai_vendor_governance.state_machine import (
    determine_initial_state,
)
from services.field_assessment.store import (
    create_finding,
    create_scan_result,
)

BRIDGE_VERSION = "field-assessment-ai-vendor-governance-bridge-v1"
CONNECTOR_TYPE = "ai_vendor_governance"
SCHEMA_VERSION = "1.0"

_SEVERITY_CONFIDENCE: dict[str, int] = {
    "critical": 94,
    "high": 89,
    "moderate": 83,
    "low": 75,
    "info": 65,
}


@dataclass(frozen=True)
class AiVendorGovernanceImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    records_imported: int
    findings_imported: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_ai_vendor_governance(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: Any,
) -> AiVendorGovernanceImportResult:
    """Persist governance records and findings; create FaScanResult for evidence chain.

    scan_result must be produced by the route handler which reads PR3 data
    and calls the governance engine. This bridge is the H12/H13/H15 wiring layer.
    """
    _ = actor
    governance_records: list[dict[str, Any]] = (
        scan_result.get("governance_records") or []
    )
    raw_findings: list[dict[str, Any]] = scan_result.get("findings") or []
    summary = scan_result.get("summary", {})

    # stable_ts from PR3 scan for deterministic evidence_hash
    stable_ts = scan_result.get("scan_completed_at") or utc_iso8601_z_now()

    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=SCHEMA_VERSION,
        collected_at=stable_ts,
        raw_payload=scan_result,
        normalized_payload={
            "governance_records": governance_records,
            "findings": raw_findings,
            "summary": summary,
        },
        object_count=len(governance_records),
    )

    _upsert_governance_records(
        db, governance_records, scan_record.id, tenant_id, engagement_id
    )

    imported_findings = 0
    finding_ids: list[str] = []
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "ai_vendor_governance.finding")
        nist_raw = raw.get("nist_controls") or [
            {"framework": "NIST-AI-RMF", "control": "GOVERN 1.1"},
        ]
        severity = str(raw.get("severity") or "info")
        confidence = _SEVERITY_CONFIDENCE.get(severity, 75)
        finding = create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=finding_type,
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}:{raw.get('tool_name', '')}",
            severity=severity,
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"ai_vendor_governance:{scan_record.id}",
            confidence_score=confidence,
            framework_mappings=[
                {
                    "framework": m["framework"],
                    "control_id": m["control"],
                    "control_ref": m["control"],
                }
                for m in nist_raw
            ],
            nist_ai_rmf_mappings=nist_raw,
            evidence_ref_ids=[scan_record.id],
            remediation_hint=str(raw.get("recommendation") or ""),
        )
        finding_ids.append(finding.id)
        imported_findings += 1

    if finding_ids:
        _backfill_finding_refs(db, governance_records, finding_ids, scan_record.id)

    return AiVendorGovernanceImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        records_imported=len(governance_records),
        findings_imported=imported_findings,
    )


def _upsert_governance_records(
    db: Session,
    governance_records: list[dict[str, Any]],
    scan_result_id: str,
    tenant_id: str,
    engagement_id: str,
) -> None:
    """Insert or update FaAiVendorGovernanceRecord rows idempotently."""
    from api.db_models_ai_vendor_governance import (
        FaAiVendorGovernanceDecision,
        FaAiVendorGovernanceRecord,
    )

    now = utc_iso8601_z_now()
    for rec in governance_records:
        tool_name = str(rec.get("tool_name") or "unknown")

        existing = (
            db.query(FaAiVendorGovernanceRecord)
            .filter_by(
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                tool_name=tool_name,
            )
            .first()
        )

        if existing:
            # Preserve exception_granted — operator-set, not overwritable by re-scan
            if existing.workflow_state != "exception_granted":
                # Re-evaluate initial state from latest PR3 evidence
                new_state = determine_initial_state(
                    rec.get("business_owner"), rec.get("technical_owner")
                )
                # Only regress to needs_owner/discovered if currently unreviewed
                if existing.workflow_state in (
                    "discovered",
                    "needs_owner",
                    "needs_review",
                ):
                    existing.workflow_state = new_state

            # Update deterministic fields from latest PR3 evidence
            existing.risk_score = rec.get("risk_score", existing.risk_score)
            existing.risk_categories = rec.get(
                "risk_categories", existing.risk_categories
            )
            existing.regulatory_flags = rec.get(
                "regulatory_flags", existing.regulatory_flags
            )
            existing.data_processed = rec.get("data_processed", existing.data_processed)
            existing.sensitive_data_types = rec.get(
                "sensitive_data_types", existing.sensitive_data_types
            )
            existing.regulated_data_present = rec.get(
                "regulated_data_present", existing.regulated_data_present
            )
            existing.source_scan_result_id = scan_result_id
            existing.pr3_risk_record_id = rec.get(
                "pr3_risk_record_id", existing.pr3_risk_record_id
            )
            existing.updated_at = now

            # Recompute governance_readiness from current record state
            record_dict = {
                "business_owner": existing.business_owner,
                "technical_owner": existing.technical_owner,
                "security_review_status": existing.security_review_status,
                "dpa_required": existing.dpa_required,
                "dpa_status": existing.dpa_status,
                "baa_required": existing.baa_required,
                "baa_status": existing.baa_status,
                "risk_acceptance_required": existing.risk_acceptance_required,
                "risk_acceptance_status": existing.risk_acceptance_status,
                "review_due_date": existing.review_due_date,
            }
            existing.governance_readiness = compute_governance_readiness(record_dict)
        else:
            row = FaAiVendorGovernanceRecord(
                id=rec["id"],
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                vendor=rec.get("vendor", ""),
                tool_name=tool_name,
                tool_id=rec.get("tool_id"),
                target_type=rec.get("target_type", "ai_tool"),
                workflow_state=rec.get("workflow_state", "discovered"),
                business_owner=rec.get("business_owner"),
                technical_owner=rec.get("technical_owner"),
                executive_sponsor=None,
                business_justification=None,
                business_process=None,
                department=None,
                criticality="unknown",
                data_processed=rec.get("data_processed", []),
                sensitive_data_types=rec.get("sensitive_data_types", []),
                regulated_data_present=rec.get("regulated_data_present", False),
                data_residency_notes=None,
                contract_status="unknown",
                contract_owner=None,
                contract_expiration=None,
                renewal_date=None,
                dpa_required=False,
                dpa_status="unknown",
                dpa_review_date=None,
                baa_required=False,
                baa_status="unknown",
                baa_review_date=None,
                security_review_status="not_started",
                security_review_date=None,
                security_reviewer=None,
                privacy_review_status="not_started",
                privacy_review_date=None,
                privacy_reviewer=None,
                soc2_available=False,
                soc2_reviewed=False,
                soc2_review_date=None,
                iso27001_available=False,
                iso27001_reviewed=False,
                iso_review_date=None,
                risk_acceptance_required=rec.get("risk_acceptance_required", False),
                risk_acceptance_status="unknown",
                risk_acceptance_owner=None,
                risk_acceptance_expiration=None,
                review_due_date=None,
                last_review_date=None,
                renewal_due_date=None,
                retirement_date=None,
                governance_readiness=rec.get("governance_readiness", "unknown"),
                pr1_scan_result_id=rec.get("pr1_scan_result_id"),
                pr2_scan_result_id=rec.get("pr2_scan_result_id"),
                pr3_risk_record_id=rec.get("pr3_risk_record_id"),
                risk_score=rec.get("risk_score", "unknown"),
                risk_categories=rec.get("risk_categories", []),
                regulatory_flags=rec.get("regulatory_flags", []),
                evidence_refs=rec.get("evidence_refs", []),
                finding_refs=[],
                graph_node_id=rec.get("graph_node_id"),
                vendor_node_id=rec.get("vendor_node_id"),
                owner_node_id=rec.get("owner_node_id"),
                contract_node_id=rec.get("contract_node_id"),
                evidence_node_id=rec.get("evidence_node_id"),
                decision_node_id=rec.get("decision_node_id"),
                governance_node_id=rec.get("governance_node_id"),
                source_scan_result_id=scan_result_id,
                created_at=now,
                updated_at=now,
                last_reviewed_at=None,
            )
            db.add(row)
            db.flush()

            # Append governance_initiated decision for audit trail
            decision = FaAiVendorGovernanceDecision(
                decision_id=f"dec:{rec['id']}:init",
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                governance_record_id=rec["id"],
                vendor=rec.get("vendor", ""),
                tool_name=tool_name,
                target_type=rec.get("target_type", "ai_tool"),
                decision="governance_initiated",
                reason="Initial governance record created from PR3 risk evidence.",
                previous_state=None,
                new_state=rec.get("workflow_state", "discovered"),
                actor_id=None,
                actor_name="system",
                actor_email=None,
                evidence_refs=rec.get("evidence_refs", []),
                notes=None,
                exception_expiration=None,
                created_at=now,
            )
            db.add(decision)

    db.flush()


def _backfill_finding_refs(
    db: Session,
    governance_records: list[dict[str, Any]],
    finding_ids: list[str],
    scan_result_id: str,
) -> None:
    """Write finding_ids back into the corresponding governance records."""
    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    now = utc_iso8601_z_now()
    for rec in governance_records:
        tool_name = str(rec.get("tool_name") or "unknown")
        tenant_id = str(rec.get("tenant_id") or "")
        engagement_id = str(rec.get("engagement_id") or "")
        existing = (
            db.query(FaAiVendorGovernanceRecord)
            .filter_by(
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                tool_name=tool_name,
            )
            .first()
        )
        if existing:
            existing.finding_refs = list(
                set(list(existing.finding_refs or []) + finding_ids)
            )
            existing.updated_at = now
    db.flush()
