"""Import bridge — External AI Risk Register -> Field Assessment DB.

Not standalone. This module is not standalone. It requires the fg-core API, auth layer, and Postgres substrate.
This module is called by the API route after the risk engine produces its output.

Creates or updates FaExternalAiRiskRecord rows (idempotent via uq_fa_ext_ai_risk_tool).
Creates FaNormalizedFinding rows for high/critical risks.
Creates a FaScanResult record (source_type="external_ai_risk_register") for the bundle.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result


def _compute_age_days(first_detected_at: str, now: str) -> int:
    """Return whole days between two ISO 8601 UTC timestamps."""
    try:
        t0 = datetime.fromisoformat(first_detected_at.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(now.replace("Z", "+00:00"))
        return max(0, (t1 - t0).days)
    except (ValueError, AttributeError):
        return 0


BRIDGE_VERSION = "field-assessment-external-ai-risk-register-bridge-v1"
CONNECTOR_TYPE = "external_ai_risk_register"
SCHEMA_VERSION = "1.0"

_FINDING_NIST: dict[str, list[dict[str, str]]] = {
    "external_ai_risk.critical": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
    "external_ai_risk.high": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
}

_SEVERITY_CONFIDENCE: dict[str, int] = {
    "critical": 94,
    "high": 89,
    "moderate": 83,
    "low": 75,
    "info": 65,
}


@dataclass(frozen=True)
class ExternalAiRiskImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    risks_imported: int
    findings_imported: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_external_ai_risk_register(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> ExternalAiRiskImportResult:
    """Persist risk records and findings; create FaScanResult for evidence chain."""
    _ = actor
    risk_records: list[dict[str, Any]] = scan_result.get("risk_records") or []
    raw_findings: list[dict[str, Any]] = scan_result.get("findings") or []
    summary = scan_result.get("summary", {})

    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=SCHEMA_VERSION,
        collected_at=scan_result.get("scan_completed_at") or utc_iso8601_z_now(),
        raw_payload=scan_result,
        normalized_payload={
            "risk_records": risk_records,
            "findings": raw_findings,
            "summary": summary,
        },
        object_count=len(risk_records),
    )

    _upsert_risk_records(db, risk_records, scan_record.id)

    imported_findings = 0
    finding_ids: list[str] = []
    tool_finding_map: dict[str, list[str]] = {}
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "external_ai_risk.finding")
        nist = _FINDING_NIST.get(
            finding_type,
            [
                {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
                {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
            ],
        )
        severity = str(raw.get("severity") or "info")
        confidence = _SEVERITY_CONFIDENCE.get(severity, 75)
        finding = create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"external_ai_risk.{finding_type.split('.')[-1]}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=severity,
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"external_ai_risk_register:{scan_record.id}",
            confidence_score=confidence,
            framework_mappings=[
                {
                    "framework": m["framework"],
                    "control_id": m["control"],
                    "control_ref": m["control"],
                }
                for m in nist
            ],
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint=str(raw.get("recommendation") or ""),
        )
        finding_ids.append(finding.id)
        tool_key = str(raw.get("tool_name") or "")
        if tool_key:
            tool_finding_map.setdefault(tool_key, []).append(finding.id)
        imported_findings += 1

    # Back-reference finding IDs into risk records (per-tool, not global)
    if tool_finding_map:
        _backfill_finding_refs(db, risk_records, tool_finding_map, scan_record.id)

    return ExternalAiRiskImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        risks_imported=len(risk_records),
        findings_imported=imported_findings,
    )


def _upsert_risk_records(
    db: Session,
    risk_records: list[dict[str, Any]],
    scan_result_id: str,
) -> None:
    """Insert or update FaExternalAiRiskRecord rows via ON CONFLICT DO UPDATE."""
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord

    now = utc_iso8601_z_now()
    for rec in risk_records:
        tool_name = str(rec.get("tool_name") or "unknown")
        tenant_id = str(rec.get("tenant_id") or "")
        engagement_id = str(rec.get("engagement_id") or "")

        existing = (
            db.query(FaExternalAiRiskRecord)
            .filter_by(
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                tool_name=tool_name,
            )
            .first()
        )
        if existing:
            # Preserve all operator-mutable fields; update everything generated at scan time.
            existing.tool_id = rec.get("tool_id")
            existing.vendor = str(rec.get("vendor") or "unknown")
            existing.permissions = list(rec.get("permissions") or [])
            existing.data_access_summary = rec.get("data_access_summary")
            existing.sensitive_data_exposure = list(
                rec.get("sensitive_data_exposure") or []
            )
            existing.publisher_trust = str(rec.get("publisher_trust") or "unknown")
            existing.user_count = rec.get("user_count")
            existing.admin_consent = bool(rec.get("admin_consent"))
            existing.risk_score = str(rec.get("risk_score") or "low")
            existing.risk_reason = str(rec.get("risk_reason") or "")
            existing.risk_category = str(
                rec.get("risk_category") or "no_approval_record"
            )
            existing.risk_categories = list(rec.get("risk_categories") or [])
            existing.recommended_action = str(rec.get("recommended_action") or "")
            existing.evidence_refs = list(rec.get("evidence_refs") or [])
            existing.graph_node_id = rec.get("graph_node_id")
            existing.risk_node_id = rec.get("risk_node_id")
            existing.owner_node_id = rec.get("owner_node_id")
            existing.vendor_node_id = rec.get("vendor_node_id")
            existing.decision_node_id = rec.get("decision_node_id")
            existing.governance_node_id = rec.get("governance_node_id")
            existing.source_scan_result_id = (
                rec.get("source_scan_result_id") or scan_result_id
            )
            existing.pr1_scan_result_id = rec.get("pr1_scan_result_id")
            # Governance state: update from scan unless operator granted exception
            if existing.governance_state != "exception_granted":
                existing.governance_state = str(
                    rec.get("governance_state") or "unknown"
                )
            # Regulatory flags: always update (deterministic)
            existing.regulatory_flags = list(rec.get("regulatory_flags") or [])
            # Vendor status: update if still at default (future PR 3.5 may set these)
            if existing.vendor_review_status == "not_reviewed":
                existing.vendor_review_status = str(
                    rec.get("vendor_review_status") or "not_reviewed"
                )
            # Risk aging: preserve first_detected_at, update last_observed_at
            existing.last_observed_at = now
            if existing.first_detected_at:
                existing.risk_age_days = _compute_age_days(
                    existing.first_detected_at, now
                )
            existing.updated_at = now
        else:
            row = FaExternalAiRiskRecord(
                id=str(rec.get("id") or ""),
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                tool_id=rec.get("tool_id"),
                tool_name=tool_name,
                vendor=str(rec.get("vendor") or "unknown"),
                business_owner=str(rec.get("business_owner") or "Unknown"),
                technical_owner=str(rec.get("technical_owner") or "Unknown"),
                # Addition 1 — ownership defaults
                risk_owner=None,
                owner_type="Unknown",
                permissions=list(rec.get("permissions") or []),
                data_access_summary=rec.get("data_access_summary"),
                sensitive_data_exposure=list(rec.get("sensitive_data_exposure") or []),
                publisher_trust=str(rec.get("publisher_trust") or "unknown"),
                user_count=rec.get("user_count"),
                admin_consent=bool(rec.get("admin_consent")),
                risk_score=str(rec.get("risk_score") or "low"),
                risk_reason=str(rec.get("risk_reason") or ""),
                risk_category=str(rec.get("risk_category") or "no_approval_record"),
                risk_categories=list(rec.get("risk_categories") or []),
                recommended_action=str(rec.get("recommended_action") or ""),
                review_status="unreviewed",
                # Addition 2 — governance state (deterministic at generation)
                governance_state=str(rec.get("governance_state") or "unknown"),
                # Addition 3 — decision linkage (empty at generation)
                decision_refs=[],
                risk_acceptance_refs=[],
                exception_refs=[],
                approval_refs=[],
                # Addition 4 — vendor governance status (defaults; future PR 3.5)
                vendor_review_status=str(
                    rec.get("vendor_review_status") or "not_reviewed"
                ),
                vendor_dpa_status="unknown",
                vendor_baa_status="unknown",
                vendor_security_review_status="unknown",
                vendor_last_reviewed_at=None,
                # Addition 5 — regulatory flags (deterministic at generation)
                regulatory_flags=list(rec.get("regulatory_flags") or []),
                # Addition 6 — risk aging (first detection = now)
                risk_age_days=0,
                first_detected_at=now,
                last_observed_at=now,
                last_reviewed_at=None,
                # Addition 7 — remediation (not started at generation)
                remediation_status="not_started",
                remediation_target_date=None,
                remediation_completed_at=None,
                evidence_refs=list(rec.get("evidence_refs") or []),
                finding_refs=[],
                graph_node_id=rec.get("graph_node_id"),
                # Addition 10 — graph node identifiers
                risk_node_id=rec.get("risk_node_id"),
                owner_node_id=rec.get("owner_node_id"),
                vendor_node_id=rec.get("vendor_node_id"),
                decision_node_id=rec.get("decision_node_id"),
                governance_node_id=rec.get("governance_node_id"),
                source_scan_result_id=rec.get("source_scan_result_id")
                or scan_result_id,
                pr1_scan_result_id=rec.get("pr1_scan_result_id"),
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            try:
                db.flush()
            except IntegrityError:
                db.rollback()


def _backfill_finding_refs(
    db: Session,
    risk_records: list[dict[str, Any]],
    tool_finding_map: dict[str, list[str]],
    scan_result_id: str,
) -> None:
    """Attach per-tool finding IDs back to the risk records that generated them."""
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord

    now = utc_iso8601_z_now()
    for rec in risk_records:
        if rec.get("risk_score") not in ("critical", "high"):
            continue
        tool_name = str(rec.get("tool_name") or "")
        tenant_id = str(rec.get("tenant_id") or "")
        engagement_id = str(rec.get("engagement_id") or "")
        tool_findings = tool_finding_map.get(tool_name, [])
        if not tool_findings:
            continue
        existing = (
            db.query(FaExternalAiRiskRecord)
            .filter_by(
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                tool_name=tool_name,
            )
            .first()
        )
        if existing:
            existing.finding_refs = list(
                set(list(existing.finding_refs or []) + tool_findings)
            )
            existing.updated_at = now
