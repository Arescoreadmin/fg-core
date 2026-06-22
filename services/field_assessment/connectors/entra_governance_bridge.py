"""Import bridge — Entra ID Governance scan result → Field Assessment DB."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result


BRIDGE_VERSION = "field-assessment-entra-governance-bridge-v1"
CONNECTOR_TYPE = "entra_governance"
SCHEMA_VERSION = "1.0"

_FINDING_NIST: dict[str, list[dict[str, str]]] = {
    # PIM / role assignment findings → GOVERN 1.2 (roles + responsibilities)
    "permanent_global_admin": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "excessive_global_admins": [{"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"}],
    "permanent_privileged_role": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "stale_pim_eligible_assignment": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"}
    ],
    # Access review findings
    "no_access_reviews_configured": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
    "access_reviews_missing_privileged_roles": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"}
    ],
    "non_recurring_access_reviews": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"}
    ],
    # Identity protection findings
    "unmediated_high_risk_users": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"},
    ],
    "unmediated_medium_risk_users": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}
    ],
    # Conditional access findings
    "no_conditional_access_policies": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "ca_policies_report_only": [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"}],
    "legacy_auth_not_blocked": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "no_mfa_conditional_access": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
}

_DEFAULT_NIST = [{"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"}]

_SEVERITY_CONFIDENCE: dict[str, int] = {
    "critical": 95,
    "high": 90,
    "medium": 85,
    "low": 80,
    "info": 70,
}


@dataclass(frozen=True)
class EntraGovernanceImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    findings_imported: int
    role_assignments_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_entra_governance_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> EntraGovernanceImportResult:
    _ = actor
    role_assignments = scan_result.get("role_assignments") or []
    raw_findings = scan_result.get("findings") or []

    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=SCHEMA_VERSION,
        collected_at=scan_result.get("scan_initiated_at") or utc_iso8601_z_now(),
        raw_payload=scan_result,
        normalized_payload={
            "role_assignments": role_assignments,
            "findings": raw_findings,
            "summary": scan_result.get("summary", {}),
        },
        object_count=len(role_assignments),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "entra_governance.finding")
        nist = _FINDING_NIST.get(finding_type, _DEFAULT_NIST)
        fm = [{"framework": m["framework"], "control": m["control"]} for m in nist]
        severity = str(raw.get("severity") or "medium")
        confidence = _SEVERITY_CONFIDENCE.get(severity, 85)

        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"entra_governance.{finding_type}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=severity,
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"entra_governance:{scan_record.id}",
            confidence_score=confidence,
            framework_mappings=fm,
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint="",
        )
        imported += 1

    return EntraGovernanceImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        findings_imported=imported,
        role_assignments_scanned=len(role_assignments),
    )
