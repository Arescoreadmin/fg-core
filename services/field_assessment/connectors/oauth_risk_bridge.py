"""Import bridge — OAuth Risk Deep Scan result → Field Assessment DB."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result


BRIDGE_VERSION = "field-assessment-oauth-risk-bridge-v1"
CONNECTOR_TYPE = "oauth_risk"
SCHEMA_VERSION = "1.0"

_FINDING_NIST: dict[str, list[dict[str, str]]] = {
    # Illicit consent → GOVERN 1.2 (roles/responsibilities) + GOVERN 6.2 (third-party access)
    "illicit_consent_grant_critical": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
    "illicit_consent_grant_high": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
    ],
    # AI tool OAuth access → MAP 1.1 (data inventory) + GOVERN 6.2
    "ai_tool_oauth_data_access": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
    ],
    # Over-privileged app permissions → GOVERN 1.2 + MANAGE 2.4
    "critical_application_permissions": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "high_application_permissions": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    # Unverified publisher → GOVERN 6.2 (third-party risk)
    "unverified_publisher_sensitive_access": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
}

_DEFAULT_NIST = [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]

_SEVERITY_CONFIDENCE: dict[str, int] = {
    "critical": 94,
    "high": 89,
    "medium": 83,
    "low": 75,
    "info": 65,
}


@dataclass(frozen=True)
class OauthRiskImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    findings_imported: int
    grants_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_oauth_risk_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> OauthRiskImportResult:
    _ = actor
    grants = scan_result.get("grants") or []
    raw_findings = scan_result.get("findings") or []
    summary = scan_result.get("summary", {})

    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=SCHEMA_VERSION,
        collected_at=scan_result.get("scan_initiated_at") or utc_iso8601_z_now(),
        raw_payload=scan_result,
        normalized_payload={
            "grants": grants,
            "findings": raw_findings,
            "summary": summary,
        },
        object_count=len(grants),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "oauth_risk.finding")
        nist = _FINDING_NIST.get(finding_type, _DEFAULT_NIST)
        fm = [{"framework": m["framework"], "control": m["control"]} for m in nist]
        severity = str(raw.get("severity") or "high")
        confidence = _SEVERITY_CONFIDENCE.get(severity, 83)

        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"oauth_risk.{finding_type}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=severity,
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"oauth_risk:{scan_record.id}",
            confidence_score=confidence,
            framework_mappings=fm,
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint="",
        )
        imported += 1

    return OauthRiskImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        findings_imported=imported,
        grants_scanned=len(grants),
    )
