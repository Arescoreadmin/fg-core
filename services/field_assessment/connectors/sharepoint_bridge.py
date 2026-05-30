"""Import bridge — SharePoint & OneDrive Data Exposure scan result → Field Assessment DB."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result


BRIDGE_VERSION = "field-assessment-sharepoint-bridge-v1"
CONNECTOR_TYPE = "sharepoint_onedrive"
SCHEMA_VERSION = "1.0"

_FINDING_NIST: dict[str, list[dict[str, str]]] = {
    "anonymous_sharing_links": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
    ],
    "external_user_sharing": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "sharing_links_no_expiry": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "org_wide_sharing": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
    ],
    "sharing_baseline_clean": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
}

_DEFAULT_NIST = [{"framework": "NIST-AI-RMF", "control": "MAP 1.1"}]

_SEVERITY_CONFIDENCE: dict[str, int] = {
    "critical": 92,
    "high": 88,
    "medium": 82,
    "low": 75,
    "info": 65,
}


@dataclass(frozen=True)
class SharepointImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    findings_imported: int
    sites_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_sharepoint_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> SharepointImportResult:
    _ = actor
    sites = scan_result.get("sites") or []
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
            "sites": sites,
            "findings": raw_findings,
            "summary": summary,
        },
        object_count=len(sites),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "sharepoint.finding")
        # Skip informational baseline-clean findings — no actionable remediation
        if finding_type == "sharing_baseline_clean":
            continue
        nist = _FINDING_NIST.get(finding_type, _DEFAULT_NIST)
        fm = [{"framework": m["framework"], "control": m["control"]} for m in nist]
        severity = str(raw.get("severity") or "medium")
        confidence = _SEVERITY_CONFIDENCE.get(severity, 82)

        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"sharepoint.{finding_type}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=severity,
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"sharepoint_onedrive:{scan_record.id}",
            confidence_score=confidence,
            framework_mappings=fm,
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint="",
        )
        imported += 1

    return SharepointImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        findings_imported=imported,
        sites_scanned=len(sites),
    )
