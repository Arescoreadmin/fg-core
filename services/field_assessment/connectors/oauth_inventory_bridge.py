"""Import bridge — OAuth Inventory scan result → Field Assessment DB."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result


BRIDGE_VERSION = "field-assessment-oauth-inventory-bridge-v1"
CONNECTOR_TYPE = "oauth_inventory"
SCHEMA_VERSION = "1.0"

_NIST_MAP: dict[str, list[dict[str, str]]] = {
    "NIST-AI-RMF-GOVERN-1.2": [{"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"}],
    "NIST-AI-RMF-MAP-1.1": [{"framework": "NIST-AI-RMF", "control": "MAP 1.1"}],
    "NIST-AI-RMF-MANAGE-1.1": [{"framework": "NIST-AI-RMF", "control": "MANAGE 1.1"}],
}


@dataclass(frozen=True)
class OauthInventoryImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    findings_imported: int
    apps_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_oauth_inventory_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> OauthInventoryImportResult:
    _ = actor
    apps = scan_result.get("apps") or []
    raw_findings = scan_result.get("findings") or []

    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=SCHEMA_VERSION,
        collected_at=scan_result.get("scan_completed_at") or utc_iso8601_z_now(),
        raw_payload=scan_result,
        normalized_payload={"apps": apps, "findings": raw_findings},
        object_count=len(apps),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("finding_type") or "oauth.finding")
        control_id = str(raw.get("control_id") or "NIST-AI-RMF-GOVERN-1.2")
        fm = [
            {
                "framework": "NIST-AI-RMF",
                "control": control_id.replace("NIST-AI-RMF-", ""),
            }
        ]
        nist = _NIST_MAP.get(control_id, fm)
        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=finding_type,
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=str(raw.get("severity") or "medium"),
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"oauth_inventory:{scan_record.id}",
            confidence_score=75,
            framework_mappings=fm,
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint=str(raw.get("recommendation") or ""),
        )
        imported += 1

    return OauthInventoryImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        findings_imported=imported,
        apps_scanned=len(apps),
    )
