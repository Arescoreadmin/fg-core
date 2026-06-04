"""Import bridge — AI Data Access Mapping result -> Field Assessment DB.

Not standalone. Requires the fg-core API, auth layer, and Postgres substrate.
This module is called by the API route after the mapping engine produces its output.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result

BRIDGE_VERSION = "field-assessment-ai-data-access-mapping-bridge-v1"
CONNECTOR_TYPE = "ai_data_access_mapping"
SCHEMA_VERSION = "1.0"

_FINDING_NIST: dict[str, list[dict[str, str]]] = {
    "critical_data_access": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "tenant_wide_sensitive_access": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
    "sensitive_data_access": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "multi_category_sensitive_access": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
    "unverified_sensitive_access": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
}

_SEVERITY_CONFIDENCE: dict[str, int] = {
    "critical": 94,
    "high": 89,
    "medium": 83,
    "low": 75,
    "info": 65,
}


@dataclass(frozen=True)
class AiDataAccessMappingImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    tools_mapped: int
    findings_imported: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_ai_data_access_mapping_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> AiDataAccessMappingImportResult:
    _ = actor
    mappings = scan_result.get("mappings") or []
    raw_findings = scan_result.get("findings") or []
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
            "mappings": mappings,
            "findings": raw_findings,
            "summary": summary,
        },
        object_count=len(mappings),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "ai_data_access.finding")
        nist = _FINDING_NIST.get(
            finding_type,
            [
                {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
                {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
            ],
        )
        severity = str(raw.get("severity") or "info")
        confidence = _SEVERITY_CONFIDENCE.get(severity, 75)
        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"ai_data_access.{finding_type}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=severity,
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"ai_data_access_mapping:{scan_record.id}",
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
        imported += 1

    return AiDataAccessMappingImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        tools_mapped=len(mappings),
        findings_imported=imported,
    )
