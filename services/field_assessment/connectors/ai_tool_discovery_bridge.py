"""Import bridge - AI Tool Discovery scan result -> Field Assessment DB."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result

BRIDGE_VERSION = "field-assessment-ai-tool-discovery-bridge-v1"
CONNECTOR_TYPE = "ai_tool_discovery"
SCHEMA_VERSION = "1.0"

_FINDING_NIST: dict[str, list[dict[str, str]]] = {
    "ai_tool_sensitive_permissions": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
    "ai_tool_unverified_publishers": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
}


@dataclass(frozen=True)
class AiToolDiscoveryImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    findings_imported: int
    tools_discovered: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_ai_tool_discovery_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> AiToolDiscoveryImportResult:
    _ = actor
    tools = scan_result.get("tools") or []
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
        normalized_payload={"tools": tools, "findings": raw_findings, "summary": summary},
        object_count=len(tools),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "ai_tool_discovery.finding")
        nist = _FINDING_NIST.get(finding_type, [{"framework": "NIST-AI-RMF", "control": "MAP 1.1"}])
        severity = str(raw.get("severity") or "info")
        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"ai_tool_discovery.{finding_type}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=severity,
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"ai_tool_discovery:{scan_record.id}",
            confidence_score=82 if severity in {"medium", "high"} else 72,
            framework_mappings=[{"framework": m["framework"], "control": m["control"]} for m in nist],
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint=str(raw.get("recommendation") or ""),
        )
        imported += 1

    return AiToolDiscoveryImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        findings_imported=imported,
        tools_discovered=len(tools),
    )
