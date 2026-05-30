"""Import bridge — Web Security Headers scan result → Field Assessment DB."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result


BRIDGE_VERSION = "field-assessment-web-headers-bridge-v1"
CONNECTOR_TYPE = "web_headers"
SCHEMA_VERSION = "1.0"

_FINDING_NIST: dict[str, list[dict[str, str]]] = {
    "missing_hsts":              [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"}],
    "hsts_short_maxage":         [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"}],
    "hsts_no_subdomains":        [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"}],
    "missing_csp":               [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}],
    "csp_unsafe_inline":         [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}],
    "csp_unsafe_eval":           [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}],
    "csp_wildcard_source":       [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}],
    "missing_x_frame_options":   [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}],
    "missing_x_content_type":    [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}],
    "missing_referrer_policy":   [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}],
    "referrer_policy_unsafe":    [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}],
    "missing_permissions_policy":[{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}],
    "plain_http":                [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"}],
}

_DEFAULT_NIST = [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}]


@dataclass(frozen=True)
class WebHeadersImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    findings_imported: int
    targets_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_web_headers_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> WebHeadersImportResult:
    _ = actor
    targets = scan_result.get("targets") or []
    raw_findings = scan_result.get("findings") or []

    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=SCHEMA_VERSION,
        collected_at=utc_iso8601_z_now(),
        raw_payload=scan_result,
        normalized_payload={"targets": targets, "findings": raw_findings},
        object_count=len(targets),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "web_headers.finding")
        nist = _FINDING_NIST.get(finding_type, _DEFAULT_NIST)
        fm = [{"framework": "NIST-AI-RMF", "control": m["control"]} for m in nist]
        target_label = raw.get("target") or ""
        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"web_headers.{finding_type}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}:{target_label}",
            severity=str(raw.get("severity") or "medium"),
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"web_headers:{scan_record.id}",
            confidence_score=95,
            framework_mappings=fm,
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint="",
        )
        imported += 1

    return WebHeadersImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        findings_imported=imported,
        targets_scanned=len(targets),
    )
