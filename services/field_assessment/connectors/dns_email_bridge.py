"""Import bridge — DNS & Email Security scan result → Field Assessment DB."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import create_finding, create_scan_result


BRIDGE_VERSION = "field-assessment-dns-email-bridge-v1"
CONNECTOR_TYPE = "dns_email"
SCHEMA_VERSION = "1.0"

_SEVERITY_NIST: dict[str, dict[str, list[dict[str, str]]]] = {
    "missing_spf":        {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "spf_permissive":     {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "spf_no_all":         {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "missing_dmarc":      {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "dmarc_policy_none":  {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "dmarc_partial_coverage": {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "dmarc_no_reporting": {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "no_dkim_found":      {"nist": [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]},
    "no_mx":              {"nist": [{"framework": "NIST-AI-RMF", "control": "MAP 1.6"}]},
    "dnssec_not_enabled": {"nist": [{"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"}]},
}

_DEFAULT_NIST = [{"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"}]


@dataclass(frozen=True)
class DnsEmailImportResult:
    engagement_id: str
    scan_result_id: str
    connector_type: str
    findings_imported: int
    domains_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def import_dns_email_scan(
    *,
    db: Session,
    tenant_id: str,
    engagement_id: str,
    scan_result: dict[str, Any],
    actor: str,
) -> DnsEmailImportResult:
    _ = actor
    domains = scan_result.get("domains") or []
    raw_findings = scan_result.get("findings") or []

    scan_record = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=CONNECTOR_TYPE,
        schema_version=SCHEMA_VERSION,
        collected_at=utc_iso8601_z_now(),
        raw_payload=scan_result,
        normalized_payload={"domains": domains, "findings": raw_findings},
        object_count=len(domains),
    )

    imported = 0
    for raw in raw_findings:
        finding_type = str(raw.get("type") or "dns_email.finding")
        nist = _SEVERITY_NIST.get(finding_type, {}).get("nist", _DEFAULT_NIST)
        fm = [{"framework": "NIST-AI-RMF", "control": m["control"]} for m in nist]
        create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=f"dns_email.{finding_type}",
            source_ref=f"{CONNECTOR_TYPE}:{scan_record.id}:{finding_type}",
            severity=str(raw.get("severity") or "medium"),
            title=str(raw.get("title") or finding_type),
            description=str(raw.get("description") or ""),
            source_attribution=f"dns_email:{scan_record.id}",
            confidence_score=90,
            framework_mappings=fm,
            nist_ai_rmf_mappings=nist,
            evidence_ref_ids=[scan_record.id],
            remediation_hint="",
        )
        imported += 1

    return DnsEmailImportResult(
        engagement_id=engagement_id,
        scan_result_id=scan_record.id,
        connector_type=CONNECTOR_TYPE,
        findings_imported=imported,
        domains_scanned=len(domains),
    )
