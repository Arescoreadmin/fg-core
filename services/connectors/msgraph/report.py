"""MS Graph scan report generation.

Derives a client-deliverable governance report from a verified msgraph ScanResult.

Report contract:
  - Deterministic: identical ScanResult → identical manifest_hash.
  - No PII: tenant_id_hash only; no display names, UPNs, or raw tenant IDs.
  - Verifiable: manifest_hash is embedded as verification_url → GET /verify/{manifest_hash}.
  - Export-safe: all finding data is pre-sanitised by the connector layer.
  - Operator chain: receipt_hmac from the original scan is included for custody proof.

manifest_hash covers all deterministic fields (finding IDs, posture, operator receipt).
generated_at is excluded from the manifest hash — it varies across re-generation runs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.posture_score import (
    PostureScore,
    compute_posture_score,
)
from services.connectors.msgraph.schema.scan_result import Finding, ScanResult

REPORT_SCHEMA_VERSION = "1.0"
REPORT_TYPE = "msgraph_governance_v1"
VERIFY_BASE_URL = "https://verify.fieldguide.io/report"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


@dataclass(frozen=True)
class MsgraphFindingSummary:
    """Export-safe finding summary for inclusion in client reports."""

    finding_id: str
    control_id: str
    severity: str
    title: str
    affected_count: int
    recommendation: str
    remediation_effort: str
    remediation_owner: str
    framework_refs: tuple[str, ...]
    delta_status: str | None


@dataclass(frozen=True)
class MsgraphScanReport:
    """Client-deliverable governance report derived from a verified MS Graph scan.

    All fields are export-safe and deterministic.
    manifest_hash = SHA-256 over all deterministic fields, excluding generated_at.
    verification_url is derived from manifest_hash and embedded for client use.
    """

    report_id: str
    scan_result_id: str
    engagement_id: str
    tenant_id_hash: str  # sha256 — never plaintext tenant_id
    scan_completed_at: str  # ISO 8601 — from the original scan
    generated_at: str  # ISO 8601 — excluded from manifest hash
    schema_version: str
    report_type: str

    # Posture scores (0–100)
    posture_overall: int
    posture_band: str  # good / fair / poor / critical
    posture_security: int
    posture_compliance: int
    posture_ai_governance: int

    # Finding counts
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int

    # Findings — sorted critical-first, then by finding_id for stability
    findings: tuple[MsgraphFindingSummary, ...]

    # Framework coverage — deduplicated union of all finding.framework_refs
    framework_refs: tuple[str, ...]

    # Scan metadata
    scan_type: str
    scopes_authorized: tuple[str, ...]
    endpoints_called: int

    # Operator chain-of-custody proof
    operator_receipt_hmac: str  # HMAC from the original scan acknowledgment

    # Verification
    manifest_hash: str  # SHA-256 over deterministic content
    verification_url: str  # embedded for client use


def _derive_report_id(scan_result_id: str, tenant_id_hash: str) -> str:
    raw = f"msgraph-report:{scan_result_id}:{tenant_id_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_finding_summaries(
    findings: list[Finding],
) -> tuple[MsgraphFindingSummary, ...]:
    return tuple(
        MsgraphFindingSummary(
            finding_id=f.finding_id,
            control_id=f.control_id,
            severity=f.severity,
            title=f.title,
            affected_count=f.affected_count,
            recommendation=f.recommendation,
            remediation_effort=f.remediation_effort,
            remediation_owner=f.remediation_owner,
            framework_refs=tuple(sorted(f.framework_refs)),
            delta_status=f.delta_status,
        )
        for f in sorted(
            findings,
            key=lambda x: (_SEVERITY_ORDER.get(x.severity, 9), x.finding_id),
        )
    )


def _collect_framework_refs(findings: list[Finding]) -> tuple[str, ...]:
    refs: set[str] = set()
    for f in findings:
        refs.update(f.framework_refs)
    return tuple(sorted(refs))


def _canonical_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_manifest_hash(
    report_id: str,
    scan_result_id: str,
    engagement_id: str,
    tenant_id_hash: str,
    scan_completed_at: str,
    posture: PostureScore,
    summaries: tuple[MsgraphFindingSummary, ...],
    framework_refs: tuple[str, ...],
    scan_type: str,
    scopes_authorized: tuple[str, ...],
    endpoints_called: int,
    operator_receipt_hmac: str,
) -> str:
    """Deterministic manifest hash — excludes generated_at and verification_url."""
    payload: dict[str, Any] = {
        "report_id": report_id,
        "scan_result_id": scan_result_id,
        "engagement_id": engagement_id,
        "tenant_id_hash": tenant_id_hash,
        "scan_completed_at": scan_completed_at,
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "posture_overall": posture.overall,
        "posture_band": posture.band,
        "posture_security": posture.security,
        "posture_compliance": posture.compliance,
        "posture_ai_governance": posture.ai_governance,
        "finding_count": posture.finding_count,
        "critical_count": posture.critical_count,
        "high_count": posture.high_count,
        "medium_count": posture.medium_count,
        "low_count": posture.low_count,
        "informational_count": posture.informational_count,
        "findings": [
            {
                "finding_id": s.finding_id,
                "control_id": s.control_id,
                "severity": s.severity,
                "title": s.title,
                "affected_count": s.affected_count,
                "recommendation": s.recommendation,
                "remediation_effort": s.remediation_effort,
                "remediation_owner": s.remediation_owner,
                "framework_refs": list(s.framework_refs),
                "delta_status": s.delta_status,
            }
            for s in summaries
        ],
        "framework_refs": list(framework_refs),
        "scan_type": scan_type,
        "scopes_authorized": list(scopes_authorized),
        "endpoints_called": endpoints_called,
        "operator_receipt_hmac": operator_receipt_hmac,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def generate_report(scan: ScanResult, scan_result_id: str) -> MsgraphScanReport:
    """Generate a deterministic, client-deliverable governance report from a verified scan.

    Args:
        scan: Verified ScanResult from the msgraph connector.
        scan_result_id: The FaScanResult.id (DB primary key) assigned after import.

    Returns:
        MsgraphScanReport — frozen, deterministic, manifest-hashed.
        Identical inputs always produce an identical manifest_hash.
    """
    posture = compute_posture_score(list(scan.findings))
    summaries = _build_finding_summaries(list(scan.findings))
    framework_refs = _collect_framework_refs(list(scan.findings))
    scopes_authorized = tuple(sorted(scan.scopes_authorized))
    endpoints_called = len(scan.endpoints_called)
    operator_receipt_hmac = scan.operator_acknowledgment_receipt.receipt_hmac

    report_id = _derive_report_id(
        scan_result_id=scan_result_id,
        tenant_id_hash=scan.tenant_id_hash,
    )

    manifest_hash = _compute_manifest_hash(
        report_id=report_id,
        scan_result_id=scan_result_id,
        engagement_id=scan.engagement_id,
        tenant_id_hash=scan.tenant_id_hash,
        scan_completed_at=scan.scan_completed_at,
        posture=posture,
        summaries=summaries,
        framework_refs=framework_refs,
        scan_type=scan.scan_type,
        scopes_authorized=scopes_authorized,
        endpoints_called=endpoints_called,
        operator_receipt_hmac=operator_receipt_hmac,
    )

    return MsgraphScanReport(
        report_id=report_id,
        scan_result_id=scan_result_id,
        engagement_id=scan.engagement_id,
        tenant_id_hash=scan.tenant_id_hash,
        scan_completed_at=scan.scan_completed_at,
        generated_at=datetime.now(timezone.utc).isoformat(),
        schema_version=REPORT_SCHEMA_VERSION,
        report_type=REPORT_TYPE,
        posture_overall=posture.overall,
        posture_band=posture.band,
        posture_security=posture.security,
        posture_compliance=posture.compliance,
        posture_ai_governance=posture.ai_governance,
        finding_count=posture.finding_count,
        critical_count=posture.critical_count,
        high_count=posture.high_count,
        medium_count=posture.medium_count,
        low_count=posture.low_count,
        informational_count=posture.informational_count,
        findings=summaries,
        framework_refs=framework_refs,
        scan_type=scan.scan_type,
        scopes_authorized=scopes_authorized,
        endpoints_called=endpoints_called,
        operator_receipt_hmac=operator_receipt_hmac,
        manifest_hash=manifest_hash,
        verification_url=f"{VERIFY_BASE_URL}/{manifest_hash}",
    )


def report_to_json(report: MsgraphScanReport) -> dict[str, Any]:
    """Convert a MsgraphScanReport to a JSON-serializable dict for DB storage."""
    d = asdict(report)
    # asdict converts nested dataclasses and tuples recursively.
    # Tuples become lists; nested MsgraphFindingSummary becomes dict.
    # Ensure framework_refs inside each finding are also lists (already done by asdict).
    return d
