"""
Assessment coverage summary — L14-SCAN-COMPLETENESS-001.

Generates a canonical, deterministic, machine-readable coverage record for
a completed or partial field assessment scan. Intended to be consumed by the
Report Authority (L14-SCAN-REPORT-PROOF-001) so that assessment reports can
accurately disclose what was assessed, what was not, and why.

Non-goals:
- Does NOT modify the PDF renderer.
- Does NOT introduce a new report generator.
- Does NOT fabricate coverage percentages without a valid denominator.

Required for L14-SCAN-REPORT-PROOF-001 integration point:
  services/field_assessment/coverage_summary.py:build_coverage_summary()

NOT_STANDALONE: Part of the FrostGate Core field assessment pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from services.connectors.collection_status import CollectionStatus


COVERAGE_SUMMARY_SCHEMA_VERSION = "1.0"


@dataclass
class ScannerCoverageRecord:
    """Coverage record for a single scanner / data source."""

    scanner_id: str
    scanner_type: str
    data_source: str

    collection_status: CollectionStatus

    requested_scope: str | None = None
    assessed_scope: str | None = None
    unassessed_scope: str | None = None

    items_requested: int | None = None
    items_assessed: int = 0
    items_failed: int = 0

    known_limits: list[str] = field(default_factory=list)
    permission_restrictions: list[str] = field(default_factory=list)
    sampling_disclosures: list[str] = field(default_factory=list)
    collection_timestamp: str | None = None
    evidence_ref: str | None = None
    assessor_followup_required: bool = False
    followup_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_id": self.scanner_id,
            "scanner_type": self.scanner_type,
            "data_source": self.data_source,
            "collection_status": self.collection_status.value,
            "requested_scope": self.requested_scope,
            "assessed_scope": self.assessed_scope,
            "unassessed_scope": self.unassessed_scope,
            "items_requested": self.items_requested,
            "items_assessed": self.items_assessed,
            "items_failed": self.items_failed,
            "known_limits": self.known_limits,
            "permission_restrictions": self.permission_restrictions,
            "sampling_disclosures": self.sampling_disclosures,
            "collection_timestamp": self.collection_timestamp,
            "evidence_ref": self.evidence_ref,
            "assessor_followup_required": self.assessor_followup_required,
            "followup_reason": self.followup_reason,
        }


@dataclass
class AssessmentCoverageSummary:
    """Canonical, machine-readable coverage summary for an entire assessment scan.

    This is the integration point for L14-SCAN-REPORT-PROOF-001. When the report
    renderer reads this structure, it must:
    - Display collection_status per scanner.
    - Suppress "No risks found" when any scanner is DENIED/TIMEOUT/FAILED.
    - Suppress "Fully assessed" when any scanner is PARTIAL/TRUNCATED.
    - Surface assessor_followup_required items to the delivery note.
    """

    schema_version: str = COVERAGE_SUMMARY_SCHEMA_VERSION
    tenant_id: str | None = None
    engagement_id: str | None = None
    scan_id: str | None = None
    generated_at: str | None = None

    scanner_records: list[ScannerCoverageRecord] = field(default_factory=list)

    @property
    def overall_collection_status(self) -> CollectionStatus:
        """Aggregate collection status across all scanners.

        Fail-closed: any DENIED/FAILED/TIMEOUT → overall is not COMPLETE.
        """
        if not self.scanner_records:
            return CollectionStatus.UNKNOWN

        status_precedence = {
            CollectionStatus.FAILED: 0,
            CollectionStatus.DENIED: 1,
            CollectionStatus.TIMEOUT: 2,
            CollectionStatus.CANCELLED: 3,
            CollectionStatus.TRUNCATED: 4,
            CollectionStatus.PARTIAL: 5,
            CollectionStatus.NOT_ASSESSED: 6,
            CollectionStatus.UNKNOWN: 7,
            CollectionStatus.COMPLETE: 8,
        }
        return min(
            (r.collection_status for r in self.scanner_records),
            key=lambda s: status_precedence.get(s, 0),
        )

    @property
    def has_incomplete_scanners(self) -> bool:
        return any(
            r.collection_status != CollectionStatus.COMPLETE
            for r in self.scanner_records
        )

    @property
    def requires_assessor_followup(self) -> bool:
        return any(r.assessor_followup_required for r in self.scanner_records)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "overall_collection_status": self.overall_collection_status.value,
            "has_incomplete_scanners": self.has_incomplete_scanners,
            "requires_assessor_followup": self.requires_assessor_followup,
            "scanner_records": [r.to_dict() for r in self.scanner_records],
            # Report enforcement signals — read by L14-SCAN-REPORT-PROOF-001
            "report_constraints": {
                "may_claim_no_risks_found": not self.has_incomplete_scanners,
                "may_claim_fully_assessed": self.overall_collection_status
                == CollectionStatus.COMPLETE,
                "must_disclose_incomplete_scanners": self.has_incomplete_scanners,
                "must_surface_assessor_followup": self.requires_assessor_followup,
            },
        }


def build_coverage_summary(
    *,
    tenant_id: str | None,
    engagement_id: str | None,
    scan_id: str | None,
    generated_at: str | None = None,
    scanner_records: list[ScannerCoverageRecord] | None = None,
) -> AssessmentCoverageSummary:
    """Construct an AssessmentCoverageSummary from pre-built scanner records.

    This is a thin builder; callers supply pre-classified ScannerCoverageRecord
    instances from each scanner bridge/runner.
    """
    return AssessmentCoverageSummary(
        schema_version=COVERAGE_SUMMARY_SCHEMA_VERSION,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_id=scan_id,
        generated_at=generated_at,
        scanner_records=scanner_records or [],
    )


def coverage_record_from_dns_result(
    result: dict[str, Any],
    *,
    engagement_id: str | None = None,
) -> ScannerCoverageRecord:
    """Build a ScannerCoverageRecord from a dns_email runner result dict."""
    raw_status = result.get("collection_status", CollectionStatus.UNKNOWN.value)
    try:
        status = CollectionStatus(raw_status)
    except ValueError:
        status = CollectionStatus.UNKNOWN

    domains = result.get("summary", {}).get("total_domains", 0)
    failed = result.get("summary", {}).get("domains_with_collection_failures", 0)

    limits: list[str] = []
    restrictions: list[str] = []
    sampling: list[str] = []

    if failed:
        limits.append(
            f"{failed}/{domains} domain(s) had DNS collection failures (timeout/SERVFAIL/refused). "
            "Missing-record findings are suppressed for those domains."
        )

    return ScannerCoverageRecord(
        scanner_id="dns_email",
        scanner_type="dns_email",
        data_source="DNS resolver",
        collection_status=status,
        items_requested=domains,
        items_assessed=domains - failed,
        items_failed=failed,
        known_limits=limits,
        permission_restrictions=restrictions,
        sampling_disclosures=sampling,
        assessor_followup_required=failed > 0,
        followup_reason=(
            "DNS collection failures occurred. Manual DNS verification recommended for affected domains."
            if failed > 0
            else None
        ),
    )


def coverage_record_from_endpoint_result(
    result: dict[str, Any],
) -> ScannerCoverageRecord:
    """Build a ScannerCoverageRecord from an endpoint_inventory runner result dict."""
    raw_status = result.get("collection_status", CollectionStatus.UNKNOWN.value)
    try:
        status = CollectionStatus(raw_status)
    except ValueError:
        status = CollectionStatus.UNKNOWN

    summary = result.get("summary", {})
    total = summary.get("total", 0)
    unknown_ts = summary.get("unknown_last_seen", 0)

    intune_status = result.get(
        "intune_collection_status", CollectionStatus.UNKNOWN.value
    )
    limits: list[str] = []
    restrictions: list[str] = []

    if intune_status in (CollectionStatus.DENIED.value, CollectionStatus.FAILED.value):
        restrictions.append(
            f"Intune managed device data was {intune_status}. "
            "Encryption status and detailed compliance data not available."
        )

    sampling: list[str] = []
    if unknown_ts:
        sampling.append(
            f"{unknown_ts}/{total} devices have absent or invalid last-seen timestamps. "
            "Their staleness is INDETERMINATE and they are excluded from the stale device count."
        )

    return ScannerCoverageRecord(
        scanner_id="endpoint_inventory",
        scanner_type="endpoint_inventory",
        data_source="Microsoft Graph — /devices, /deviceManagement/managedDevices",
        collection_status=status,
        items_requested=total if status == CollectionStatus.COMPLETE else None,
        items_assessed=total,
        known_limits=limits,
        permission_restrictions=restrictions,
        sampling_disclosures=sampling,
        assessor_followup_required=bool(unknown_ts or restrictions),
        followup_reason=(
            "Incomplete endpoint data: Intune access denied or devices with unknown timestamps."
            if unknown_ts or restrictions
            else None
        ),
    )


def coverage_record_from_sharepoint_result(
    result: dict[str, Any],
) -> ScannerCoverageRecord:
    """Build a ScannerCoverageRecord from a sharepoint runner result dict."""
    raw_status = result.get("collection_status", CollectionStatus.UNKNOWN.value)
    try:
        status = CollectionStatus(raw_status)
    except ValueError:
        status = CollectionStatus.UNKNOWN

    summary = result.get("summary", {})
    sites_scanned = summary.get("sites_scanned", 0)
    site_cap = summary.get("site_cap", 30)

    notes = result.get("coverage_notes", {})
    sampling: list[str] = []
    if notes.get("site_limit_note"):
        sampling.append(notes["site_limit_note"])
    if notes.get("denied_note"):
        sampling.append(notes["denied_note"])

    return ScannerCoverageRecord(
        scanner_id="sharepoint_onedrive",
        scanner_type="sharepoint_onedrive",
        data_source="Microsoft Graph — /sites, /drives",
        collection_status=status,
        items_requested=None,  # source does not report total site count
        items_assessed=sites_scanned,
        known_limits=[f"Site scan capped at {site_cap} sites per execution."],
        sampling_disclosures=sampling,
        assessor_followup_required=status
        in (
            CollectionStatus.TRUNCATED,
            CollectionStatus.DENIED,
            CollectionStatus.PARTIAL,
        ),
        followup_reason=(
            "SharePoint coverage is incomplete. Manual review of unscanned sites recommended."
            if status != CollectionStatus.COMPLETE
            else None
        ),
    )


def coverage_record_from_network_result(
    result: dict[str, Any],
) -> ScannerCoverageRecord:
    """Build a ScannerCoverageRecord from a network_scan runner result dict."""
    raw_status = result.get("collection_status", CollectionStatus.UNKNOWN.value)
    try:
        status = CollectionStatus(raw_status)
    except ValueError:
        status = CollectionStatus.UNKNOWN

    summary = result.get("summary", {})
    total_hosts = summary.get("total_hosts", 0)
    error_count = summary.get("host_scan_error_count", 0)

    return ScannerCoverageRecord(
        scanner_id="network_scan",
        scanner_type="network_scan",
        data_source="TCP port probe",
        collection_status=status,
        items_requested=total_hosts + len(result.get("rejected_targets", [])),
        items_assessed=total_hosts - error_count,
        items_failed=error_count,
        known_limits=[
            "Port probes return 'not confirmed open' — cannot distinguish closed from timed-out/filtered.",
            "Scan limited to predefined port list; non-listed ports are NOT_ASSESSED.",
        ],
        sampling_disclosures=(
            [
                f"{summary.get('rejected_target_count', 0)} target(s) blocked by SSRF safety policy."
            ]
            if summary.get("rejected_target_count")
            else []
        ),
        assessor_followup_required=error_count > 0,
    )


def coverage_record_from_web_headers_result(
    result: dict[str, Any],
) -> ScannerCoverageRecord:
    """Build a ScannerCoverageRecord from a web_headers runner result dict."""
    raw_status = result.get("collection_status", CollectionStatus.UNKNOWN.value)
    try:
        status = CollectionStatus(raw_status)
    except ValueError:
        status = CollectionStatus.UNKNOWN

    summary = result.get("summary", {})
    total = summary.get("total_targets", 0)
    failed = summary.get("failed", 0)
    denied = summary.get("denied", 0)

    return ScannerCoverageRecord(
        scanner_id="web_headers",
        scanner_type="web_headers",
        data_source="HTTP HEAD request",
        collection_status=status,
        items_requested=total,
        items_assessed=summary.get("reachable", 0),
        items_failed=failed,
        known_limits=[
            "Checks HTTP response headers from a HEAD request only; "
            "headers may differ on other routes or for authenticated responses.",
        ],
        sampling_disclosures=(
            [f"{denied} target(s) blocked by redirect or SSRF safety policy."]
            if denied
            else []
        ),
        assessor_followup_required=failed > 0,
    )
