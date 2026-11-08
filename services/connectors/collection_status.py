"""
Canonical scanner collection status contract — L14-SCAN-COMPLETENESS-001.

Defines the authoritative CollectionStatus enum, DnsQueryOutcome, and
CollectionOutcome dataclass used by all FrostGate scanner connectors to
represent whether requested data was actually obtained.

Dimension separation (see FROSTGATE_VERIFIED_ASSESSMENT_STANDARD.md):
- CollectionStatus  : whether the requested data was obtained
- FindingConfidence : how strongly collected evidence supports a finding
- ScanJobStatus     : whether the job is queued/running/completed/failed
These are DISTINCT and must not be conflated.

NOT_STANDALONE: Part of the FrostGate Core field assessment pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# CollectionStatus
# ---------------------------------------------------------------------------


class CollectionStatus(str, Enum):
    """Authoritative collection status for a single scanner data-fetch operation.

    Fail-closed: unknown/future values must not silently map to COMPLETE.
    """

    COMPLETE = "COMPLETE"
    """All requested data was successfully obtained within authorized limits."""

    PARTIAL = "PARTIAL"
    """Some data was obtained but collection stopped before the full scope
    (pagination cap, partial permission, worker interruption)."""

    DENIED = "DENIED"
    """Access was explicitly refused (HTTP 403, permission error, license
    restriction). No inference of empty set is permitted."""

    TIMEOUT = "TIMEOUT"
    """The collection operation did not complete within the allowed duration.
    The result is indeterminate — not confirmed clean, not confirmed risky."""

    TRUNCATED = "TRUNCATED"
    """Results were capped at a configured safety limit. The assessed scope
    is explicitly smaller than the actual scope."""

    FAILED = "FAILED"
    """The collection operation encountered a non-timeout, non-permission
    error (network failure, malformed response, SERVFAIL, etc.)."""

    CANCELLED = "CANCELLED"
    """Scan was actively cancelled. Partial results, if any, must be
    disclosed as incomplete."""

    NOT_ASSESSED = "NOT_ASSESSED"
    """This source or asset class was explicitly excluded from scope.
    It must remain visibly unassessed — not counted as compliant."""

    UNKNOWN = "UNKNOWN"
    """Status cannot be determined from available information. Used for
    legacy records or when the upstream source provided no status signal.
    Fail-closed: treat as incomplete coverage."""


# ---------------------------------------------------------------------------
# DnsQueryStatus — DNS-specific error taxonomy
# ---------------------------------------------------------------------------


class DnsQueryStatus(str, Enum):
    """Detailed DNS query outcome — more specific than CollectionStatus."""

    SUCCESS = "SUCCESS"
    """Query returned NOERROR with one or more records."""

    NO_DATA = "NO_DATA"
    """NOERROR but no records of the requested type exist (authoritative
    negative response). This IS evidence of verified record absence."""

    NXDOMAIN = "NXDOMAIN"
    """The queried name does not exist. This IS evidence of domain/name
    absence for the queried label."""

    TIMEOUT = "TIMEOUT"
    """The resolver did not respond within the allowed time. Result is
    indeterminate — not evidence of record absence."""

    SERVFAIL = "SERVFAIL"
    """The authoritative server returned SERVFAIL. Collection failed —
    not evidence of record absence."""

    REFUSED = "REFUSED"
    """The resolver refused the query. Collection failed."""

    RESOLVER_ERROR = "RESOLVER_ERROR"
    """Resolver configuration or network connectivity failure. Collection
    failed — not evidence of record absence."""

    MALFORMED = "MALFORMED"
    """The DNS response was structurally malformed."""

    UNSUPPORTED = "UNSUPPORTED"
    """The requested record type is not supported by the resolver."""


# DNS statuses that represent definitive collection failure (not verified absence)
DNS_COLLECTION_FAILURE_STATUSES: frozenset[DnsQueryStatus] = frozenset(
    {
        DnsQueryStatus.TIMEOUT,
        DnsQueryStatus.SERVFAIL,
        DnsQueryStatus.REFUSED,
        DnsQueryStatus.RESOLVER_ERROR,
        DnsQueryStatus.MALFORMED,
        DnsQueryStatus.UNSUPPORTED,
    }
)

# DNS statuses that constitute verified authoritative negative responses
DNS_AUTHORITATIVE_ABSENCE_STATUSES: frozenset[DnsQueryStatus] = frozenset(
    {
        DnsQueryStatus.NO_DATA,
        DnsQueryStatus.NXDOMAIN,
    }
)


def dns_query_status_to_collection_status(status: DnsQueryStatus) -> CollectionStatus:
    """Map a DnsQueryStatus to a canonical CollectionStatus."""
    if status == DnsQueryStatus.SUCCESS:
        return CollectionStatus.COMPLETE
    if status in DNS_AUTHORITATIVE_ABSENCE_STATUSES:
        return CollectionStatus.COMPLETE  # authoritative negative = complete collection
    if status == DnsQueryStatus.TIMEOUT:
        return CollectionStatus.TIMEOUT
    return CollectionStatus.FAILED


# ---------------------------------------------------------------------------
# EndpointTimestampStatus — device last-seen taxonomy
# ---------------------------------------------------------------------------


class EndpointTimestampStatus(str, Enum):
    """Classification of a device's last-seen timestamp value."""

    KNOWN = "KNOWN"
    """Timestamp was present, parseable, and in a recognized UTC format."""

    ABSENT = "ABSENT"
    """No timestamp was provided by the source API."""

    INVALID = "INVALID"
    """Timestamp was present but could not be parsed as a valid datetime."""

    INDETERMINATE = "INDETERMINATE"
    """Timestamp status cannot be established (e.g. permission denied on
    the source field). Cannot be used to determine staleness."""


# ---------------------------------------------------------------------------
# CollectionOutcome
# ---------------------------------------------------------------------------


@dataclass
class CollectionOutcome:
    """Machine-readable record of a single scanner data-collection attempt.

    Intended to be embedded in scanner runner output payloads and later
    consumed by coverage_summary and report rendering.

    Fields prefixed 'source_reported_*' reflect what the upstream API
    claims; they may differ from what was actually retrieved.
    """

    schema_version: str = "1.0"
    tenant_id: str | None = None
    engagement_id: str | None = None
    scan_id: str | None = None
    scanner_id: str = ""
    data_source: str = ""
    collection_operation: str = ""

    collection_status: CollectionStatus = CollectionStatus.UNKNOWN

    started_at: str | None = None
    completed_at: str | None = None

    total_requested: int | None = None
    items_collected: int = 0
    items_failed: int = 0
    items_skipped: int = 0

    pagination_complete: bool | None = None
    pages_fetched: int = 0
    source_reported_total: int | None = None

    rate_limited: bool = False
    permission_denied: bool = False
    license_restriction: bool = False
    truncated: bool = False
    truncation_reason: str | None = None
    cancellation_reason: str | None = None

    error_code: str | None = None
    error_detail: str | None = None

    evidence_envelope_ref: str | None = None
    source_provenance: str | None = None

    coverage_limitation: str | None = None
    assessor_followup_required: bool = False

    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict."""
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "scan_id": self.scan_id,
            "scanner_id": self.scanner_id,
            "data_source": self.data_source,
            "collection_operation": self.collection_operation,
            "collection_status": self.collection_status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_requested": self.total_requested,
            "items_collected": self.items_collected,
            "items_failed": self.items_failed,
            "items_skipped": self.items_skipped,
            "pagination_complete": self.pagination_complete,
            "pages_fetched": self.pages_fetched,
            "source_reported_total": self.source_reported_total,
            "rate_limited": self.rate_limited,
            "permission_denied": self.permission_denied,
            "license_restriction": self.license_restriction,
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
            "cancellation_reason": self.cancellation_reason,
            "error_code": self.error_code,
            "error_detail": self.error_detail,
            "evidence_envelope_ref": self.evidence_envelope_ref,
            "source_provenance": self.source_provenance,
            "coverage_limitation": self.coverage_limitation,
            "assessor_followup_required": self.assessor_followup_required,
            **self.extra,
        }
