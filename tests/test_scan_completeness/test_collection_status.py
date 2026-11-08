"""L14-SCAN-COMPLETENESS-001 — CollectionStatus canonical contract tests.

Tests the canonical CollectionStatus enum, DnsQueryStatus taxonomy,
EndpointTimestampStatus, and CollectionOutcome serialization.

All tests are pure unit tests; no external I/O.
"""

from __future__ import annotations

from services.connectors.collection_status import (
    CollectionOutcome,
    CollectionStatus,
    DnsQueryStatus,
    DNS_COLLECTION_FAILURE_STATUSES,
    DNS_AUTHORITATIVE_ABSENCE_STATUSES,
    EndpointTimestampStatus,
    dns_query_status_to_collection_status,
)


# ---------------------------------------------------------------------------
# CS-001: CollectionStatus enum completeness
# ---------------------------------------------------------------------------


class TestCollectionStatusEnum:
    def test_all_required_values_present(self):
        required = {
            "COMPLETE",
            "PARTIAL",
            "DENIED",
            "TIMEOUT",
            "TRUNCATED",
            "FAILED",
            "CANCELLED",
            "NOT_ASSESSED",
            "UNKNOWN",
        }
        actual = {s.value for s in CollectionStatus}
        assert required <= actual

    def test_enum_is_string_subclass(self):
        assert isinstance(CollectionStatus.COMPLETE, str)

    def test_unknown_does_not_equal_complete(self):
        assert CollectionStatus.UNKNOWN != CollectionStatus.COMPLETE

    def test_failed_does_not_equal_denied(self):
        assert CollectionStatus.FAILED != CollectionStatus.DENIED


# ---------------------------------------------------------------------------
# CS-002: DnsQueryStatus taxonomy
# ---------------------------------------------------------------------------


class TestDnsQueryStatusTaxonomy:
    def test_success_in_authoritative_absence_statuses_is_false(self):
        assert DnsQueryStatus.SUCCESS not in DNS_AUTHORITATIVE_ABSENCE_STATUSES

    def test_no_data_is_authoritative_absence(self):
        assert DnsQueryStatus.NO_DATA in DNS_AUTHORITATIVE_ABSENCE_STATUSES

    def test_nxdomain_is_authoritative_absence(self):
        assert DnsQueryStatus.NXDOMAIN in DNS_AUTHORITATIVE_ABSENCE_STATUSES

    def test_timeout_is_collection_failure(self):
        assert DnsQueryStatus.TIMEOUT in DNS_COLLECTION_FAILURE_STATUSES

    def test_servfail_is_collection_failure(self):
        assert DnsQueryStatus.SERVFAIL in DNS_COLLECTION_FAILURE_STATUSES

    def test_refused_is_collection_failure(self):
        assert DnsQueryStatus.REFUSED in DNS_COLLECTION_FAILURE_STATUSES

    def test_resolver_error_is_collection_failure(self):
        assert DnsQueryStatus.RESOLVER_ERROR in DNS_COLLECTION_FAILURE_STATUSES

    def test_authoritative_absence_and_collection_failure_are_disjoint(self):
        overlap = DNS_AUTHORITATIVE_ABSENCE_STATUSES & DNS_COLLECTION_FAILURE_STATUSES
        assert overlap == frozenset(), (
            "Authoritative absence and collection failure must be mutually exclusive."
        )


# ---------------------------------------------------------------------------
# CS-003: dns_query_status_to_collection_status mapping
# ---------------------------------------------------------------------------


class TestDnsQueryStatusToCollectionStatus:
    def test_success_maps_to_complete(self):
        assert (
            dns_query_status_to_collection_status(DnsQueryStatus.SUCCESS)
            == CollectionStatus.COMPLETE
        )

    def test_no_data_maps_to_complete(self):
        # NO_DATA is authoritative — collection completed (found nothing)
        assert (
            dns_query_status_to_collection_status(DnsQueryStatus.NO_DATA)
            == CollectionStatus.COMPLETE
        )

    def test_nxdomain_maps_to_complete(self):
        assert (
            dns_query_status_to_collection_status(DnsQueryStatus.NXDOMAIN)
            == CollectionStatus.COMPLETE
        )

    def test_timeout_maps_to_timeout(self):
        assert (
            dns_query_status_to_collection_status(DnsQueryStatus.TIMEOUT)
            == CollectionStatus.TIMEOUT
        )

    def test_servfail_maps_to_failed(self):
        assert (
            dns_query_status_to_collection_status(DnsQueryStatus.SERVFAIL)
            == CollectionStatus.FAILED
        )

    def test_refused_maps_to_failed(self):
        assert (
            dns_query_status_to_collection_status(DnsQueryStatus.REFUSED)
            == CollectionStatus.FAILED
        )

    def test_resolver_error_maps_to_failed(self):
        assert (
            dns_query_status_to_collection_status(DnsQueryStatus.RESOLVER_ERROR)
            == CollectionStatus.FAILED
        )


# ---------------------------------------------------------------------------
# CS-004: EndpointTimestampStatus
# ---------------------------------------------------------------------------


class TestEndpointTimestampStatus:
    def test_known_is_separate_from_absent(self):
        assert EndpointTimestampStatus.KNOWN != EndpointTimestampStatus.ABSENT

    def test_absent_is_separate_from_invalid(self):
        assert EndpointTimestampStatus.ABSENT != EndpointTimestampStatus.INVALID

    def test_indeterminate_is_not_known(self):
        assert EndpointTimestampStatus.INDETERMINATE != EndpointTimestampStatus.KNOWN


# ---------------------------------------------------------------------------
# CS-005: CollectionOutcome serialization
# ---------------------------------------------------------------------------


class TestCollectionOutcome:
    def test_to_dict_contains_all_required_fields(self):
        outcome = CollectionOutcome(
            scanner_id="dns_email",
            data_source="DNS resolver",
            collection_operation="TXT lookup",
            collection_status=CollectionStatus.COMPLETE,
        )
        d = outcome.to_dict()
        required = {
            "schema_version",
            "tenant_id",
            "engagement_id",
            "scan_id",
            "scanner_id",
            "data_source",
            "collection_operation",
            "collection_status",
            "started_at",
            "completed_at",
            "total_requested",
            "items_collected",
            "items_failed",
            "items_skipped",
            "pagination_complete",
            "pages_fetched",
            "source_reported_total",
            "rate_limited",
            "permission_denied",
            "license_restriction",
            "truncated",
            "truncation_reason",
            "cancellation_reason",
            "error_code",
            "error_detail",
            "evidence_envelope_ref",
            "source_provenance",
            "coverage_limitation",
            "assessor_followup_required",
        }
        assert required <= set(d.keys())

    def test_collection_status_serialized_as_string(self):
        outcome = CollectionOutcome(
            scanner_id="test",
            data_source="test",
            collection_operation="test",
            collection_status=CollectionStatus.DENIED,
        )
        d = outcome.to_dict()
        assert d["collection_status"] == "DENIED"
        assert isinstance(d["collection_status"], str)

    def test_complete_outcome_no_error(self):
        outcome = CollectionOutcome(
            scanner_id="test",
            data_source="test",
            collection_operation="test",
            collection_status=CollectionStatus.COMPLETE,
            items_collected=50,
        )
        d = outcome.to_dict()
        assert d["collection_status"] == "COMPLETE"
        assert d["items_collected"] == 50
        assert d["error_code"] is None
