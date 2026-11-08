"""L14-SCAN-COMPLETENESS-001 — Coverage summary and scanner collection status tests.

Tests:
- AssessmentCoverageSummary aggregation logic
- Coverage record builders for each scanner
- Overall collection_status in network_scan, web_headers, sharepoint, oauth_inventory
- Cancellation does not become completion
- Partial evidence preserved without overclaiming
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from services.connectors.collection_status import CollectionStatus
from services.field_assessment.coverage_summary import (
    ScannerCoverageRecord,
    build_coverage_summary,
    coverage_record_from_dns_result,
    coverage_record_from_endpoint_result,
    coverage_record_from_sharepoint_result,
)


# ---------------------------------------------------------------------------
# CS-COV-001: AssessmentCoverageSummary overall_collection_status aggregation
# ---------------------------------------------------------------------------


class TestAssessmentCoverageSummaryAggregation:
    def _record(self, status: CollectionStatus) -> ScannerCoverageRecord:
        return ScannerCoverageRecord(
            scanner_id="test",
            scanner_type="test",
            data_source="test",
            collection_status=status,
        )

    def test_all_complete_produces_complete(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[
                self._record(CollectionStatus.COMPLETE),
                self._record(CollectionStatus.COMPLETE),
            ],
        )
        assert summary.overall_collection_status == CollectionStatus.COMPLETE

    def test_one_failed_produces_failed(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[
                self._record(CollectionStatus.COMPLETE),
                self._record(CollectionStatus.FAILED),
            ],
        )
        assert summary.overall_collection_status == CollectionStatus.FAILED

    def test_one_denied_overrides_complete(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[
                self._record(CollectionStatus.COMPLETE),
                self._record(CollectionStatus.DENIED),
            ],
        )
        assert summary.overall_collection_status == CollectionStatus.DENIED

    def test_one_partial_does_not_produce_complete(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[
                self._record(CollectionStatus.COMPLETE),
                self._record(CollectionStatus.PARTIAL),
            ],
        )
        assert summary.overall_collection_status != CollectionStatus.COMPLETE

    def test_empty_records_produces_unknown(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[],
        )
        assert summary.overall_collection_status == CollectionStatus.UNKNOWN

    def test_failed_ranked_below_denied(self):
        """FAILED is the worst status (index 0 in precedence)."""
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[
                self._record(CollectionStatus.DENIED),
                self._record(CollectionStatus.FAILED),
            ],
        )
        assert summary.overall_collection_status == CollectionStatus.FAILED


class TestCoverageSummaryReportConstraints:
    def _record(self, status: CollectionStatus) -> ScannerCoverageRecord:
        return ScannerCoverageRecord(
            scanner_id="test",
            scanner_type="test",
            data_source="test",
            collection_status=status,
        )

    def test_complete_does_not_allow_no_risks_found_claim(self):
        """CRITICAL: collection COMPLETE != no findings found.
        may_claim_no_risks_found is ALWAYS False from the coverage summary.
        Only L14-SCAN-REPORT-PROOF-001 (finding authority) may assert this
        after independently verifying finding_count == 0 within assessed scope.
        """
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[self._record(CollectionStatus.COMPLETE)],
        )
        d = summary.to_dict()
        assert d["report_constraints"]["may_claim_no_risks_found"] is False, (
            "COMPLETE collection status does NOT mean no findings exist. "
            "Collection completed ≠ inventory coverage established ≠ no reportable "
            "findings ≠ environment has no risks. These are four separate claims."
        )

    def test_no_risks_found_always_false_regardless_of_collection_status(self):
        """may_claim_no_risks_found must be False for every collection status.
        This is a finding-authority constraint, not a collection-status constraint.
        """
        for status in CollectionStatus:
            summary = build_coverage_summary(
                tenant_id="t1",
                engagement_id="e1",
                scan_id="s1",
                scanner_records=[self._record(status)],
            )
            d = summary.to_dict()
            assert d["report_constraints"]["may_claim_no_risks_found"] is False, (
                f"may_claim_no_risks_found must be False for status={status.value}. "
                "The coverage summary cannot assert finding absence."
            )

    def test_partial_forbids_no_risks_found_claim(self):
        """Retained as named regression guard: PARTIAL still produces False."""
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[
                self._record(CollectionStatus.COMPLETE),
                self._record(CollectionStatus.PARTIAL),
            ],
        )
        d = summary.to_dict()
        assert d["report_constraints"]["may_claim_no_risks_found"] is False

    def test_denied_forbids_fully_assessed_claim(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[self._record(CollectionStatus.DENIED)],
        )
        d = summary.to_dict()
        assert d["report_constraints"]["may_claim_fully_assessed"] is False

    def test_complete_allows_fully_assessed_claim(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[self._record(CollectionStatus.COMPLETE)],
        )
        d = summary.to_dict()
        assert d["report_constraints"]["may_claim_fully_assessed"] is True

    def test_incomplete_requires_disclosure(self):
        summary = build_coverage_summary(
            tenant_id="t1",
            engagement_id="e1",
            scan_id="s1",
            scanner_records=[self._record(CollectionStatus.TIMEOUT)],
        )
        d = summary.to_dict()
        assert d["report_constraints"]["must_disclose_incomplete_scanners"] is True


# ---------------------------------------------------------------------------
# CS-COV-002: DNS coverage record builder
# ---------------------------------------------------------------------------


class TestDnsCoverageRecord:
    def test_complete_dns_result_produces_complete_record(self):
        result = {
            "collection_status": "COMPLETE",
            "summary": {
                "total_domains": 2,
                "domains_with_collection_failures": 0,
            },
        }
        record = coverage_record_from_dns_result(result)
        assert record.collection_status == CollectionStatus.COMPLETE
        assert record.assessor_followup_required is False

    def test_partial_dns_result_produces_followup(self):
        result = {
            "collection_status": "PARTIAL",
            "summary": {
                "total_domains": 2,
                "domains_with_collection_failures": 1,
            },
        }
        record = coverage_record_from_dns_result(result)
        assert record.collection_status == CollectionStatus.PARTIAL
        assert record.assessor_followup_required is True
        assert record.followup_reason is not None

    def test_unknown_status_in_result_produces_unknown_record(self):
        result = {"collection_status": "UNKNOWN_GARBAGE", "summary": {}}
        record = coverage_record_from_dns_result(result)
        assert record.collection_status == CollectionStatus.UNKNOWN


# ---------------------------------------------------------------------------
# CS-COV-003: Endpoint coverage record builder
# ---------------------------------------------------------------------------


class TestEndpointCoverageRecord:
    def test_denied_intune_produces_restriction_note(self):
        result = {
            "collection_status": "COMPLETE",
            "intune_collection_status": "DENIED",
            "summary": {"total": 10, "unknown_last_seen": 0},
        }
        record = coverage_record_from_endpoint_result(result)
        assert len(record.permission_restrictions) > 0
        assert record.assessor_followup_required is True

    def test_unknown_timestamps_produce_sampling_note(self):
        result = {
            "collection_status": "COMPLETE",
            "intune_collection_status": "COMPLETE",
            "summary": {"total": 10, "unknown_last_seen": 3},
        }
        record = coverage_record_from_endpoint_result(result)
        assert len(record.sampling_disclosures) > 0
        assert record.assessor_followup_required is True


# ---------------------------------------------------------------------------
# CS-COV-004: SharePoint coverage record builder
# ---------------------------------------------------------------------------


class TestSharepointCoverageRecord:
    def test_truncated_produces_followup(self):
        result = {
            "collection_status": "TRUNCATED",
            "summary": {"sites_scanned": 30, "site_cap": 30},
            "coverage_notes": {
                "site_limit_note": "Site scan capped at 30.",
                "denied_note": None,
            },
        }
        record = coverage_record_from_sharepoint_result(result)
        assert record.collection_status == CollectionStatus.TRUNCATED
        assert record.assessor_followup_required is True
        assert any("30" in note for note in record.sampling_disclosures)

    def test_denied_produces_followup_with_note(self):
        result = {
            "collection_status": "DENIED",
            "summary": {"sites_scanned": 0, "site_cap": 30},
            "coverage_notes": {
                "site_limit_note": None,
                "denied_note": "HTTP 403 — SharePoint site listing was denied.",
            },
        }
        record = coverage_record_from_sharepoint_result(result)
        assert record.collection_status == CollectionStatus.DENIED
        assert record.assessor_followup_required is True

    def test_complete_does_not_produce_followup(self):
        result = {
            "collection_status": "COMPLETE",
            "summary": {"sites_scanned": 5, "site_cap": 30},
            "coverage_notes": {"site_limit_note": None, "denied_note": None},
        }
        record = coverage_record_from_sharepoint_result(result)
        assert record.assessor_followup_required is False


# ---------------------------------------------------------------------------
# CS-COV-005: Network scan collection_status
# ---------------------------------------------------------------------------


class TestNetworkScanCollectionStatus:
    def _run_with_hosts(self, hosts: list[str], fail_all: bool = False):
        from services.connectors.network_scan.runner import run_network_scan

        def mock_scan_host(host):
            if fail_all:
                raise Exception("scan error")
            return {"host": host, "open_ports": [], "tls": {}}

        with patch(
            "services.connectors.network_scan.runner._scan_host",
            side_effect=mock_scan_host,
        ):
            with patch(
                "services.connectors.network_scan.runner._expand_targets"
            ) as mock_expand:
                mock_expand.return_value = (hosts, [])
                return run_network_scan(
                    target_hosts=hosts,
                    engagement_id="eng-001",
                )

    def test_no_errors_produces_complete_status(self):
        result = self._run_with_hosts(["1.2.3.4"])
        assert result["collection_status"] == CollectionStatus.COMPLETE.value

    def test_all_errors_produces_failed_status(self):
        result = self._run_with_hosts(["1.2.3.4"], fail_all=True)
        assert result["collection_status"] == CollectionStatus.FAILED.value


# ---------------------------------------------------------------------------
# CS-COV-006: Web headers collection_status
# ---------------------------------------------------------------------------


class TestWebHeadersCollectionStatus:
    def test_timeout_target_produces_failed_collection_status(self):
        from services.connectors.web_headers.runner import scan_target

        with patch("services.connectors.web_headers.runner._validator") as mock_v:
            mock_v.validate.return_value = MagicMock(ok=True)
            with patch("httpx.Client") as mock_client:
                mock_client.return_value.__enter__.return_value.head.side_effect = (
                    __import__("httpx").TimeoutException("timeout")
                )
                result = scan_target("https://example.com")

        assert result["collection_status"] == CollectionStatus.FAILED.value
        assert result["findings"] == [], (
            "Timeout must not emit missing-header findings."
        )

    def test_blocked_target_produces_denied_collection_status(self):
        from services.connectors.web_headers.runner import scan_target

        mock_validation = MagicMock()
        mock_validation.ok = False
        mock_validation.rejection_code = "PRIVATE_RANGE"
        mock_validation.rejection_reason = "private IP"

        with patch("services.connectors.web_headers.runner._validator") as mock_v:
            mock_v.validate.return_value = mock_validation
            result = scan_target("https://192.168.1.1")

        assert result["collection_status"] == CollectionStatus.DENIED.value


# ---------------------------------------------------------------------------
# CS-COV-007: OAuth inventory collection_status
# ---------------------------------------------------------------------------


class TestOAuthInventoryCollectionStatus:
    def test_403_on_app_registrations_produces_denied(self):
        from services.connectors.oauth_inventory.runner import run_oauth_inventory

        def mock_get(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 403
            resp.raise_for_status = MagicMock(return_value=None)
            resp.json.return_value = {}
            return resp

        with patch("httpx.get", side_effect=mock_get):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["collection_status"] == CollectionStatus.DENIED.value
        assert (
            result["source_statuses"]["app_registrations"]
            == CollectionStatus.DENIED.value
        )

    def test_success_produces_complete_status(self):
        from services.connectors.oauth_inventory.runner import run_oauth_inventory

        def mock_get(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock(return_value=None)
            resp.json.return_value = {"value": []}
            return resp

        with patch("httpx.get", side_effect=mock_get):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["collection_status"] == CollectionStatus.COMPLETE.value
