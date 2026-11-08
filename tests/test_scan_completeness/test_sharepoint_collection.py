"""L14-SCAN-COMPLETENESS-001 — SharePoint collection completeness tests.

Tests:
- TRUNCATED status when site cap is reached
- DENIED status on HTTP 403 for site listing
- Findings suppressed when access is denied (cannot claim sharing is clean)
- coverage_notes properly populated
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from services.connectors.collection_status import CollectionStatus
from services.connectors.sharepoint.runner import run_sharepoint_scan


def _mock_get_factory(*, sites: list[dict], sites_403: bool = False):
    """Create a mock httpx.get that returns controlled SharePoint API responses."""

    def _mock(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status = MagicMock(return_value=None)

        if "/organization" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "value": [
                    {
                        "verifiedDomains": [
                            {
                                "isDefault": True,
                                "type": "Managed",
                                "name": "example.com",
                            }
                        ]
                    }
                ]
            }
        elif "/sites" in url:
            if sites_403:
                resp.status_code = 403
            else:
                resp.status_code = 200
                resp.json.return_value = {"value": sites}
        elif "/drives" in url:
            resp.status_code = 200
            resp.json.return_value = {"value": []}
        else:
            resp.status_code = 200
            resp.json.return_value = {"value": []}
        return resp

    return _mock


class TestSharepointTruncated:
    def test_more_sites_than_cap_produces_truncated_status(self):
        """When source has more sites than _MAX_SITES, collection_status=TRUNCATED."""
        from services.connectors.sharepoint.runner import _MAX_SITES

        # Provide MAX_SITES + 1 sites
        sites = [
            {
                "id": f"site-{i}",
                "displayName": f"Site {i}",
                "webUrl": f"https://example.com/sites/s{i}",
            }
            for i in range(_MAX_SITES + 1)
        ]

        with patch("httpx.get", side_effect=_mock_get_factory(sites=sites)):
            result = run_sharepoint_scan(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["collection_status"] == CollectionStatus.TRUNCATED.value, (
            "Site count exceeding cap must produce TRUNCATED status, not COMPLETE."
        )

    def test_truncated_scan_scans_exactly_max_sites(self):
        from services.connectors.sharepoint.runner import _MAX_SITES

        sites = [
            {
                "id": f"site-{i}",
                "displayName": f"Site {i}",
                "webUrl": f"https://example.com/sites/s{i}",
            }
            for i in range(_MAX_SITES + 2)
        ]

        with patch("httpx.get", side_effect=_mock_get_factory(sites=sites)):
            result = run_sharepoint_scan(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["summary"]["sites_scanned"] == _MAX_SITES

    def test_truncated_note_present_in_coverage_notes(self):
        from services.connectors.sharepoint.runner import _MAX_SITES

        sites = [
            {
                "id": f"site-{i}",
                "displayName": f"Site {i}",
                "webUrl": f"https://example.com/sites/s{i}",
            }
            for i in range(_MAX_SITES + 1)
        ]

        with patch("httpx.get", side_effect=_mock_get_factory(sites=sites)):
            result = run_sharepoint_scan(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["coverage_notes"]["site_limit_note"] is not None


class TestSharepointDenied:
    def test_sites_403_produces_denied_status(self):
        """HTTP 403 on /sites must produce collection_status=DENIED."""
        with patch(
            "httpx.get", side_effect=_mock_get_factory(sites=[], sites_403=True)
        ):
            result = run_sharepoint_scan(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["collection_status"] == CollectionStatus.DENIED.value

    def test_sites_403_does_not_claim_clean_sharing(self):
        """DENIED access must not produce a 'sharing_baseline_clean' finding."""
        with patch(
            "httpx.get", side_effect=_mock_get_factory(sites=[], sites_403=True)
        ):
            result = run_sharepoint_scan(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        finding_types = [f["type"] for f in result["findings"]]
        assert "sharing_baseline_clean" not in finding_types, (
            "DENIED access must NOT produce sharing_baseline_clean — "
            "absence of sites does not prove sharing is clean."
        )

    def test_sites_403_records_denied_note(self):
        with patch(
            "httpx.get", side_effect=_mock_get_factory(sites=[], sites_403=True)
        ):
            result = run_sharepoint_scan(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["coverage_notes"]["denied_note"] is not None


class TestSharepointComplete:
    def test_fewer_sites_than_cap_produces_complete_status(self):
        """When sites <= cap, collection_status=COMPLETE."""
        sites = [
            {
                "id": "site-1",
                "displayName": "Site 1",
                "webUrl": "https://example.com/sites/s1",
            },
        ]

        with patch("httpx.get", side_effect=_mock_get_factory(sites=sites)):
            result = run_sharepoint_scan(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["collection_status"] == CollectionStatus.COMPLETE.value
