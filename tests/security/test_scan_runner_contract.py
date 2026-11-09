"""Contract assertions for field assessment scan runner outputs — L14-SCAN-COMPLETENESS-001.

Anchors the contract that all scan runners include collection_status in their output dict
with a valid canonical CollectionStatus enum value. Downstream consumers
(coverage_summary, report renderer) depend on this field being present and valid.
"""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import MagicMock, patch

from services.connectors.collection_status import CollectionStatus

VALID_STATUS_VALUES = {s.value for s in CollectionStatus}


class TestNetworkScanOutputContract:
    def test_output_has_collection_status(self) -> None:
        from services.connectors.network_scan.runner import run_network_scan

        with patch(
            "services.connectors.network_scan.runner._scan_host",
            return_value={"host": "1.2.3.4", "open_ports": [], "tls": {}},
        ):
            with patch(
                "services.connectors.network_scan.runner._expand_targets"
            ) as mock_expand:
                mock_expand.return_value = (["1.2.3.4"], [])
                result = run_network_scan(
                    target_hosts=["1.2.3.4"],
                    engagement_id="eng-contract-001",
                )

        assert "collection_status" in result
        assert result["collection_status"] in VALID_STATUS_VALUES


class TestWebHeadersOutputContract:
    def test_output_has_collection_status_on_success(self) -> None:
        from services.connectors.web_headers.runner import scan_target

        mock_validation = MagicMock()
        mock_validation.ok = True

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        }
        mock_response.url = "https://example.com"

        with patch("services.connectors.web_headers.runner._validator") as mock_v:
            mock_v.validate.return_value = mock_validation
            with patch("httpx.Client") as mock_client:
                mock_client.return_value.__enter__.return_value.head.return_value = (
                    mock_response
                )
                result = scan_target("https://example.com")

        assert "collection_status" in result
        assert result["collection_status"] in VALID_STATUS_VALUES

    def test_output_has_collection_status_on_timeout(self) -> None:
        from services.connectors.web_headers.runner import scan_target

        mock_validation = MagicMock()
        mock_validation.ok = True

        with patch("services.connectors.web_headers.runner._validator") as mock_v:
            mock_v.validate.return_value = mock_validation
            with patch("httpx.Client") as mock_client:
                mock_client.return_value.__enter__.return_value.head.side_effect = (
                    __import__("httpx").TimeoutException("timeout")
                )
                result = scan_target("https://example.com")

        assert "collection_status" in result
        assert result["collection_status"] in VALID_STATUS_VALUES


class TestOAuthInventoryOutputContract:
    def _mock_success(self) -> Callable[..., MagicMock]:
        def mock_get(url: str, headers=None, timeout=None) -> MagicMock:
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock(return_value=None)
            resp.json.return_value = {"value": []}
            return resp

        return mock_get

    def test_output_has_collection_status(self) -> None:
        from services.connectors.oauth_inventory.runner import run_oauth_inventory

        with patch("httpx.get", side_effect=self._mock_success()):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-contract-001",
                engagement_id="eng-contract-001",
            )

        assert "collection_status" in result
        assert result["collection_status"] in VALID_STATUS_VALUES

    def test_denied_collection_status_is_valid_enum(self) -> None:
        from services.connectors.oauth_inventory.runner import run_oauth_inventory

        def mock_denied(url: str, headers=None, timeout=None) -> MagicMock:
            resp = MagicMock()
            resp.status_code = 403
            resp.raise_for_status = MagicMock(return_value=None)
            resp.json.return_value = {}
            return resp

        with patch("httpx.get", side_effect=mock_denied):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-contract-002",
                engagement_id="eng-contract-002",
            )

        assert "collection_status" in result
        assert result["collection_status"] in VALID_STATUS_VALUES


class TestEndpointInventoryOutputContract:
    def test_output_has_collection_status(self) -> None:
        from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

        def mock_get(url: str, headers=None, timeout=None) -> MagicMock:
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock(return_value=None)
            resp.json.return_value = {"value": []}
            return resp

        with patch("httpx.get", side_effect=mock_get):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-contract-003",
                engagement_id="eng-contract-003",
            )

        assert "collection_status" in result
        assert result["collection_status"] in VALID_STATUS_VALUES
