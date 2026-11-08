"""Security invariants for field assessment scan runners — L14-SCAN-COMPLETENESS-001.

Tests:
- DEF-001 security layer: DNS collection failure must not assert record absence
- DEF-002b security layer: DENIED Intune access must not assert device encryption
- collection_status fail-closed: DENIED/TIMEOUT runners must not produce false negatives
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from services.connectors.collection_status import CollectionStatus, DnsQueryStatus
from services.connectors.dns_email.runner import DnsQueryOutcome, scan_domain


def _timeout_outcome() -> DnsQueryOutcome:
    return DnsQueryOutcome(records=[], status=DnsQueryStatus.TIMEOUT)


class TestDnsTimeoutFailClosed:
    """DEF-001: DNS collection failure must not produce missing-record security findings."""

    def test_timeout_scan_findings_list_is_empty(self) -> None:
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            return_value=_timeout_outcome(),
        ):
            result = scan_domain("example.com")

        assert result["findings"] == [], (
            "DEF-001: DNS timeout must produce no findings — collection failure is not "
            "authoritative absence"
        )

    def test_timeout_spf_check_finding_is_none(self) -> None:
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            return_value=_timeout_outcome(),
        ):
            result = scan_domain("example.com")

        assert result["spf"]["finding"] is None, (
            "DEF-001: DNS timeout must not assert SPF absence"
        )

    def test_timeout_dmarc_check_finding_is_none(self) -> None:
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            return_value=_timeout_outcome(),
        ):
            result = scan_domain("example.com")

        assert result["dmarc"]["finding"] is None, (
            "DEF-001: DNS timeout must not assert DMARC absence"
        )

    def test_servfail_does_not_produce_absence_findings(self) -> None:
        servfail_outcome = DnsQueryOutcome(records=[], status=DnsQueryStatus.SERVFAIL)
        with patch(
            "services.connectors.dns_email.runner._dns_query",
            return_value=servfail_outcome,
        ):
            result = scan_domain("example.com")

        assert result["findings"] == [], (
            "DEF-001: SERVFAIL is a collection failure, not authoritative absence"
        )


class TestIntuneAccessDeniedFailClosed:
    """DEF-002b: DENIED Intune access must not assert or imply device encryption state."""

    def test_intune_403_does_not_produce_unencrypted_finding(self) -> None:
        from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

        def mock_get(url: str, headers=None, timeout=None) -> MagicMock:
            resp = MagicMock()
            if "deviceManagement/managedDevices" in url:
                resp.status_code = 403
                resp.json.return_value = {}
            else:
                resp.status_code = 200
                resp.json.return_value = {
                    "value": [
                        {
                            "id": "dev-sec-001",
                            "displayName": "WorkstationA",
                            "operatingSystem": "Windows",
                            "approximateLastSignInDateTime": "2026-10-01T00:00:00Z",
                            "isCompliant": None,
                            "accountEnabled": True,
                        }
                    ]
                }
            resp.raise_for_status = MagicMock(return_value=None)
            return resp

        with patch("httpx.get", side_effect=mock_get):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-sec-001",
                engagement_id="eng-sec-001",
            )

        finding_types = {f["finding_type"] for f in result.get("findings", [])}
        assert "endpoint.unencrypted_devices" not in finding_types, (
            "DEF-002b: Intune DENIED must not produce unencrypted_devices finding "
            "— cannot assert encryption state without Intune access"
        )

    def test_intune_403_device_encryption_status_is_unknown(self) -> None:
        from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

        def mock_get(url: str, headers=None, timeout=None) -> MagicMock:
            resp = MagicMock()
            if "deviceManagement/managedDevices" in url:
                resp.status_code = 403
                resp.json.return_value = {}
            else:
                resp.status_code = 200
                resp.json.return_value = {
                    "value": [
                        {
                            "id": "dev-sec-002",
                            "displayName": "LaptopB",
                            "operatingSystem": "Windows",
                            "approximateLastSignInDateTime": "2026-10-01T00:00:00Z",
                            "isCompliant": None,
                            "accountEnabled": True,
                        }
                    ]
                }
            resp.raise_for_status = MagicMock(return_value=None)
            return resp

        with patch("httpx.get", side_effect=mock_get):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-sec-002",
                engagement_id="eng-sec-002",
            )

        for device in result.get("endpoints", []):
            assert device.get("encryption_status") == "UNKNOWN", (
                f"DEF-002b: Intune DENIED must set encryption_status=UNKNOWN, got "
                f"{device.get('encryption_status')} for {device.get('display_name')}"
            )

    def test_intune_403_collection_status_is_denied(self) -> None:
        from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

        def mock_get(url: str, headers=None, timeout=None) -> MagicMock:
            resp = MagicMock()
            if "deviceManagement/managedDevices" in url:
                resp.status_code = 403
                resp.json.return_value = {}
            else:
                resp.status_code = 200
                resp.json.return_value = {"value": []}
            resp.raise_for_status = MagicMock(return_value=None)
            return resp

        with patch("httpx.get", side_effect=mock_get):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-sec-003",
                engagement_id="eng-sec-003",
            )

        assert result["intune_collection_status"] == CollectionStatus.DENIED.value, (
            "DEF-002b: HTTP 403 on Intune must set intune_collection_status=DENIED"
        )
