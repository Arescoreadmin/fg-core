"""L14-SCAN-COMPLETENESS-001 — DEF-002 closure tests.

Adversarial tests proving that unknown, absent, or invalid device last-seen
timestamps produce INDETERMINATE status (is_stale=None), not is_stale=False.

A missing timestamp must NOT be treated as evidence that the device is active.
A missing Intune record must NOT default is_encrypted to True.

Tests call real endpoint_inventory runner logic; httpx.get is mocked.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from services.connectors.collection_status import (
    CollectionStatus,
    EndpointTimestampStatus,
)
from services.connectors.endpoint_inventory.runner import (
    _classify_timestamp,
    run_endpoint_inventory,
)


# ---------------------------------------------------------------------------
# DEF002-TIMESTAMP: _classify_timestamp unit tests
# ---------------------------------------------------------------------------


class TestClassifyTimestamp:
    """Unit tests for _classify_timestamp — the DEF-002 fix function."""

    def _cutoff(self, days: int = 90) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=days)

    def test_none_produces_absent_and_indeterminate(self):
        status, is_stale = _classify_timestamp(None, self._cutoff())
        assert status == EndpointTimestampStatus.ABSENT
        assert is_stale is None

    def test_empty_string_produces_absent_and_indeterminate(self):
        status, is_stale = _classify_timestamp("", self._cutoff())
        assert status == EndpointTimestampStatus.ABSENT
        assert is_stale is None

    def test_malformed_string_produces_invalid_and_indeterminate(self):
        status, is_stale = _classify_timestamp("not-a-date", self._cutoff())
        assert status == EndpointTimestampStatus.INVALID
        assert is_stale is None

    def test_valid_recent_produces_known_not_stale(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        status, is_stale = _classify_timestamp(recent, self._cutoff())
        assert status == EndpointTimestampStatus.KNOWN
        assert is_stale is False

    def test_valid_stale_produces_known_stale(self):
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        status, is_stale = _classify_timestamp(old, self._cutoff())
        assert status == EndpointTimestampStatus.KNOWN
        assert is_stale is True

    def test_z_suffix_handled_correctly(self):
        """Graph API returns timestamps with Z suffix."""
        old = (datetime.now(timezone.utc) - timedelta(days=120)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        status, is_stale = _classify_timestamp(old, self._cutoff())
        assert status == EndpointTimestampStatus.KNOWN
        assert is_stale is True

    def test_absent_is_not_stale_true(self):
        """ABSENT must not produce is_stale=True (device may be very recent)."""
        status, is_stale = _classify_timestamp(None, self._cutoff())
        assert is_stale is not True

    def test_absent_is_not_stale_false(self):
        """ABSENT must not produce is_stale=False (device may be very old)."""
        status, is_stale = _classify_timestamp(None, self._cutoff())
        assert is_stale is not False
        assert is_stale is None


# ---------------------------------------------------------------------------
# DEF002-RUNNER: run_endpoint_inventory integration tests
# ---------------------------------------------------------------------------


def _make_mock_get(
    devices: list[dict],
    intune_devices: list[dict] | None = None,
    intune_403: bool = False,
):
    def _mock(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status = MagicMock(return_value=None)
        if "deviceManagement" in url:
            if intune_403:
                resp.status_code = 403
                resp.json.return_value = {}
            else:
                resp.status_code = 200
                resp.json.return_value = {"value": intune_devices or []}
        else:
            resp.status_code = 200
            resp.json.return_value = {"value": devices}
        return resp

    return _mock


def _build_device(
    dev_id: str,
    display_name: str,
    *,
    last_seen_raw: str | None = "",
    is_compliant: bool | None = True,
    is_managed: bool = True,
) -> dict:
    return {
        "id": dev_id,
        "displayName": display_name,
        "operatingSystem": "Windows",
        "operatingSystemVersion": "10.0",
        "isCompliant": is_compliant,
        "isManaged": is_managed,
        "approximateLastSignInDateTime": last_seen_raw or "",
        "trustType": "AzureAD",
    }


class TestDef002RunnerAbsentTimestamp:
    def test_absent_timestamp_produces_is_stale_none(self):
        """DEF-002 closed: absent last_seen → is_stale=None, not is_stale=False."""
        devices = [_build_device("dev-001", "NoDate", last_seen_raw="")]
        with patch("httpx.get", side_effect=_make_mock_get(devices)):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        ep = result["endpoints"][0]
        assert ep["is_stale"] is None, (
            "DEF-002 closed: absent timestamp must yield is_stale=None, not False."
        )
        assert ep["last_seen_timestamp_status"] == EndpointTimestampStatus.ABSENT.value

    def test_absent_timestamp_not_counted_in_stale_count(self):
        devices = [_build_device("dev-001", "NoDate", last_seen_raw="")]
        with patch("httpx.get", side_effect=_make_mock_get(devices)):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["summary"]["stale"] == 0
        assert result["summary"]["unknown_last_seen"] == 1

    def test_absent_timestamp_does_not_produce_stale_finding(self):
        devices = [_build_device("dev-001", "NoDate", last_seen_raw="")]
        with patch("httpx.get", side_effect=_make_mock_get(devices)):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "endpoint.stale_devices" not in finding_types, (
            "DEF-002: absent timestamp must NOT trigger stale_devices finding."
        )


class TestDef002RunnerInvalidTimestamp:
    def test_invalid_timestamp_produces_is_stale_none(self):
        """DEF-002 closed: invalid/malformed timestamp → is_stale=None."""
        dev = {
            "id": "dev-002",
            "displayName": "BadDate",
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0",
            "isCompliant": True,
            "isManaged": True,
            "approximateLastSignInDateTime": "definitely-not-iso8601",
            "trustType": "AzureAD",
        }
        with patch("httpx.get", side_effect=_make_mock_get([dev])):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        ep = result["endpoints"][0]
        assert ep["is_stale"] is None
        assert ep["last_seen_timestamp_status"] == EndpointTimestampStatus.INVALID.value

    def test_invalid_timestamp_not_counted_in_stale(self):
        dev = {
            "id": "dev-002",
            "displayName": "BadDate",
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0",
            "isCompliant": True,
            "isManaged": True,
            "approximateLastSignInDateTime": "definitely-not-iso8601",
            "trustType": "AzureAD",
        }
        with patch("httpx.get", side_effect=_make_mock_get([dev])):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert result["summary"]["stale"] == 0
        assert result["summary"]["unknown_last_seen"] >= 1


class TestDef002EncryptionDefault:
    def test_missing_intune_record_does_not_default_is_encrypted_to_true(self):
        """DEF-002: missing Intune data must NOT set encryption_status=encrypted.
        is_encrypted=True was the old harmful default; now it's UNKNOWN.
        """
        devices = [_build_device("dev-003", "NoIntuneDevice")]
        with patch("httpx.get", side_effect=_make_mock_get(devices, intune_devices=[])):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        ep = result["endpoints"][0]
        assert ep["encryption_status"] == "UNKNOWN", (
            "DEF-002: absent Intune data must NOT default encryption_status to 'encrypted'. "
            "UNKNOWN is the correct indeterminate state."
        )

    def test_intune_403_does_not_produce_unencrypted_finding(self):
        """403 on Intune means access denied — cannot determine encryption status."""
        devices = [_build_device("dev-004", "ForbiddenDevice")]
        with patch("httpx.get", side_effect=_make_mock_get(devices, intune_403=True)):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        encryption_findings = [
            f
            for f in result["findings"]
            if f["finding_type"] == "endpoint.unencrypted_devices"
        ]
        assert encryption_findings == [], (
            "403 on Intune = DENIED. Must NOT produce unencrypted_devices finding."
        )
        assert result["intune_collection_status"] == CollectionStatus.DENIED.value

    def test_intune_403_records_denied_status(self):
        """Intune 403 must be recorded as DENIED, not silently ignored."""
        devices = [_build_device("dev-005", "DeniedDevice")]
        with patch("httpx.get", side_effect=_make_mock_get(devices, intune_403=True)):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        assert "intune_collection_status" in result
        assert result["intune_collection_status"] == CollectionStatus.DENIED.value

    def test_explicit_is_encrypted_true_produces_encrypted_status(self):
        """When Intune provides isEncrypted=True, encryption_status must be encrypted."""
        devices = [_build_device("dev-006", "EncryptedDevice")]
        intune = [
            {
                "id": "int-006",
                "deviceName": "encrypteddevice",
                "operatingSystem": "Windows",
                "complianceState": "compliant",
                "lastSyncDateTime": datetime.now(timezone.utc).isoformat(),
                "isEncrypted": True,
            }
        ]
        with patch("httpx.get", side_effect=_make_mock_get(devices, intune)):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        ep = result["endpoints"][0]
        assert ep["encryption_status"] == "encrypted"

    def test_explicit_is_encrypted_false_produces_unencrypted_finding(self):
        """When Intune provides isEncrypted=False, unencrypted finding must be emitted."""
        devices = [_build_device("dev-007", "UnencryptedDevice")]
        intune = [
            {
                "id": "int-007",
                "deviceName": "unencrypteddevice",
                "operatingSystem": "Windows",
                "complianceState": "compliant",
                "lastSyncDateTime": datetime.now(timezone.utc).isoformat(),
                "isEncrypted": False,
            }
        ]
        with patch("httpx.get", side_effect=_make_mock_get(devices, intune)):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        ep = result["endpoints"][0]
        assert ep["encryption_status"] == "unencrypted"
        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "endpoint.unencrypted_devices" in finding_types
