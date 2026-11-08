"""L14-SCAN-ACCURACY-001 — Endpoint inventory known-answer accuracy tests.

Updated by L14-SCAN-COMPLETENESS-001: DEF-002 closed. Unknown/missing last-seen
timestamps now produce is_stale=None and last_seen_timestamp_status=ABSENT/INVALID
rather than silently defaulting to is_stale=False.

Calls real endpoint_inventory runner classification logic.
Mocks only httpx.get (external I/O to Graph API).

Critical truth conditions tested:
- Missing encryption data != confirmed encryption failure
- Intune access denied != zero compliant devices
- Unknown last-seen → INDETERMINATE (is_stale=None), NOT is_stale=False (DEF-002 closed)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _engagement_id() -> str:
    return "test-engagement-endpoint-accuracy-001"


def _build_device(
    dev_id: str,
    display_name: str,
    is_managed: bool = True,
    is_compliant: bool | None = True,
    last_seen_days_ago: int | None = 1,
) -> dict:
    last_seen = None
    if last_seen_days_ago is not None:
        last_seen = (
            datetime.now(timezone.utc) - timedelta(days=last_seen_days_ago)
        ).isoformat()
    return {
        "id": dev_id,
        "displayName": display_name,
        "operatingSystem": "Windows",
        "operatingSystemVersion": "10.0",
        "isCompliant": is_compliant,
        "isManaged": is_managed,
        "approximateLastSignInDateTime": last_seen or "",
        "trustType": "AzureAD",
    }


def _run_with_devices(
    devices: list[dict], intune_devices: list[dict] | None = None
) -> dict:
    if intune_devices is None:
        intune_devices = []

    def _mock_get(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status = MagicMock(return_value=None)
        if "deviceManagement" in url:
            if intune_devices == "403":
                resp.status_code = 403
                resp.json.return_value = {}
            else:
                resp.status_code = 200
                resp.json.return_value = {"value": intune_devices}
        else:
            resp.status_code = 200
            resp.json.return_value = {"value": devices}
        return resp

    with patch("httpx.get", side_effect=_mock_get):
        return run_endpoint_inventory(
            access_token="mock-token",
            tenant_id="tenant-001",
            engagement_id=_engagement_id(),
        )


# ---------------------------------------------------------------------------
# SA-EP-001: managed_compliant_encrypted → clean finding (no issue)
# ---------------------------------------------------------------------------


class TestManagedCompliantEncrypted:
    def test_compliant_managed_device_no_findings(self):
        devices = [
            _build_device("dev-001", "GoodDevice", is_managed=True, is_compliant=True)
        ]
        intune = [
            {
                "id": "intune-001",
                "deviceName": "gooddevice",
                "operatingSystem": "Windows",
                "complianceState": "compliant",
                "lastSyncDateTime": datetime.now(timezone.utc).isoformat(),
                "isEncrypted": True,
            }
        ]
        result = _run_with_devices(devices, intune)

        assert result["findings"] == [], (
            "Managed, compliant, encrypted device must produce no findings."
        )
        assert result["summary"]["total"] == 1

    def test_scan_id_always_present(self):
        result = _run_with_devices([])
        assert result.get("scan_id")
        assert result.get("engagement_id") == _engagement_id()


# ---------------------------------------------------------------------------
# SA-EP-002: managed_noncompliant → ENDPOINT_NONCOMPLIANT
# ---------------------------------------------------------------------------


class TestManagedNoncompliant:
    def test_non_compliant_device_produces_finding(self):
        devices = [
            _build_device("dev-002", "BadDevice", is_managed=True, is_compliant=False)
        ]
        result = _run_with_devices(devices)

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "endpoint.non_compliant_devices" in finding_types

    def test_non_compliant_finding_severity(self):
        devices = [
            _build_device("dev-002", "BadDevice", is_managed=True, is_compliant=False)
        ]
        result = _run_with_devices(devices)

        for f in result["findings"]:
            if f["finding_type"] == "endpoint.non_compliant_devices":
                assert f["severity"] in ("critical", "high", "medium", "low")


# ---------------------------------------------------------------------------
# SA-EP-003: unmanaged_device → UNMANAGED_DEVICE
# ---------------------------------------------------------------------------


class TestUnmanagedDevice:
    def test_unmanaged_device_produces_finding(self):
        devices = [
            _build_device(
                "dev-003", "UnmanagedDevice", is_managed=False, is_compliant=None
            )
        ]
        result = _run_with_devices(devices)

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "endpoint.unmanaged_devices" in finding_types


# ---------------------------------------------------------------------------
# SA-EP-004: CRITICAL — encryption_unknown != UNENCRYPTED
# ---------------------------------------------------------------------------


class TestEncryptionUnknown:
    """CRITICAL TRUTH CONDITION: When Intune data is unavailable (device not in Intune,
    or Intune not enrolled), the encryption status is UNKNOWN.
    It must NOT be classified as UNENCRYPTED.
    """

    def test_no_intune_data_does_not_produce_unencrypted_finding(self):
        """Device in Azure AD but not in Intune — encryption status is unknown."""
        devices = [
            _build_device(
                "dev-004", "NoIntuneDevice", is_managed=True, is_compliant=True
            )
        ]
        # Empty intune_devices — no Intune enrollment
        result = _run_with_devices(devices, intune_devices=[])

        encryption_findings = [
            f
            for f in result["findings"]
            if f["finding_type"] == "endpoint.unencrypted_devices"
        ]
        assert encryption_findings == [], (
            "No Intune data means encryption status is UNKNOWN, not UNENCRYPTED. "
            "Must NOT produce unencrypted_devices finding without Intune evidence."
        )


# ---------------------------------------------------------------------------
# SA-EP-005: CRITICAL — intune_access_denied != zero_compliant_devices
# ---------------------------------------------------------------------------


class TestIntuneAccessDenied:
    """CRITICAL TRUTH CONDITION: When Intune returns 403 (access denied),
    the scanner cannot determine device compliance from Intune.
    It must NOT produce findings claiming zero compliant or zero encrypted devices.
    """

    def test_intune_403_does_not_produce_zero_encrypted_devices(self):
        devices = [
            _build_device(
                "dev-005", "MaybeEncrypted", is_managed=True, is_compliant=True
            )
        ]
        result = _run_with_devices(devices, intune_devices="403")

        encryption_findings = [
            f
            for f in result["findings"]
            if f["finding_type"] == "endpoint.unencrypted_devices"
        ]
        assert encryption_findings == [], (
            "403 on Intune = access denied. Must NOT claim zero encrypted devices. "
            "Access denied != zero compliant devices."
        )


# ---------------------------------------------------------------------------
# SA-EP-006: stale_device_known_date → STALE_DEVICE with date
# ---------------------------------------------------------------------------


class TestStaleDeviceKnownDate:
    def test_stale_device_120_days_produces_finding(self):
        devices = [_build_device("dev-006", "OldDevice", last_seen_days_ago=120)]
        result = _run_with_devices(devices)

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "endpoint.stale_devices" in finding_types

    def test_recent_device_no_stale_finding(self):
        devices = [_build_device("dev-007", "NewDevice", last_seen_days_ago=1)]
        result = _run_with_devices(devices)

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "endpoint.stale_devices" not in finding_types


# ---------------------------------------------------------------------------
# SA-EP-007: DEF-002 CLOSED — unknown timestamp → INDETERMINATE, not is_stale=False
# ---------------------------------------------------------------------------


class TestStaleDeviceUnknownTimestamp:
    """DEF-002 closed: A device with no last-seen timestamp produces:
    - is_stale=None (INDETERMINATE), NOT is_stale=False
    - last_seen_timestamp_status=ABSENT
    - Device excluded from stale_count in summary
    """

    def test_unknown_last_seen_produces_indeterminate_not_false(self):
        """DEF-002 closed: empty last_seen → is_stale=None, not is_stale=False."""
        devices = [
            _build_device("dev-008", "UnknownDateDevice", last_seen_days_ago=None)
        ]
        result = _run_with_devices(devices)

        assert len(result["endpoints"]) == 1
        ep = result["endpoints"][0]

        assert ep["is_stale"] is None, (
            "DEF-002 closed: unknown last_seen must produce is_stale=None "
            "(INDETERMINATE), not is_stale=False (which implies the device is active)."
        )
        assert ep["last_seen_timestamp_status"] == "ABSENT", (
            "Missing timestamp must be classified as ABSENT, not KNOWN."
        )
        assert ep["last_seen"] is None

    def test_unknown_last_seen_excluded_from_stale_count(self):
        """Devices with unknown timestamps must not inflate the stale count."""
        devices = [
            _build_device("dev-008", "UnknownDateDevice", last_seen_days_ago=None)
        ]
        result = _run_with_devices(devices)

        assert result["summary"]["stale"] == 0, (
            "Device with unknown timestamp must not be counted as stale."
        )
        assert result["summary"]["unknown_last_seen"] == 1, (
            "Device with unknown timestamp must be counted in unknown_last_seen."
        )

    def test_no_stale_finding_from_unknown_timestamp(self):
        """Unknown timestamp must not produce a stale_devices finding."""
        devices = [
            _build_device("dev-009", "UnknownDateDevice2", last_seen_days_ago=None)
        ]
        result = _run_with_devices(devices)

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "endpoint.stale_devices" not in finding_types, (
            "DEF-002: unknown last_seen must NOT produce stale_devices finding."
        )

    def test_invalid_timestamp_produces_indeterminate(self):
        """Invalid/malformed timestamp → is_stale=None, last_seen_timestamp_status=INVALID."""
        # Build a device with a bad timestamp
        dev = {
            "id": "dev-010",
            "displayName": "BadTimestampDevice",
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0",
            "isCompliant": True,
            "isManaged": True,
            "approximateLastSignInDateTime": "not-a-date",
            "trustType": "AzureAD",
        }
        result = _run_with_devices([dev])

        assert len(result["endpoints"]) == 1
        ep = result["endpoints"][0]

        assert ep["is_stale"] is None, (
            "Invalid timestamp must produce INDETERMINATE (is_stale=None)."
        )
        assert ep["last_seen_timestamp_status"] == "INVALID"


# ---------------------------------------------------------------------------
# SA-EP-008: scan provenance
# ---------------------------------------------------------------------------


class TestEndpointScanProvenance:
    def test_scan_has_all_provenance_fields(self):
        result = _run_with_devices([])
        assert "scan_id" in result
        assert "engagement_id" in result
        assert "scan_initiated_at" in result
        assert "scan_completed_at" in result
        assert result["scan_type"] == "endpoint_inventory_v1"
        assert "collection_status" in result

    def test_summary_always_present(self):
        result = _run_with_devices([])
        assert "summary" in result
        assert "total" in result["summary"]
        assert "unknown_last_seen" in result["summary"]
