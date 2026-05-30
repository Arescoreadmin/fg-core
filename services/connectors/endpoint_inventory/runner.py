"""Endpoint Inventory connector — enumerates devices via Microsoft Graph."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 30
_STALE_DAYS = 90


def _get_all(
    access_token: str, path: str, params: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    base: str = f"{_GRAPH_BASE}{path}"
    if params:
        base = base + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    url: str | None = base

    results: list[dict[str, Any]] = []
    pages = 0
    while url and pages < 20:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 403:
            break
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1
    return results


def run_endpoint_inventory(
    *,
    access_token: str,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Run endpoint/device inventory scan using a Microsoft Graph access token.

    Returns a raw payload dict compatible with source_type=endpoint_inventory.
    Required top-level key: endpoints (list).
    """
    scan_initiated_at = datetime.now(timezone.utc).isoformat()
    now_utc = datetime.now(timezone.utc)
    stale_cutoff = now_utc - timedelta(days=_STALE_DAYS)

    try:
        devices = _get_all(
            access_token,
            "/devices",
            {
                "$select": (
                    "id,displayName,operatingSystem,operatingSystemVersion,"
                    "isCompliant,isManaged,approximateLastSignInDateTime,trustType"
                )
            },
        )
    except Exception:
        devices = []

    # Intune managed devices (requires DeviceManagementManagedDevices.Read.All)
    # Attempt but gracefully skip if scope is absent.
    try:
        intune_devices = _get_all(
            access_token,
            "/deviceManagement/managedDevices",
            {
                "$select": "id,deviceName,operatingSystem,complianceState,lastSyncDateTime,isEncrypted"
            },
        )
    except Exception:
        intune_devices = []

    intune_by_name = {d.get("deviceName", "").lower(): d for d in intune_devices}

    endpoints: list[dict[str, Any]] = []
    stale_ids: list[str] = []
    non_compliant_ids: list[str] = []
    unmanaged_ids: list[str] = []
    unencrypted_ids: list[str] = []

    for dev in devices:
        dev_id = dev.get("id", "")
        last_seen_raw = dev.get("approximateLastSignInDateTime", "")
        is_stale = False
        if last_seen_raw:
            try:
                last_seen = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
                is_stale = last_seen < stale_cutoff
            except ValueError:
                pass

        is_managed = bool(dev.get("isManaged"))
        is_compliant = dev.get("isCompliant")

        display_name = dev.get("displayName", "").lower()
        intune = intune_by_name.get(display_name, {})
        is_encrypted = bool(intune.get("isEncrypted", True))

        endpoints.append(
            {
                "device_id": dev_id,
                "display_name": dev.get("displayName", ""),
                "os": dev.get("operatingSystem", ""),
                "os_version": dev.get("operatingSystemVersion", ""),
                "is_managed": is_managed,
                "is_compliant": is_compliant,
                "is_stale": is_stale,
                "trust_type": dev.get("trustType", ""),
                "last_seen": last_seen_raw,
            }
        )

        if is_stale:
            stale_ids.append(dev_id)
        if not is_managed:
            unmanaged_ids.append(dev_id)
        if is_compliant is False:
            non_compliant_ids.append(dev_id)
        if not is_encrypted and intune:
            unencrypted_ids.append(dev_id)

    findings: list[dict[str, Any]] = []

    if non_compliant_ids:
        findings.append(
            {
                "finding_type": "endpoint.non_compliant_devices",
                "severity": "high",
                "title": f"Non-compliant managed devices detected ({len(non_compliant_ids)})",
                "description": (
                    f"{len(non_compliant_ids)} Azure AD-registered devices have a "
                    "non-compliant compliance state in Microsoft Intune."
                ),
                "control_id": "NIST-AI-RMF-MANAGE-2.2",
                "affected_count": len(non_compliant_ids),
                "recommendation": (
                    "Investigate non-compliant devices. Enforce compliance policies via "
                    "Conditional Access to block resource access until remediated."
                ),
            }
        )

    if unmanaged_ids:
        findings.append(
            {
                "finding_type": "endpoint.unmanaged_devices",
                "severity": "high",
                "title": f"Unmanaged devices in tenant ({len(unmanaged_ids)})",
                "description": (
                    f"{len(unmanaged_ids)} devices are registered in Azure AD but are "
                    "not managed by an MDM/MAM solution (Intune or equivalent)."
                ),
                "control_id": "NIST-AI-RMF-MAP-3.5",
                "affected_count": len(unmanaged_ids),
                "recommendation": (
                    "Enroll unmanaged devices in Microsoft Intune or an equivalent MDM. "
                    "Consider requiring compliant devices via Conditional Access."
                ),
            }
        )

    if stale_ids:
        findings.append(
            {
                "finding_type": "endpoint.stale_devices",
                "severity": "medium",
                "title": f"Stale devices not seen in {_STALE_DAYS} days ({len(stale_ids)})",
                "description": (
                    f"{len(stale_ids)} devices have not signed in for over {_STALE_DAYS} days. "
                    "Stale devices represent unmonitored attack surface."
                ),
                "control_id": "NIST-AI-RMF-MANAGE-1.3",
                "affected_count": len(stale_ids),
                "recommendation": (
                    "Disable or delete stale device objects. Establish a device lifecycle "
                    "management policy with regular cleanup cadence."
                ),
            }
        )

    if unencrypted_ids:
        findings.append(
            {
                "finding_type": "endpoint.unencrypted_devices",
                "severity": "high",
                "title": f"Managed devices without disk encryption ({len(unencrypted_ids)})",
                "description": (
                    f"{len(unencrypted_ids)} Intune-managed devices do not have disk "
                    "encryption enabled (BitLocker or equivalent)."
                ),
                "control_id": "NIST-AI-RMF-MANAGE-2.4",
                "affected_count": len(unencrypted_ids),
                "recommendation": (
                    "Enforce disk encryption via Intune device configuration policy. "
                    "Block non-encrypted devices from accessing sensitive resources."
                ),
            }
        )

    scan_completed_at = datetime.now(timezone.utc).isoformat()

    return {
        "scan_id": uuid.uuid4().hex,
        "scan_type": "endpoint_inventory_v1",
        "schema_version": "1.0",
        "engagement_id": engagement_id,
        "scan_initiated_at": scan_initiated_at,
        "scan_completed_at": scan_completed_at,
        "scan_status": "completed",
        "endpoints": endpoints,
        "summary": {
            "total": len(endpoints),
            "managed": len(endpoints) - len(unmanaged_ids),
            "unmanaged": len(unmanaged_ids),
            "compliant": len([e for e in endpoints if e.get("is_compliant") is True]),
            "non_compliant": len(non_compliant_ids),
            "stale": len(stale_ids),
        },
        "findings": findings,
    }
