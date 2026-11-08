"""Endpoint Inventory connector — enumerates devices via Microsoft Graph.

DEF-002 (closed): Unknown/missing device last_seen timestamps now produce
EndpointTimestampStatus.ABSENT and is_stale=None (INDETERMINATE) rather than
silently defaulting to is_stale=False (treated as active/healthy).

Additional corrections:
- Invalid timestamp (parse failure) → INVALID, is_stale=None
- HTTP 403 on device or Intune collection → DENIED, recorded explicitly
- is_encrypted defaults removed: missing Intune data → encryption_status=UNKNOWN
- collection_status emitted at the top level

NOT_STANDALONE: Part of the FrostGate Core field assessment pipeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from services.connectors.collection_status import (
    CollectionStatus,
    EndpointTimestampStatus,
)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 30
_STALE_DAYS = 90


class _GraphPermissionDenied(Exception):
    """Raised when the Graph API returns HTTP 403."""


def _get_all(
    access_token: str,
    path: str,
    params: dict[str, str] | None = None,
    *,
    page_limit: int = 20,
) -> tuple[list[dict[str, Any]], CollectionStatus]:
    """Fetch all pages for a Graph API path.

    Returns (results, status) where status is:
    - COMPLETE   : all pages fetched within page_limit
    - PARTIAL    : page_limit reached before source was exhausted
    - DENIED     : HTTP 403
    - FAILED     : non-403 error
    """
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    base: str = f"{_GRAPH_BASE}{path}"
    if params:
        base = base + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    url: str | None = base

    results: list[dict[str, Any]] = []
    pages = 0
    while url and pages < page_limit:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 403:
            return results, CollectionStatus.DENIED
        if resp.status_code == 401:
            return results, CollectionStatus.DENIED
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1

    # If there's still a nextLink, we hit the page cap
    if url:
        return results, CollectionStatus.PARTIAL
    return results, CollectionStatus.COMPLETE


def _classify_timestamp(
    raw: str | None,
    stale_cutoff: datetime,
) -> tuple[EndpointTimestampStatus, bool | None]:
    """Classify a device last-seen timestamp.

    Returns (timestamp_status, is_stale) where is_stale is:
    - True   : timestamp is known and device is stale
    - False  : timestamp is known and device is not stale
    - None   : timestamp is absent, invalid, or indeterminate
    """
    if not raw:
        return EndpointTimestampStatus.ABSENT, None

    try:
        last_seen = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        # Ensure timezone-aware comparison
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        is_stale = last_seen < stale_cutoff
        return EndpointTimestampStatus.KNOWN, is_stale
    except (ValueError, TypeError):
        return EndpointTimestampStatus.INVALID, None


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

    # Device collection
    devices: list[dict[str, Any]] = []
    devices_collection_status = CollectionStatus.FAILED
    try:
        devices, devices_collection_status = _get_all(
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
        devices_collection_status = CollectionStatus.FAILED

    # Intune managed devices (requires DeviceManagementManagedDevices.Read.All)
    intune_devices: list[dict[str, Any]] = []
    intune_collection_status = CollectionStatus.FAILED
    try:
        intune_devices, intune_collection_status = _get_all(
            access_token,
            "/deviceManagement/managedDevices",
            {
                "$select": "id,deviceName,operatingSystem,complianceState,lastSyncDateTime,isEncrypted"
            },
        )
    except Exception:
        intune_collection_status = CollectionStatus.FAILED

    intune_by_name = {d.get("deviceName", "").lower(): d for d in intune_devices}
    intune_available = intune_collection_status not in (
        CollectionStatus.DENIED,
        CollectionStatus.FAILED,
    )

    endpoints: list[dict[str, Any]] = []
    stale_ids: list[str] = []
    non_compliant_ids: list[str] = []
    unmanaged_ids: list[str] = []
    unencrypted_ids: list[str] = []
    unknown_timestamp_ids: list[str] = []

    for dev in devices:
        dev_id = dev.get("id", "")
        last_seen_raw = dev.get("approximateLastSignInDateTime") or ""

        ts_status, is_stale = _classify_timestamp(last_seen_raw, stale_cutoff)

        is_managed = bool(dev.get("isManaged"))
        is_compliant = dev.get("isCompliant")

        # Encryption status: only knowable from Intune data
        display_name = dev.get("displayName", "").lower()
        intune = intune_by_name.get(display_name) if intune_available else None

        if intune is not None and "isEncrypted" in intune:
            # Intune data present with explicit field
            is_encrypted: bool | None = bool(intune["isEncrypted"])
        elif intune is not None:
            # Intune record exists but isEncrypted field absent
            is_encrypted = None
        else:
            # No Intune record for this device (or Intune not available)
            is_encrypted = None

        endpoint: dict[str, Any] = {
            "device_id": dev_id,
            "display_name": dev.get("displayName", ""),
            "os": dev.get("operatingSystem", ""),
            "os_version": dev.get("operatingSystemVersion", ""),
            "is_managed": is_managed,
            "is_compliant": is_compliant,
            "is_stale": is_stale,
            "last_seen_timestamp_status": ts_status.value,
            "trust_type": dev.get("trustType", ""),
            "last_seen": last_seen_raw or None,
            "encryption_status": (
                "encrypted"
                if is_encrypted is True
                else "unencrypted"
                if is_encrypted is False
                else "UNKNOWN"
            ),
        }
        endpoints.append(endpoint)

        # Only classify stale when timestamp is definitively known
        if is_stale is True:
            stale_ids.append(dev_id)
        elif ts_status != EndpointTimestampStatus.KNOWN:
            unknown_timestamp_ids.append(dev_id)

        if not is_managed:
            unmanaged_ids.append(dev_id)
        if is_compliant is False:
            non_compliant_ids.append(dev_id)
        # Only flag unencrypted when we have definitive evidence (is_encrypted=False)
        if is_encrypted is False and intune:
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

    # Overall collection status
    if devices_collection_status == CollectionStatus.DENIED:
        overall_status = CollectionStatus.DENIED.value
    elif devices_collection_status == CollectionStatus.FAILED:
        overall_status = CollectionStatus.FAILED.value
    elif devices_collection_status == CollectionStatus.PARTIAL:
        overall_status = CollectionStatus.PARTIAL.value
    else:
        overall_status = CollectionStatus.COMPLETE.value

    return {
        "scan_id": uuid.uuid4().hex,
        "scan_type": "endpoint_inventory_v1",
        "schema_version": "1.0",
        "engagement_id": engagement_id,
        "scan_initiated_at": scan_initiated_at,
        "scan_completed_at": scan_completed_at,
        "scan_status": "completed",
        "collection_status": overall_status,
        "devices_collection_status": devices_collection_status.value,
        "intune_collection_status": intune_collection_status.value,
        "endpoints": endpoints,
        "summary": {
            "total": len(endpoints),
            "managed": len(endpoints) - len(unmanaged_ids),
            "unmanaged": len(unmanaged_ids),
            "compliant": len([e for e in endpoints if e.get("is_compliant") is True]),
            "non_compliant": len(non_compliant_ids),
            "stale": len(stale_ids),
            "unknown_last_seen": len(unknown_timestamp_ids),
        },
        "findings": findings,
        "coverage_notes": {
            "intune_data_available": intune_available,
            "intune_collection_status": intune_collection_status.value,
            "devices_with_unknown_timestamp": len(unknown_timestamp_ids),
            "stale_assessment_note": (
                f"{len(unknown_timestamp_ids)} devices have no or invalid last-seen "
                "timestamp; their staleness is INDETERMINATE and they are excluded from "
                "the stale device count."
            )
            if unknown_timestamp_ids
            else None,
        },
    }
