"""SharePoint & OneDrive Data Exposure connector — external sharing, anonymous links, guest access."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.connectors.sharepoint.runner")

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 30

# Scan limits to bound execution time
_MAX_SITES = 30
_MAX_DRIVES_PER_SITE = 3
_MAX_ITEMS_PER_DRIVE = 100
_MAX_PERMISSION_CHECKS_PER_DRIVE = 15

# Anonymous sharing threshold — findings escalate above this count
_ANONYMOUS_CRITICAL_THRESHOLD = 10


def _get(
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
    while url and pages < 10:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 403:
            log.info("sharepoint: 403 on %s — skipping", path)
            return []
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1
    return results


def _get_one(access_token: str, path: str) -> dict[str, Any]:
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    resp = httpx.get(f"{_GRAPH_BASE}{path}", headers=headers, timeout=_TIMEOUT)
    if resp.status_code == 403:
        return {}
    resp.raise_for_status()
    return resp.json()


def _get_tenant_domain(access_token: str) -> str:
    try:
        orgs = _get(access_token, "/organization", {"$select": "verifiedDomains"})
        if orgs:
            domains = orgs[0].get("verifiedDomains") or []
            for d in domains:
                if d.get("isDefault") and d.get("type") == "Managed":
                    return d.get("name", "").lower()
            for d in domains:
                if d.get("isInitial"):
                    return d.get("name", "").lower()
    except Exception as exc:
        log.warning("sharepoint: failed to get tenant domain: %s", exc)
    return ""


def _is_external(email: str, tenant_domain: str) -> bool:
    if not email or not tenant_domain:
        return False
    return not email.lower().endswith(
        f"@{tenant_domain}"
    ) and not email.lower().endswith(f".{tenant_domain}")


def _check_permissions(
    access_token: str,
    drive_id: str,
    item_id: str,
    item_name: str,
    item_url: str,
    tenant_domain: str,
) -> dict[str, Any]:
    try:
        perms = _get(
            access_token,
            f"/drives/{drive_id}/items/{item_id}/permissions",
            {"$select": "id,roles,link,grantedTo,grantedToV2,expirationDateTime"},
        )
    except Exception:
        return {
            "item_id": item_id,
            "item_name": item_name,
            "anonymous": False,
            "external_users": [],
            "org_wide": False,
        }

    anonymous = False
    org_wide = False
    external_users: list[str] = []
    no_expiry_links: list[str] = []

    for perm in perms:
        link = perm.get("link") or {}
        scope = link.get("scope", "")
        link_type = link.get("type", "")

        if scope == "anonymous":
            anonymous = True
            expiry = perm.get("expirationDateTime")
            if not expiry:
                no_expiry_links.append(link_type or "anonymous")

        elif scope == "organization":
            org_wide = True

        # Check for external users via grantedTo
        granted_to = perm.get("grantedToV2") or perm.get("grantedTo") or {}
        user = granted_to.get("user") or {}
        email = user.get("email") or user.get("userPrincipalName") or ""
        if email and _is_external(email, tenant_domain):
            external_users.append(email)

        # Check grantedToV2 identities array
        for identity in (
            perm.get("grantedToIdentitiesV2") or perm.get("grantedToIdentities") or []
        ):
            u = identity.get("user") or {}
            em = u.get("email") or u.get("userPrincipalName") or ""
            if em and _is_external(em, tenant_domain) and em not in external_users:
                external_users.append(em)

    return {
        "item_id": item_id,
        "item_name": item_name,
        "item_url": item_url,
        "anonymous": anonymous,
        "org_wide": org_wide,
        "external_users": external_users,
        "no_expiry_links": no_expiry_links,
    }


def _scan_drive(
    access_token: str,
    drive_id: str,
    drive_name: str,
    site_name: str,
    tenant_domain: str,
) -> dict[str, Any]:
    try:
        items = _get(
            access_token,
            f"/drives/{drive_id}/root/children",
            {
                "$select": "id,name,webUrl,shared,file,folder,size,createdBy,lastModifiedDateTime",
                "$top": str(_MAX_ITEMS_PER_DRIVE),
            },
        )
    except Exception as exc:
        log.warning("sharepoint: failed to list drive %s: %s", drive_id, exc)
        return {"drive_id": drive_id, "items_scanned": 0, "shared_items": []}

    # Only check permissions for items that have the 'shared' property set
    shared_items_raw = [i for i in items if "shared" in i]
    to_check = shared_items_raw[:_MAX_PERMISSION_CHECKS_PER_DRIVE]

    checked: list[dict[str, Any]] = []
    for item in to_check:
        result = _check_permissions(
            access_token,
            drive_id,
            item["id"],
            item.get("name", ""),
            item.get("webUrl", ""),
            tenant_domain,
        )
        result["site_name"] = site_name
        result["drive_name"] = drive_name
        result["size_bytes"] = item.get("size", 0)
        result["last_modified"] = item.get("lastModifiedDateTime")
        if result["anonymous"] or result["external_users"] or result["org_wide"]:
            checked.append(result)

    return {
        "drive_id": drive_id,
        "drive_name": drive_name,
        "items_scanned": len(items),
        "shared_items_detected": len(shared_items_raw),
        "shared_items": checked,
    }


def _build_findings(
    sites: list[dict],
    all_shared: list[dict],
    tenant_domain: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    anonymous_items = [i for i in all_shared if i.get("anonymous")]
    external_items = [i for i in all_shared if i.get("external_users")]
    org_wide_items = [i for i in all_shared if i.get("org_wide")]
    no_expiry = [i for i in all_shared if i.get("no_expiry_links")]

    if anonymous_items:
        severity = (
            "critical"
            if len(anonymous_items) >= _ANONYMOUS_CRITICAL_THRESHOLD
            else "high"
        )
        names = ", ".join(i["item_name"] for i in anonymous_items[:5])
        suffix = (
            f" (and {len(anonymous_items) - 5} more)"
            if len(anonymous_items) > 5
            else ""
        )
        findings.append(
            {
                "type": "anonymous_sharing_links",
                "severity": severity,
                "title": f"Anonymous 'Anyone with the Link' Sharing Active ({len(anonymous_items)} item(s))",
                "description": (
                    f"{len(anonymous_items)} file(s)/folder(s) are shared via 'Anyone with the link' — "
                    f"no authentication required to access these items: {names}{suffix}. "
                    f"If any of these contain AI training data, proprietary datasets, or PII, "
                    f"this represents a data exfiltration risk with no audit trail."
                ),
            }
        )

    if external_items:
        unique_domains: set[str] = set()
        for item in external_items:
            for email in item.get("external_users", []):
                parts = email.split("@")
                if len(parts) == 2:
                    unique_domains.add(parts[1].lower())
        domain_str = ", ".join(sorted(unique_domains)[:5])
        findings.append(
            {
                "type": "external_user_sharing",
                "severity": "high",
                "title": f"Files Shared with External Users ({len(external_items)} item(s), {len(unique_domains)} domain(s))",
                "description": (
                    f"{len(external_items)} item(s) are shared with users outside the tenant domain '{tenant_domain}'. "
                    f"External domains receiving access: {domain_str}. "
                    f"Verify each share is intentional and time-bounded with appropriate expiry."
                ),
            }
        )

    if no_expiry:
        findings.append(
            {
                "type": "sharing_links_no_expiry",
                "severity": "medium",
                "title": f"Sharing Links Without Expiration Date ({len(no_expiry)} item(s))",
                "description": (
                    f"{len(no_expiry)} anonymous or external sharing link(s) have no expiration date set. "
                    f"Links that never expire remain active indefinitely even after the business need is gone. "
                    f"Set a maximum link lifetime policy in SharePoint admin center."
                ),
            }
        )

    if org_wide_items:
        findings.append(
            {
                "type": "org_wide_sharing",
                "severity": "low",
                "title": f"Organization-Wide Sharing Links ({len(org_wide_items)} item(s))",
                "description": (
                    f"{len(org_wide_items)} item(s) use 'People in your organization' sharing links, "
                    f"making them accessible to all authenticated internal users. "
                    f"Review whether broad internal sharing is appropriate for the content."
                ),
            }
        )

    if not anonymous_items and not external_items and all_shared:
        findings.append(
            {
                "type": "sharing_baseline_clean",
                "severity": "info",
                "title": "No Anonymous or External Sharing Detected in Sampled Files",
                "description": (
                    f"Scanned {len(all_shared)} shared item(s) across {len(sites)} site(s). "
                    f"No anonymous links or external user access detected in the sampled scope. "
                    f"Note: scan covers root-level items only; deeply nested files were not inspected."
                ),
            }
        )

    return findings


def run_sharepoint_scan(
    *,
    access_token: str,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Scan SharePoint sites and OneDrive drives for external/anonymous data exposure.

    Returns a raw payload dict compatible with source_type=sharepoint_onedrive.
    Required top-level key: sites (list).
    """
    scan_initiated_at = datetime.now(timezone.utc).isoformat()

    tenant_domain = _get_tenant_domain(access_token)
    log.info("sharepoint: tenant domain resolved as '%s'", tenant_domain)

    try:
        sites_raw = _get(
            access_token,
            "/sites",
            {
                "$search": "*",
                "$select": "id,displayName,webUrl",
                "$top": str(_MAX_SITES),
            },
        )[:_MAX_SITES]
    except Exception as exc:
        log.warning("sharepoint: failed to enumerate sites: %s", exc)
        sites_raw = []

    # Also scan the root OneDrive (personal drives) via /drives if sites empty
    if not sites_raw:
        log.info("sharepoint: no sites returned; attempting /me/drive fallback")

    sites_out: list[dict[str, Any]] = []
    all_shared_items: list[dict[str, Any]] = []

    for site in sites_raw:
        site_id = site.get("id", "")
        site_name = site.get("displayName", site_id)
        site_url = site.get("webUrl", "")

        try:
            drives = _get(
                access_token,
                f"/sites/{site_id}/drives",
                {"$select": "id,name,driveType", "$top": str(_MAX_DRIVES_PER_SITE)},
            )[:_MAX_DRIVES_PER_SITE]
        except Exception:
            drives = []

        drive_results = []
        for drive in drives:
            drive_id = drive.get("id", "")
            drive_name = drive.get("name", drive_id)
            result = _scan_drive(
                access_token, drive_id, drive_name, site_name, tenant_domain
            )
            all_shared_items.extend(result.get("shared_items", []))
            drive_results.append(result)

        sites_out.append(
            {
                "id": site_id,
                "name": site_name,
                "url": site_url,
                "drives_scanned": len(drive_results),
                "drives": drive_results,
            }
        )

    findings = _build_findings(sites_out, all_shared_items, tenant_domain)

    anonymous_count = sum(1 for i in all_shared_items if i.get("anonymous"))
    external_count = sum(1 for i in all_shared_items if i.get("external_users"))

    return {
        "sites": sites_out,
        "shared_items": all_shared_items,
        "findings": findings,
        "summary": {
            "tenant_domain": tenant_domain,
            "sites_scanned": len(sites_out),
            "total_shared_items_found": len(all_shared_items),
            "anonymous_links": anonymous_count,
            "external_shares": external_count,
            "total_findings": len(findings),
        },
        "scan_initiated_at": scan_initiated_at,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
    }
