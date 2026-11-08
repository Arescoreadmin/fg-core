"""OAuth Inventory connector — enumerates OAuth apps and grants via Microsoft Graph.

Collection status disclosure:
- HTTP 403 on app registrations or service principals → DENIED recorded per-source.
- Pagination capped at 20 pages; a hit on the cap produces PARTIAL.
- Overall collection_status reflects the worst per-source status.

NOT_STANDALONE: Part of the FrostGate Core field assessment pipeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from services.connectors.collection_status import CollectionStatus

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 30


def _get_all(
    access_token: str,
    path: str,
    params: dict[str, str] | None = None,
    *,
    page_limit: int = 20,
) -> tuple[list[dict[str, Any]], CollectionStatus]:
    """Fetch paginated Graph results.

    Returns (results, CollectionStatus) where status is COMPLETE, PARTIAL, DENIED, or FAILED.
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
        if resp.status_code in (403, 401):
            return results, CollectionStatus.DENIED
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1

    if url:
        return results, CollectionStatus.PARTIAL
    return results, CollectionStatus.COMPLETE


def run_oauth_inventory(
    *,
    access_token: str,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Run OAuth app inventory scan using a Microsoft Graph access token.

    Returns a raw payload dict compatible with source_type=oauth_inventory.
    Required top-level key: apps (list).
    """
    scan_initiated_at = datetime.now(timezone.utc).isoformat()

    app_regs: list[dict[str, Any]] = []
    app_regs_status = CollectionStatus.FAILED
    try:
        app_regs, app_regs_status = _get_all(
            access_token,
            "/applications",
            {
                "$select": "id,appId,displayName,createdDateTime,signInAudience,requiredResourceAccess"
            },
        )
    except Exception:
        app_regs_status = CollectionStatus.FAILED

    sps: list[dict[str, Any]] = []
    sp_status = CollectionStatus.FAILED
    sp_by_app: dict[str, Any] = {}
    try:
        sps, sp_status = _get_all(
            access_token,
            "/servicePrincipals",
            {"$select": "id,appId,displayName,verifiedPublisher,createdDateTime"},
        )
        sp_by_app = {sp.get("appId", ""): sp for sp in sps}
    except Exception:
        sp_status = CollectionStatus.FAILED

    grants: list[dict[str, Any]] = []
    grants_status = CollectionStatus.FAILED
    try:
        grants, grants_status = _get_all(
            access_token,
            "/oauth2PermissionGrants",
            {"$select": "clientId,consentType,scope"},
        )
    except Exception:
        grants_status = CollectionStatus.FAILED

    apps: list[dict[str, Any]] = []
    for reg in app_regs:
        app_id = reg.get("appId", "")
        sp = sp_by_app.get(app_id, {})
        scope_count = sum(
            len(r.get("resourceAccess", []))
            for r in (reg.get("requiredResourceAccess") or [])
        )
        apps.append(
            {
                "app_id": app_id,
                "display_name": reg.get("displayName", ""),
                "created": reg.get("createdDateTime", ""),
                "sign_in_audience": reg.get("signInAudience", ""),
                "verified_publisher": bool(sp.get("verifiedPublisher")),
                "required_scope_count": scope_count,
            }
        )

    admin_grants = [g for g in grants if g.get("consentType") == "AllPrincipals"]
    unverified = [a for a in apps if not a["verified_publisher"]]
    broad_scope = [a for a in apps if a["required_scope_count"] > 10]

    findings: list[dict[str, Any]] = []

    if admin_grants:
        findings.append(
            {
                "finding_type": "oauth.admin_consented_grants",
                "severity": "high" if len(admin_grants) > 5 else "medium",
                "title": f"Admin-consented OAuth grants detected ({len(admin_grants)})",
                "description": (
                    f"{len(admin_grants)} OAuth permission grants have AllPrincipals (tenant-wide) "
                    "consent. Each grant applies silently to every user in the tenant."
                ),
                "control_id": "NIST-AI-RMF-GOVERN-1.2",
                "affected_count": len(admin_grants),
                "recommendation": (
                    "Review all admin-consented OAuth grants. Revoke any grants for applications "
                    "that do not require tenant-wide access."
                ),
            }
        )

    if unverified:
        findings.append(
            {
                "finding_type": "oauth.unverified_publishers",
                "severity": "medium",
                "title": f"Apps from unverified publishers detected ({len(unverified)})",
                "description": (
                    f"{len(unverified)} OAuth applications are registered by publishers "
                    "who have not completed Microsoft's publisher verification process."
                ),
                "control_id": "NIST-AI-RMF-MAP-1.1",
                "affected_count": len(unverified),
                "recommendation": (
                    "Review all apps from unverified publishers. Remove any not justified "
                    "by a documented business need."
                ),
            }
        )

    if broad_scope:
        findings.append(
            {
                "finding_type": "oauth.broad_scope_apps",
                "severity": "medium",
                "title": f"Apps requesting broad permission scopes ({len(broad_scope)})",
                "description": (
                    f"{len(broad_scope)} registered applications request more than 10 "
                    "API permission scopes, indicating potentially excessive access."
                ),
                "control_id": "NIST-AI-RMF-MANAGE-1.1",
                "affected_count": len(broad_scope),
                "recommendation": (
                    "Review broad-scope apps and reduce permissions to the minimum required "
                    "for business function."
                ),
            }
        )

    scan_completed_at = datetime.now(timezone.utc).isoformat()

    # Overall status: worst of the three sources
    _status_rank = {
        CollectionStatus.FAILED: 0,
        CollectionStatus.DENIED: 1,
        CollectionStatus.PARTIAL: 2,
        CollectionStatus.COMPLETE: 3,
    }
    overall_status = min(
        [app_regs_status, sp_status, grants_status],
        key=lambda s: _status_rank.get(s, 0),
    )

    return {
        "scan_id": uuid.uuid4().hex,
        "scan_type": "oauth_inventory_v1",
        "schema_version": "1.0",
        "engagement_id": engagement_id,
        "scan_initiated_at": scan_initiated_at,
        "scan_completed_at": scan_completed_at,
        "scan_status": "completed",
        "collection_status": overall_status.value,
        "source_statuses": {
            "app_registrations": app_regs_status.value,
            "service_principals": sp_status.value,
            "oauth2_permission_grants": grants_status.value,
        },
        "apps": apps,
        "grants_summary": {
            "total": len(grants),
            "admin_consented": len(admin_grants),
            "user_consented": len(grants) - len(admin_grants),
        },
        "findings": findings,
    }
