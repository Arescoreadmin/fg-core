"""AI Tool Discovery scan using read-only Microsoft Graph evidence."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from services.connectors.ai_tool_discovery.vendor_registry import match_ai_vendor

log = logging.getLogger("frostgate.connectors.ai_tool_discovery.runner")

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 30
_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

_SENSITIVE_PERMISSIONS = {
    "Files.Read.All": "files_read_all",
    "Files.ReadWrite.All": "files_read_write_all",
    "Mail.Read": "mail_read",
    "Mail.Read.All": "mail_read",
    "Mail.ReadWrite": "mail_read_write",
    "Mail.ReadWrite.All": "mail_read_write",
    "Directory.Read.All": "directory_read_all",
    "Directory.ReadWrite.All": "directory_read_write_all",
    "offline_access": "offline_access",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_all(
    access_token: str, path: str, params: dict[str, str] | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{_GRAPH_BASE}{path}"
    if params:
        url = url + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    rows: list[dict[str, Any]] = []
    pages = 0
    while url and pages < 20:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code in {403, 404}:
            log.info(
                "ai_tool_discovery: optional source unavailable: %s %s",
                path,
                resp.status_code,
            )
            return rows, {
                "status": "skipped",
                "status_code": resp.status_code,
                "path": path,
            }
        resp.raise_for_status()
        data = resp.json()
        rows.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1
    return rows, {"status": "collected", "count": len(rows), "path": path}


def _publisher(sp: dict[str, Any]) -> tuple[str, bool]:
    verified = sp.get("verifiedPublisher") or {}
    name = verified.get("displayName") if isinstance(verified, dict) else None
    publisher = (
        name or sp.get("publisherName") or sp.get("appOwnerOrganizationId") or "unknown"
    )
    return str(publisher or "unknown"), bool(name)


def _split_scope(scope: Any) -> list[str]:
    return sorted({s for s in str(scope or "").split() if s})


def _graph_role_map(service_principals: list[dict[str, Any]]) -> dict[str, str]:
    for sp in service_principals:
        if sp.get("appId") == _GRAPH_APP_ID:
            return {
                str(role.get("id")): str(
                    role.get("value") or role.get("displayName") or "unknown"
                )
                for role in sp.get("appRoles", [])
                if role.get("id")
            }
    return {}


def _risk_indicators(tool: dict[str, Any]) -> list[str]:
    indicators = {"ai_vendor_detected"}
    if not tool["verified_publisher"]:
        indicators.add("unverified_publisher")
    if tool["admin_consent"]:
        indicators.add("admin_consent_granted")
    if tool["consent_type"] == "AllPrincipals":
        indicators.add("tenant_wide_access")
    permissions = set(tool["delegated_permissions"]) | set(
        tool["application_permissions"]
    )
    for permission, indicator in _SENSITIVE_PERMISSIONS.items():
        if permission in permissions:
            indicators.add(indicator)
    if permissions & set(_SENSITIVE_PERMISSIONS):
        indicators.add("sensitive_permissions")
    if len(permissions) >= 10:
        indicators.add("broad_scope_access")
    if tool["publisher"] == "unknown":
        indicators.add("unknown_owner")
    if tool["last_seen"] == "unknown":
        indicators.add("inactive_application")
    return sorted(indicators)


def _permissions_summary(delegated: list[str], app_permissions: list[str]) -> str:
    parts = []
    if delegated:
        parts.append(f"delegated:{len(delegated)}")
    if app_permissions:
        parts.append(f"application:{len(app_permissions)}")
    return ", ".join(parts) if parts else "unknown"


def run_ai_tool_discovery(
    *, access_token: str, tenant_id: str, engagement_id: str
) -> dict[str, Any]:
    scan_started = _utc_now()
    apps, apps_status = _get_all(
        access_token,
        "/applications",
        {"$select": "id,appId,displayName,web,identifierUris,createdDateTime"},
    )
    service_principals, sp_status = _get_all(
        access_token,
        "/servicePrincipals",
        {
            "$select": "id,appId,displayName,verifiedPublisher,publisherName,appOwnerOrganizationId,createdDateTime,appRoles"
        },
    )
    grants, grants_status = _get_all(
        access_token,
        "/oauth2PermissionGrants",
        {"$select": "clientId,principalId,resourceId,scope,consentType"},
    )
    app_roles, app_roles_status = _get_all(
        access_token,
        "/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo",
        {"$select": "principalId,appRoleId,resourceId"},
    )
    signins, signins_status = _get_all(
        access_token,
        "/auditLogs/signIns",
        {"$top": "50", "$select": "appId,appDisplayName,createdDateTime"},
    )
    audit_logs, audit_status = _get_all(
        access_token,
        "/auditLogs/directoryAudits",
        {
            "$top": "50",
            "$select": "activityDateTime,activityDisplayName,targetResources",
        },
    )

    app_reg_by_app_id = {str(app.get("appId")): app for app in apps if app.get("appId")}
    role_map = _graph_role_map(service_principals)

    delegated_by_sp: dict[str, list[str]] = {}
    consent_by_sp: dict[str, str] = {}
    principal_ids_by_sp: dict[str, set[str]] = {}
    for grant in grants:
        client_id = str(grant.get("clientId") or "")
        if not client_id:
            continue
        delegated_by_sp.setdefault(client_id, [])
        delegated_by_sp[client_id].extend(_split_scope(grant.get("scope")))
        consent_by_sp[client_id] = str(grant.get("consentType") or "unknown")
        if grant.get("principalId"):
            principal_ids_by_sp.setdefault(client_id, set()).add(
                str(grant["principalId"])
            )

    app_permissions_by_sp: dict[str, list[str]] = {}
    for assignment in app_roles:
        principal_id = str(assignment.get("principalId") or "")
        if not principal_id:
            continue
        permission = role_map.get(str(assignment.get("appRoleId"))) or "unknown"
        app_permissions_by_sp.setdefault(principal_id, []).append(permission)

    last_seen_by_app_id: dict[str, str] = {}
    for row in signins:
        app_id = str(row.get("appId") or "")
        created = str(row.get("createdDateTime") or "")
        if app_id and created and created > last_seen_by_app_id.get(app_id, ""):
            last_seen_by_app_id[app_id] = created

    tools: list[dict[str, Any]] = []
    for sp in service_principals:
        app_id = str(sp.get("appId") or "")
        display_name = str(sp.get("displayName") or "unknown")
        app_reg = app_reg_by_app_id.get(app_id, {})
        domains: list[str] = []
        web = app_reg.get("web") if isinstance(app_reg, dict) else {}
        if isinstance(web, dict):
            domains.extend(web.get("redirectUris") or [])
            if web.get("homePageUrl"):
                domains.append(web["homePageUrl"])
        if isinstance(app_reg, dict):
            domains.extend(app_reg.get("identifierUris") or [])
        publisher, verified_publisher = _publisher(sp)
        match = match_ai_vendor(
            display_name=display_name,
            publisher=publisher,
            app_id=app_id,
            domains=domains,
        )
        if not match:
            continue
        sp_id = str(sp.get("id") or "unknown")
        delegated = sorted(set(delegated_by_sp.get(sp_id, [])))
        app_permissions = sorted(set(app_permissions_by_sp.get(sp_id, [])))
        consent_type = consent_by_sp.get(sp_id, "unknown")
        tool = {
            "tool_name": match["product_name"],
            "vendor": match["vendor_name"],
            "publisher": publisher,
            "verified_publisher": verified_publisher,
            "application_id": app_id or "unknown",
            "service_principal_id": sp_id,
            "app_registration_id": str(app_reg.get("id") or "unknown")
            if isinstance(app_reg, dict)
            else "unknown",
            "delegated_permissions": delegated,
            "application_permissions": app_permissions,
            "permissions_summary": _permissions_summary(delegated, app_permissions),
            "admin_consent": consent_type == "AllPrincipals",
            "consent_type": consent_type,
            "assigned_users": sorted(principal_ids_by_sp.get(sp_id, set())),
            "assigned_groups": [],
            "last_seen": last_seen_by_app_id.get(app_id, "unknown"),
            "matched_signature": match["signature"],
            "risk_indicators": [],
            "evidence_refs": [],
            "confidence": match["confidence"],
            "source": "microsoft_graph",
            "discovery_method": ",".join(match["match_reasons"]),
            "graph_node_id": f"ai_tool:{tenant_id}:{app_id or sp_id}",
        }
        tool["risk_indicators"] = _risk_indicators(tool)
        tool["evidence_refs"] = [
            f"servicePrincipal:{sp_id}",
            f"application:{tool['application_id']}",
        ]
        tools.append(tool)

    tools.sort(
        key=lambda item: (
            item["vendor"].casefold(),
            item["tool_name"].casefold(),
            item["application_id"],
        )
    )
    findings: list[dict[str, Any]] = []
    overprivileged = [
        t
        for t in tools
        if set(t["risk_indicators"])
        & {
            "files_read_write_all",
            "mail_read_write",
            "directory_read_write_all",
            "broad_scope_access",
        }
    ]
    if overprivileged:
        findings.append(
            {
                "type": "ai_tool_sensitive_permissions",
                "severity": "medium",
                "title": f"AI tools with sensitive enterprise data permissions detected ({len(overprivileged)})",
                "description": f"{len(overprivileged)} discovered AI-connected applications have sensitive or broad Microsoft 365 permissions. This is an evidence-backed governance review input, not an automatic risk determination.",
                "affected_count": len(overprivileged),
                "evidence_refs": [t["application_id"] for t in overprivileged],
                "recommendation": "Review business justification, approver, and least-privilege scope for each AI-connected application.",
            }
        )
    unverified = [t for t in tools if "unverified_publisher" in t["risk_indicators"]]
    if unverified:
        findings.append(
            {
                "type": "ai_tool_unverified_publishers",
                "severity": "low",
                "title": f"AI tools from unverified publishers detected ({len(unverified)})",
                "description": f"{len(unverified)} discovered AI-connected applications do not show Microsoft verified publisher evidence.",
                "affected_count": len(unverified),
                "evidence_refs": [t["application_id"] for t in unverified],
                "recommendation": "Confirm vendor ownership, approver, and governance status before expanding access.",
            }
        )

    statuses = (
        apps_status,
        sp_status,
        grants_status,
        app_roles_status,
        signins_status,
        audit_status,
    )
    return {
        "scan_id": uuid.uuid4().hex,
        "scan_type": "ai_tool_discovery_v1",
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "scan_initiated_at": scan_started,
        "scan_completed_at": _utc_now(),
        "scan_status": "completed",
        "tools": tools,
        "findings": findings,
        "summary": {
            "discovered": len([t for t in tools if t["confidence"] == "confirmed"]),
            "suspected": len([t for t in tools if t["confidence"] != "confirmed"]),
            "unknown": 0,
            "skipped": len([s for s in statuses if s["status"] == "skipped"]),
            "total_tools": len(tools),
            "sources": {
                "app_registrations": apps_status,
                "service_principals": sp_status,
                "oauth_permission_grants": grants_status,
                "app_role_assignments": app_roles_status,
                "sign_in_logs": signins_status,
                "audit_logs": audit_status,
                "directory_audit_events_sampled": len(audit_logs),
            },
        },
    }
