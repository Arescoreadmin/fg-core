"""OAuth Risk Deep Scan — illicit consent grants, over-privileged app permissions, AI tool data access.

Distinct from oauth_inventory (PR 40) which does basic enumeration.
This connector classifies risk by scope sensitivity, consent type, publisher trust, and AI tool patterns.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.connectors.oauth_risk.runner")

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Scope risk classification
# ---------------------------------------------------------------------------

# Delegated scopes that grant broad read/write access to sensitive data
_CRITICAL_DELEGATED_SCOPES: frozenset[str] = frozenset({
    "Mail.ReadWrite", "Mail.Send",
    "Files.ReadWrite.All", "Files.ReadWrite",
    "Directory.ReadWrite.All", "Directory.AccessAsUser.All",
    "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "Group.ReadWrite.All",
    "Sites.ReadWrite.All", "Sites.FullControl.All",
    "ChannelSettings.ReadWrite.All", "TeamSettings.ReadWrite.All",
    "Calendars.ReadWrite",
})

_HIGH_DELEGATED_SCOPES: frozenset[str] = frozenset({
    "Mail.Read", "Mail.ReadBasic", "MailboxSettings.Read",
    "Files.Read.All", "Files.ReadWrite",
    "Calendars.Read", "Contacts.Read",
    "User.Read.All", "Directory.Read.All",
    "Sites.Read.All", "Sites.Manage.All",
    "ChannelMessage.Read.All", "Team.ReadBasic.All",
    "AuditLog.Read.All", "Reports.Read.All",
    "InformationProtectionPolicy.Read",
})

# Application (non-delegated) permissions that are high-risk when granted
_CRITICAL_APP_ROLES: frozenset[str] = frozenset({
    "Mail.ReadWrite.All", "Mail.Send",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "Group.ReadWrite.All",
    "Sites.ReadWrite.All", "Sites.FullControl.All",
    "Calendars.ReadWrite",
    "MailboxSettings.ReadWrite",
})

_HIGH_APP_ROLES: frozenset[str] = frozenset({
    "Mail.Read.All", "MailboxSettings.Read",
    "Files.Read.All", "Sites.Read.All",
    "User.Read.All", "Directory.Read.All",
    "Group.Read.All", "AuditLog.Read.All",
    "Reports.Read.All", "Calendars.Read",
    "Contacts.Read.All", "ChannelMessage.Read.All",
    "Team.ReadBasic.All", "TeamSettings.Read.All",
    "InformationProtectionPolicy.Read",
    "SecurityEvents.Read.All", "IdentityRiskyUser.Read.All",
})

# ---------------------------------------------------------------------------
# AI tool detection by display name / publisher pattern
# ---------------------------------------------------------------------------

_AI_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"openai|chatgpt|gpt-?\d", re.I),
    re.compile(r"\bclaude\b|anthropic", re.I),
    re.compile(r"\bgemini\b|google ai|bard", re.I),
    re.compile(r"copilot(?! for microsoft)|github copilot", re.I),
    re.compile(r"perplexity|mistral|cohere|llama", re.I),
    re.compile(r"jasper\.ai|copy\.ai|writesonic|notion ai", re.I),
    re.compile(r"otter\.ai|fireflies|grain\.co", re.I),
    re.compile(r"midjourney|dall-?e|stable diffusion|runway", re.I),
    re.compile(r"zapier|make\.com|n8n\.io", re.I),  # automation tools often connecting AI
]

_DATA_ACCESS_SCOPES: frozenset[str] = frozenset({
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Mail.ReadBasic",
    "Files.Read", "Files.ReadWrite", "Files.Read.All", "Files.ReadWrite.All",
    "Calendars.Read", "Calendars.ReadWrite",
    "Contacts.Read", "Contacts.ReadWrite",
    "ChannelMessage.Read.All", "Chat.Read", "Chat.ReadWrite",
    "User.Read.All",
})


def _get(access_token: str, path: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    url: str | None = f"{_GRAPH_BASE}{path}"
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())

    results: list[dict[str, Any]] = []
    pages = 0
    while url and pages < 20:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 403:
            log.info("oauth_risk: 403 on %s — skipping", path)
            return []
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1
    return results


def _get_graph_sp_id(access_token: str) -> str | None:
    """Return the service principal ID for Microsoft Graph in this tenant."""
    try:
        sps = _get(
            access_token,
            "/servicePrincipals",
            {"$filter": "appId eq '00000003-0000-0000-c000-000000000000'", "$select": "id"},
        )
        return sps[0]["id"] if sps else None
    except Exception:
        return None


def _build_role_id_map(access_token: str, graph_sp_id: str) -> dict[str, str]:
    """Map appRoleId → permission value (e.g. 'Mail.ReadWrite.All') for MS Graph."""
    try:
        import httpx
        resp = httpx.get(
            f"{_GRAPH_BASE}/servicePrincipals/{graph_sp_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"$select": "appRoles"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return {}
        return {r["id"]: r["value"] for r in resp.json().get("appRoles", [])}
    except Exception:
        return {}


def _classify_delegated_scopes(scope_str: str) -> tuple[list[str], list[str]]:
    """Return (critical_scopes, high_scopes) found in a space-separated scope string."""
    scopes = set(scope_str.split())
    critical = sorted(scopes & _CRITICAL_DELEGATED_SCOPES)
    high = sorted(scopes & _HIGH_DELEGATED_SCOPES)
    return critical, high


def _is_ai_tool(display_name: str, publisher: str | None = None) -> bool:
    text = f"{display_name} {publisher or ''}"
    return any(p.search(text) for p in _AI_TOOL_PATTERNS)


def _has_data_access(scope_str: str) -> bool:
    return bool(set(scope_str.split()) & _DATA_ACCESS_SCOPES)


def run_oauth_risk(
    *,
    access_token: str,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Deep OAuth risk scan: consent grant abuse, over-privileged app permissions, AI tool access.

    Returns raw payload compatible with source_type=oauth_risk.
    Required top-level key: grants (list).
    """
    scan_initiated_at = datetime.now(timezone.utc).isoformat()

    # ---- 1. All delegated OAuth grants ----
    grants = _get(
        access_token,
        "/oauth2PermissionGrants",
        {"$select": "clientId,principalId,resourceId,scope,consentType"},
    )

    # ---- 2. All service principals (for name lookup + publisher info) ----
    sps_raw = _get(
        access_token,
        "/servicePrincipals",
        {"$select": "id,appId,displayName,verifiedPublisher,signInAudience,createdDateTime"},
    )
    sp_by_id: dict[str, dict] = {sp["id"]: sp for sp in sps_raw}

    # ---- 3. Application-level Graph permissions via appRoleAssignedTo ----
    graph_sp_id = _get_graph_sp_id(access_token)
    app_role_assignments: list[dict[str, Any]] = []
    role_id_map: dict[str, str] = {}

    if graph_sp_id:
        role_id_map = _build_role_id_map(access_token, graph_sp_id)
        app_role_assignments = _get(
            access_token,
            f"/servicePrincipals/{graph_sp_id}/appRoleAssignedTo",
            {"$select": "principalId,principalDisplayName,appRoleId,createdDateTime"},
        )

    # ---------------------------------------------------------------------------
    # Analysis
    # ---------------------------------------------------------------------------
    findings: list[dict[str, Any]] = []

    # --- A. Illicit consent grant analysis (user-consented broad access) ---
    user_consented_critical: list[dict] = []
    user_consented_high: list[dict] = []
    ai_tool_grants: list[dict] = []

    for grant in grants:
        scope_str = grant.get("scope") or ""
        consent_type = grant.get("consentType") or ""
        client_id = grant.get("clientId") or ""
        sp = sp_by_id.get(client_id, {})
        app_name = sp.get("displayName", client_id)
        publisher = (sp.get("verifiedPublisher") or {}).get("displayName")
        sign_in_audience = sp.get("signInAudience", "")

        critical_scopes, high_scopes = _classify_delegated_scopes(scope_str)

        # User-level consent (not AllPrincipals = admin consent)
        if consent_type == "Principal":
            if critical_scopes:
                user_consented_critical.append({
                    "app_name": app_name,
                    "scopes": critical_scopes,
                    "publisher": publisher,
                })
            elif high_scopes:
                user_consented_high.append({
                    "app_name": app_name,
                    "scopes": high_scopes,
                    "publisher": publisher,
                })

        # AI tool with data access
        if _is_ai_tool(app_name, publisher) and _has_data_access(scope_str):
            ai_tool_grants.append({
                "app_name": app_name,
                "publisher": publisher,
                "data_scopes": sorted(set(scope_str.split()) & _DATA_ACCESS_SCOPES),
                "consent_type": consent_type,
                "multi_tenant": sign_in_audience not in ("AzureADMyOrg", ""),
            })

    if user_consented_critical:
        unique_apps = list({g["app_name"] for g in user_consented_critical})
        findings.append({
            "type": "illicit_consent_grant_critical",
            "severity": "critical",
            "title": f"User-Consented OAuth Grants with Critical-Risk Scopes ({len(user_consented_critical)} grant(s))",
            "description": (
                f"{len(user_consented_critical)} delegated OAuth grant(s) were consented by individual users "
                f"(not an administrator) for scopes including write access to Mail, Files, or Directory: "
                f"{', '.join(unique_apps[:5])}. "
                f"This is the signature pattern of illicit consent grant attacks. "
                f"Revoke these grants immediately and enable admin consent requirement for all apps."
            ),
        })
    elif user_consented_high:
        unique_apps = list({g["app_name"] for g in user_consented_high})
        findings.append({
            "type": "illicit_consent_grant_high",
            "severity": "high",
            "title": f"User-Consented OAuth Grants with High-Risk Read Scopes ({len(user_consented_high)} grant(s))",
            "description": (
                f"{len(user_consented_high)} delegated OAuth grant(s) were consented by individual users "
                f"for scopes including Mail.Read, Files.Read.All, or Directory.Read.All: "
                f"{', '.join(unique_apps[:5])}. "
                f"Without admin consent enforcement, any user can grant an OAuth app access to their mailbox or files. "
                f"Configure user consent settings to require admin approval for sensitive scopes."
            ),
        })

    # Deduplicate AI tool grants by app name
    seen_ai: set[str] = set()
    deduped_ai = []
    for g in ai_tool_grants:
        if g["app_name"] not in seen_ai:
            seen_ai.add(g["app_name"])
            deduped_ai.append(g)

    if deduped_ai:
        names = ", ".join(g["app_name"] for g in deduped_ai[:6])
        mt_count = sum(1 for g in deduped_ai if g.get("multi_tenant"))
        findings.append({
            "type": "ai_tool_oauth_data_access",
            "severity": "high",
            "title": f"AI Tools with OAuth Access to Company Data ({len(deduped_ai)} app(s))",
            "description": (
                f"{len(deduped_ai)} AI tool(s) have OAuth delegated access to sensitive company data "
                f"(Mail, Files, Calendar, Teams): {names}. "
                f"{mt_count} of these are multi-tenant apps. "
                f"AI tools with mail/file access can train on or exfiltrate company data. "
                f"Review each app's data retention policy and whether user consent was appropriate."
            ),
        })

    # --- B. Over-privileged application permissions ---
    critical_app_role_grants: list[dict] = []
    high_app_role_grants: list[dict] = []

    for assignment in app_role_assignments:
        role_value = role_id_map.get(assignment.get("appRoleId", ""), "")
        if not role_value:
            continue
        principal_name = assignment.get("principalDisplayName", assignment.get("principalId", ""))

        if role_value in _CRITICAL_APP_ROLES:
            critical_app_role_grants.append({
                "app_name": principal_name,
                "permission": role_value,
                "granted_at": assignment.get("createdDateTime"),
            })
        elif role_value in _HIGH_APP_ROLES:
            high_app_role_grants.append({
                "app_name": principal_name,
                "permission": role_value,
                "granted_at": assignment.get("createdDateTime"),
            })

    if critical_app_role_grants:
        by_app: dict[str, list[str]] = {}
        for g in critical_app_role_grants:
            by_app.setdefault(g["app_name"], []).append(g["permission"])
        summary_lines = [f"{app}: {', '.join(perms)}" for app, perms in list(by_app.items())[:5]]
        findings.append({
            "type": "critical_application_permissions",
            "severity": "critical",
            "title": f"Applications with Critical MS Graph Application Permissions ({len(by_app)} app(s))",
            "description": (
                f"{len(by_app)} application(s) hold application-level MS Graph permissions that grant "
                f"tenant-wide access without user context: {'; '.join(summary_lines)}. "
                f"Application permissions (as opposed to delegated) act as a permanent standing grant "
                f"to ALL mailboxes, files, or directory objects. "
                f"Verify each app is still active, has least-privilege scopes, and is operated by a trusted publisher."
            ),
        })

    if high_app_role_grants:
        unique_apps = list({g["app_name"] for g in high_app_role_grants})
        findings.append({
            "type": "high_application_permissions",
            "severity": "high",
            "title": f"Applications with High-Risk Read-All Application Permissions ({len(unique_apps)} app(s))",
            "description": (
                f"{len(unique_apps)} application(s) hold high-risk read-all MS Graph application permissions: "
                f"{', '.join(unique_apps[:6])}. "
                f"Read-all application permissions expose the entire tenant's data to the application. "
                f"Ensure each app has a documented business justification and active monitoring."
            ),
        })

    # --- C. Unverified publishers with sensitive access ---
    unverified_sensitive: list[dict] = []
    seen_unverified: set[str] = set()
    for grant in grants:
        scope_str = grant.get("scope") or ""
        client_id = grant.get("clientId") or ""
        if client_id in seen_unverified:
            continue
        sp = sp_by_id.get(client_id, {})
        publisher = sp.get("verifiedPublisher")
        if publisher:
            continue  # verified publisher — skip
        sign_in_audience = sp.get("signInAudience", "")
        if sign_in_audience == "AzureADMyOrg":
            continue  # internal app — skip
        critical, high = _classify_delegated_scopes(scope_str)
        if critical or high:
            seen_unverified.add(client_id)
            unverified_sensitive.append({
                "app_name": sp.get("displayName", client_id),
                "scopes": critical + high,
                "multi_tenant": sign_in_audience not in ("AzureADMyOrg", ""),
            })

    if unverified_sensitive:
        mt = [u for u in unverified_sensitive if u.get("multi_tenant")]
        names = ", ".join(u["app_name"] for u in unverified_sensitive[:5])
        findings.append({
            "type": "unverified_publisher_sensitive_access",
            "severity": "medium",
            "title": f"Unverified Publishers with Sensitive OAuth Access ({len(unverified_sensitive)} app(s))",
            "description": (
                f"{len(unverified_sensitive)} third-party app(s) with unverified publishers hold sensitive "
                f"delegated OAuth access: {names}. "
                f"{len(mt)} of these are multi-tenant apps (not registered in your tenant). "
                f"Microsoft Publisher Verification provides a basic assurance of app identity. "
                f"Review whether unverified apps should have access to sensitive data."
            ),
        })

    summary = {
        "total_grants": len(grants),
        "user_consented_critical": len(user_consented_critical),
        "user_consented_high": len(user_consented_high),
        "ai_tools_with_data_access": len(deduped_ai),
        "critical_app_permissions": len(critical_app_role_grants),
        "high_app_permissions": len(high_app_role_grants),
        "unverified_publisher_apps": len(unverified_sensitive),
        "total_findings": len(findings),
    }

    return {
        "grants": grants,
        "app_role_assignments": app_role_assignments,
        "ai_tool_grants": deduped_ai,
        "findings": findings,
        "summary": summary,
        "scan_initiated_at": scan_initiated_at,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
    }
