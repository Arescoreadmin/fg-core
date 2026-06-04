"""Deterministic AI Data Access Mapping engine.

For every AI tool found by the AI Tool Discovery scan (PR 1), maps:
  Permission -> MS Resource -> Business Data Category -> Sensitivity

Addendum fields (all deterministic, no AI scoring):
  data_owner / owner_type  - deterministic from data category
  review_status            - always "unreviewed" on creation
  exposure_scope           - derived from consent_type / admin_consent / assigned_users
  governance_readiness     - derived from verified_publisher + owner_type + review_status

Graph-ready identifiers are generated for every tool and data access node
to support future evidence graph traversal without building the traversal now.
"""

from __future__ import annotations

from typing import Any

MAPPER_VERSION = "ai-data-access-mapper-v1"
SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Permission -> MS Resource
# ---------------------------------------------------------------------------

_PERMISSION_TO_RESOURCE: dict[str, str] = {
    # Files / Documents
    "Files.Read": "OneDrive",
    "Files.ReadWrite": "OneDrive",
    "Files.Read.All": "SharePoint/OneDrive",
    "Files.ReadWrite.All": "SharePoint/OneDrive",
    "Files.Read.Selected": "SharePoint/OneDrive",
    # Mail
    "Mail.Read": "Exchange",
    "Mail.ReadBasic": "Exchange",
    "Mail.ReadBasic.All": "Exchange",
    "Mail.ReadWrite": "Exchange",
    "Mail.Read.All": "Exchange",
    "Mail.ReadWrite.All": "Exchange",
    "Mail.Send": "Exchange",
    "Mail.Send.All": "Exchange",
    # Calendar
    "Calendars.Read": "Exchange",
    "Calendars.ReadWrite": "Exchange",
    "Calendars.Read.Shared": "Exchange",
    "Calendars.ReadWrite.Shared": "Exchange",
    # Contacts / People
    "Contacts.Read": "Exchange",
    "Contacts.ReadWrite": "Exchange",
    "Contacts.Read.Shared": "Exchange",
    "Contacts.ReadWrite.Shared": "Exchange",
    "People.Read": "Exchange",
    "People.Read.All": "Exchange",
    # Teams / Chat
    "Chat.Read": "Teams",
    "Chat.ReadWrite": "Teams",
    "Chat.Read.All": "Teams",
    "Chat.ReadWrite.All": "Teams",
    "Chat.Create": "Teams",
    "ChannelMessage.Read.All": "Teams",
    "ChannelMessage.Send": "Teams",
    "Channel.ReadBasic.All": "Teams",
    "Team.ReadBasic.All": "Teams",
    "TeamSettings.Read.All": "Teams",
    "TeamSettings.ReadWrite.All": "Teams",
    "TeamsActivity.Read": "Teams",
    "TeamsActivity.Read.All": "Teams",
    "TeamsAppInstallation.ReadForUser": "Teams",
    # SharePoint / Sites
    "Sites.Read.All": "SharePoint",
    "Sites.ReadWrite.All": "SharePoint",
    "Sites.Manage.All": "SharePoint",
    "Sites.FullControl.All": "SharePoint",
    "Sites.Selected": "SharePoint",
    # OneDrive / Notes
    "Drive.Read.All": "OneDrive",
    "Drive.ReadWrite.All": "OneDrive",
    "Notes.Read": "OneDrive",
    "Notes.Read.All": "OneDrive",
    "Notes.ReadWrite": "OneDrive",
    "Notes.ReadWrite.All": "OneDrive",
    "Notes.Create": "OneDrive",
    # Tasks
    "Tasks.Read": "Microsoft 365",
    "Tasks.ReadWrite": "Microsoft 365",
    "Tasks.Read.Shared": "Microsoft 365",
    "Tasks.ReadWrite.Shared": "Microsoft 365",
    # Directory / Identity
    "Directory.Read.All": "Entra ID",
    "Directory.ReadWrite.All": "Entra ID",
    "Directory.AccessAsUser.All": "Entra ID",
    "User.Read": "Entra ID",
    "User.Read.All": "Entra ID",
    "User.ReadWrite": "Entra ID",
    "User.ReadWrite.All": "Entra ID",
    "User.ReadBasic.All": "Entra ID",
    "Group.Read.All": "Entra ID",
    "Group.ReadWrite.All": "Entra ID",
    "GroupMember.Read.All": "Entra ID",
    "GroupMember.ReadWrite.All": "Entra ID",
    "Member.Read.Hidden": "Entra ID",
    "Organization.Read.All": "Entra ID",
    "Organization.ReadWrite.All": "Entra ID",
    "OrgContact.Read.All": "Entra ID",
    # Application / Service Principal
    "Application.Read.All": "Entra ID",
    "Application.ReadWrite.All": "Entra ID",
    "Application.ReadWrite.OwnedBy": "Entra ID",
    "AppRoleAssignment.ReadWrite.All": "Entra ID",
    "ServicePrincipalEndpoint.Read.All": "Entra ID",
    # Audit / Security / Reports
    "AuditLog.Read.All": "Microsoft 365 Admin",
    "Reports.Read.All": "Microsoft 365 Admin",
    "SecurityEvents.Read.All": "Microsoft 365 Admin",
    "SecurityEvents.ReadWrite.All": "Microsoft 365 Admin",
    "IdentityRiskyUser.Read.All": "Microsoft 365 Admin",
    "Policy.Read.All": "Microsoft 365 Admin",
    "Policy.ReadWrite.All": "Microsoft 365 Admin",
    "PrivilegedAccess.Read.AzureResources": "Microsoft 365 Admin",
    "RoleEligibilitySchedule.Read.Directory": "Microsoft 365 Admin",
    "RoleAssignmentSchedule.Read.Directory": "Microsoft 365 Admin",
    "AccessReview.Read.All": "Microsoft 365 Admin",
    # Device management
    "DeviceManagementManagedDevices.Read.All": "Microsoft 365 Admin",
    "DeviceManagementConfiguration.Read.All": "Microsoft 365 Admin",
    # Source code
    "Code.ReadWrite": "Azure DevOps",
    "vso.code": "Azure DevOps",
    "vso.code_write": "Azure DevOps",
}

# ---------------------------------------------------------------------------
# MS Resource -> Business Data Category
# ---------------------------------------------------------------------------

_RESOURCE_TO_DATA_CATEGORY: dict[str, str] = {
    "SharePoint/OneDrive": "Documents",
    "SharePoint": "SharePoint Data",
    "OneDrive": "OneDrive Data",
    "Exchange": "Email",
    "Teams": "Teams Data",
    "Entra ID": "Identity Data",
    "Microsoft 365 Admin": "Administrative Metadata",
    "Microsoft 365": "Administrative Metadata",
    "Azure DevOps": "Source Code",
}

# ---------------------------------------------------------------------------
# Sensitivity per permission (deterministic, no AI)
# ---------------------------------------------------------------------------

_PERMISSION_SENSITIVITY: dict[str, str] = {
    # Critical — broad write-all
    "Files.ReadWrite.All": "critical",
    "Drive.ReadWrite.All": "critical",
    "Mail.ReadWrite.All": "critical",
    "Mail.Send.All": "critical",
    "Directory.ReadWrite.All": "critical",
    "Sites.ReadWrite.All": "critical",
    "Sites.FullControl.All": "critical",
    "Sites.Manage.All": "critical",
    "User.ReadWrite.All": "critical",
    "Group.ReadWrite.All": "critical",
    "GroupMember.ReadWrite.All": "critical",
    "Application.ReadWrite.All": "critical",
    "AppRoleAssignment.ReadWrite.All": "critical",
    "Chat.ReadWrite.All": "critical",
    "TeamSettings.ReadWrite.All": "critical",
    "SecurityEvents.ReadWrite.All": "critical",
    "Policy.ReadWrite.All": "critical",
    "Organization.ReadWrite.All": "critical",
    "Notes.ReadWrite.All": "critical",
    "vso.code_write": "critical",
    "Code.ReadWrite": "critical",
    # High — read-all patterns
    "Files.Read.All": "high",
    "Drive.Read.All": "high",
    "Mail.Read.All": "high",
    "Mail.ReadBasic.All": "high",
    "Directory.Read.All": "high",
    "User.Read.All": "high",
    "Group.Read.All": "high",
    "GroupMember.Read.All": "high",
    "Member.Read.Hidden": "high",
    "Sites.Read.All": "high",
    "Chat.Read.All": "high",
    "ChannelMessage.Read.All": "high",
    "Application.Read.All": "high",
    "AuditLog.Read.All": "high",
    "Reports.Read.All": "high",
    "SecurityEvents.Read.All": "high",
    "IdentityRiskyUser.Read.All": "high",
    "Policy.Read.All": "high",
    "Organization.Read.All": "high",
    "OrgContact.Read.All": "high",
    "Notes.Read.All": "high",
    "AccessReview.Read.All": "high",
    "RoleEligibilitySchedule.Read.Directory": "high",
    "RoleAssignmentSchedule.Read.Directory": "high",
    "PrivilegedAccess.Read.AzureResources": "high",
    "DeviceManagementManagedDevices.Read.All": "high",
    "DeviceManagementConfiguration.Read.All": "high",
    "TeamsActivity.Read.All": "high",
    "vso.code": "high",
    "People.Read.All": "high",
    # Moderate — scoped read/write
    "Mail.Read": "moderate",
    "Mail.ReadBasic": "moderate",
    "Mail.ReadWrite": "moderate",
    "Mail.Send": "moderate",
    "Files.Read": "moderate",
    "Files.ReadWrite": "moderate",
    "Files.Read.Selected": "moderate",
    "Chat.Read": "moderate",
    "Chat.ReadWrite": "moderate",
    "Chat.Create": "moderate",
    "Calendars.ReadWrite": "moderate",
    "Calendars.ReadWrite.Shared": "moderate",
    "Contacts.ReadWrite": "moderate",
    "Contacts.ReadWrite.Shared": "moderate",
    "Notes.Read": "moderate",
    "Notes.ReadWrite": "moderate",
    "Notes.Create": "moderate",
    "User.ReadWrite": "moderate",
    "ChannelMessage.Send": "moderate",
    "TeamsAppInstallation.ReadForUser": "moderate",
    "Application.ReadWrite.OwnedBy": "moderate",
    "Tasks.ReadWrite": "moderate",
    "Tasks.ReadWrite.Shared": "moderate",
    # Low — user/profile level
    "User.Read": "low",
    "User.ReadBasic.All": "low",
    "Calendars.Read": "low",
    "Calendars.Read.Shared": "low",
    "Contacts.Read": "low",
    "Contacts.Read.Shared": "low",
    "People.Read": "low",
    "Tasks.Read": "low",
    "Tasks.Read.Shared": "low",
    "Team.ReadBasic.All": "low",
    "Channel.ReadBasic.All": "low",
    "TeamSettings.Read.All": "low",
    "TeamsActivity.Read": "low",
    "ServicePrincipalEndpoint.Read.All": "low",
    "Directory.AccessAsUser.All": "low",
    "Sites.Selected": "low",
    # Unknown — metadata / auth / no data access
    "offline_access": "unknown",
    "openid": "unknown",
    "profile": "unknown",
    "email": "unknown",
    "address": "unknown",
}

_SENSITIVITY_ORDER: dict[str, int] = {
    "unknown": 0,
    "low": 1,
    "moderate": 2,
    "high": 3,
    "critical": 4,
}

# ---------------------------------------------------------------------------
# Data category -> owner_type (deterministic inference only)
# ---------------------------------------------------------------------------

_DATA_CATEGORY_OWNER_TYPE: dict[str, str] = {
    "Identity Data": "IT",
    "Administrative Metadata": "IT",
    "Email": "Operations",
    "Teams Data": "Operations",
    "Documents": "Unknown",
    "SharePoint Data": "Unknown",
    "OneDrive Data": "Unknown",
    "Source Code": "Unknown",
}


# ---------------------------------------------------------------------------
# Classification functions (public API)
# ---------------------------------------------------------------------------


def classify_sensitivity(permissions: list[str]) -> str:
    """Return the highest sensitivity across all permissions."""
    best = "unknown"
    for perm in permissions:
        s = _PERMISSION_SENSITIVITY.get(perm, "unknown")
        if _SENSITIVITY_ORDER.get(s, 0) > _SENSITIVITY_ORDER.get(best, 0):
            best = s
    return best


def classify_exposure_scope(tool: dict[str, Any]) -> str:
    """Determine exposure scope from consent data. Never fabricated."""
    confidence = str(tool.get("confidence") or "unknown")
    if confidence == "suspected":
        return "unknown"
    if (
        bool(tool.get("admin_consent"))
        or str(tool.get("consent_type") or "") == "AllPrincipals"
    ):
        return "tenant"
    if tool.get("assigned_users"):
        return "user"
    return "unknown"


def classify_owner_type(data_categories: list[str]) -> str:
    """Deterministic owner inference from data categories. Unknown if ambiguous."""
    known = sorted(
        {_DATA_CATEGORY_OWNER_TYPE.get(cat, "Unknown") for cat in data_categories}
        - {"Unknown"}
    )
    return known[0] if known else "Unknown"


def classify_governance_readiness(
    *,
    verified_publisher: bool,
    owner_type: str,
    review_status: str,
    confidence: str,
) -> str:
    """Deterministic governance readiness. No AI scoring."""
    if confidence not in {"confirmed", "probable"}:
        return "unknown"
    if not verified_publisher:
        return "ungoverned"
    if review_status in {"reviewed", "accepted"}:
        return "governed"
    return "partially_governed"


def _build_resource_access(permissions: list[str]) -> list[dict[str, Any]]:
    resource_to_perms: dict[str, list[str]] = {}
    for perm in permissions:
        resource = _PERMISSION_TO_RESOURCE.get(perm)
        if resource:
            resource_to_perms.setdefault(resource, []).append(perm)
    return [
        {
            "resource": resource,
            "data_category": _RESOURCE_TO_DATA_CATEGORY.get(resource, "Unknown"),
            "permissions_enabling_access": sorted(perms),
            "sensitivity": classify_sensitivity(perms),
        }
        for resource, perms in sorted(resource_to_perms.items())
    ]


def _build_business_impact(
    *,
    sensitivity: str,
    data_categories: list[str],
    exposure_scope: str,
    admin_consent: bool,
) -> str:
    """Deterministic business impact statement. Never AI-generated."""
    cats = (
        ", ".join(data_categories) if data_categories else "no mapped data categories"
    )
    scope_phrase = {
        "tenant": "tenant-wide access (admin consent granted)",
        "group": "group-scoped access",
        "department": "department-scoped access",
        "user": "user-scoped access",
        "unknown": "access scope undetermined",
    }.get(exposure_scope, "access scope undetermined")
    action = {
        "critical": "Immediate governance review required.",
        "high": "Review approver, business justification, and least-privilege scope.",
        "moderate": "Confirm business justification and data ownership.",
        "low": "No immediate action required; confirm access is still needed.",
        "unknown": "Insufficient permission data to assess impact.",
    }.get(sensitivity, "Review access grant.")
    return f"{sensitivity.capitalize()} data access: {cats} — {scope_phrase}. {action}"


def map_tool(
    tool: dict[str, Any],
    *,
    source_scan_result_id: str,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Produce a full data-access mapping for one AI tool. All fields deterministic."""
    delegated: list[str] = list(tool.get("delegated_permissions") or [])
    application: list[str] = list(tool.get("application_permissions") or [])
    permissions = sorted(set(delegated + application))

    resource_access = _build_resource_access(permissions)
    data_categories = sorted({ra["data_category"] for ra in resource_access})
    sensitivity = classify_sensitivity(permissions)
    exposure_scope = classify_exposure_scope(tool)
    review_status = "unreviewed"
    owner_type = classify_owner_type(data_categories)
    verified_publisher = bool(tool.get("verified_publisher"))
    confidence = str(tool.get("confidence") or "unknown")

    governance_readiness = classify_governance_readiness(
        verified_publisher=verified_publisher,
        owner_type=owner_type,
        review_status=review_status,
        confidence=confidence,
    )

    app_id = str(
        tool.get("application_id") or tool.get("service_principal_id") or "unknown"
    )
    sp_id = str(tool.get("service_principal_id") or "unknown")
    graph_node_id = tool.get("graph_node_id") or f"ai_tool:{tenant_id}:{app_id}"

    # Graph-ready node IDs — supports future evidence graph traversal (Addendum 7)
    data_access_node_ids = sorted(
        f"data_access:{tenant_id}:{app_id}:{cat.lower().replace(' ', '_').replace('/', '_')}"
        for cat in data_categories
    )
    resource_node_ids = sorted(
        {
            f"ms_resource:{ra['resource'].lower().replace(' ', '_').replace('/', '_')}"
            for ra in resource_access
        }
    )
    owner_node_id = f"data_owner:{owner_type.lower()}"
    scope_node_id = f"access_scope:{exposure_scope}"
    governance_node_id = f"governance_state:{governance_readiness}"

    return {
        "tool_name": str(tool.get("tool_name") or "unknown"),
        "vendor": str(tool.get("vendor") or "unknown"),
        "permissions": permissions,
        "resource_access": resource_access,
        "data_categories": data_categories,
        "sensitivity": sensitivity,
        "data_owner": owner_type,
        "owner_type": owner_type,
        "exposure_scope": exposure_scope,
        "review_status": review_status,
        "governance_readiness": governance_readiness,
        "granted_by": sorted(tool.get("assigned_users") or []),
        "granted_to": sp_id,
        "admin_consent": bool(tool.get("admin_consent")),
        "verified_publisher": verified_publisher,
        "confidence": confidence,
        "business_impact": _build_business_impact(
            sensitivity=sensitivity,
            data_categories=data_categories,
            exposure_scope=exposure_scope,
            admin_consent=bool(tool.get("admin_consent")),
        ),
        "evidence_refs": sorted(tool.get("evidence_refs") or []),
        "graph_node_id": graph_node_id,
        "data_access_node_ids": data_access_node_ids,
        "resource_node_ids": resource_node_ids,
        "owner_node_id": owner_node_id,
        "scope_node_id": scope_node_id,
        "governance_node_id": governance_node_id,
        "source_scan_result_id": source_scan_result_id,
    }


def _generate_findings(
    mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    critical = [m for m in mappings if m["sensitivity"] == "critical"]
    if critical:
        findings.append(
            {
                "type": "critical_data_access",
                "severity": "critical",
                "title": f"AI tools with critical data write access detected ({len(critical)})",
                "description": (
                    f"{len(critical)} AI-connected application(s) hold permissions enabling broad write "
                    f"access to enterprise data (files, mail, directory, or SharePoint). "
                    f"Evidence-backed governance review input — not an automatic risk determination."
                ),
                "affected_count": len(critical),
                "affected_tools": [m["tool_name"] for m in critical],
                "evidence_refs": list({m["source_scan_result_id"] for m in critical}),
                "recommendation": (
                    "Immediately review business justification, approver chain, and least-privilege "
                    "alternatives for each tool with write-all permissions."
                ),
            }
        )

    tenant_wide = [
        m
        for m in mappings
        if m["exposure_scope"] == "tenant" and m["sensitivity"] in {"high", "critical"}
    ]
    if tenant_wide:
        findings.append(
            {
                "type": "tenant_wide_sensitive_access",
                "severity": "high",
                "title": f"AI tools with tenant-wide sensitive data access ({len(tenant_wide)})",
                "description": (
                    f"{len(tenant_wide)} AI-connected application(s) have admin-consented (tenant-wide) "
                    f"access to sensitive enterprise data. All users in the tenant may be in scope."
                ),
                "affected_count": len(tenant_wide),
                "affected_tools": [m["tool_name"] for m in tenant_wide],
                "evidence_refs": list(
                    {m["source_scan_result_id"] for m in tenant_wide}
                ),
                "recommendation": (
                    "Review admin consent grants. Restrict to specific user groups where possible "
                    "and confirm business justification for tenant-wide access."
                ),
            }
        )

    high_sensitivity = [m for m in mappings if m["sensitivity"] == "high"]
    if high_sensitivity:
        findings.append(
            {
                "type": "sensitive_data_access",
                "severity": "medium",
                "title": f"AI tools with broad read access to enterprise data ({len(high_sensitivity)})",
                "description": (
                    f"{len(high_sensitivity)} AI-connected application(s) have read-all permissions "
                    f"spanning enterprise data (files, mail, directory, or SharePoint)."
                ),
                "affected_count": len(high_sensitivity),
                "affected_tools": [m["tool_name"] for m in high_sensitivity],
                "evidence_refs": list(
                    {m["source_scan_result_id"] for m in high_sensitivity}
                ),
                "recommendation": (
                    "Review business justification and confirm read-all scope is required "
                    "rather than a more narrowly scoped permission set."
                ),
            }
        )

    multi_cat = [
        m
        for m in mappings
        if len(m["data_categories"]) >= 3 and m["sensitivity"] in {"high", "critical"}
    ]
    if multi_cat:
        findings.append(
            {
                "type": "multi_category_sensitive_access",
                "severity": "medium",
                "title": f"AI tools accessing multiple sensitive data categories ({len(multi_cat)})",
                "description": (
                    f"{len(multi_cat)} AI-connected application(s) access 3 or more distinct enterprise "
                    f"data categories with high or critical sensitivity. "
                    f"This pattern indicates broad data exposure across the tenant."
                ),
                "affected_count": len(multi_cat),
                "affected_tools": [m["tool_name"] for m in multi_cat],
                "evidence_refs": list({m["source_scan_result_id"] for m in multi_cat}),
                "recommendation": (
                    "Evaluate whether each data category access has a documented business purpose "
                    "and whether least-privilege alternatives exist."
                ),
            }
        )

    unverified_sensitive = [
        m
        for m in mappings
        if not m["verified_publisher"] and m["sensitivity"] in {"high", "critical"}
    ]
    if unverified_sensitive:
        findings.append(
            {
                "type": "unverified_sensitive_access",
                "severity": "high",
                "title": (
                    f"Unverified AI tools accessing sensitive enterprise data ({len(unverified_sensitive)})"
                ),
                "description": (
                    f"{len(unverified_sensitive)} AI-connected application(s) from unverified publishers "
                    f"have access to high or critical sensitivity enterprise data. "
                    f"Publisher identity cannot be confirmed through Microsoft's verification program."
                ),
                "affected_count": len(unverified_sensitive),
                "affected_tools": [m["tool_name"] for m in unverified_sensitive],
                "evidence_refs": list(
                    {m["source_scan_result_id"] for m in unverified_sensitive}
                ),
                "recommendation": (
                    "Confirm vendor identity, legal agreements, and governance documentation "
                    "before allowing continued access to sensitive enterprise data."
                ),
            }
        )

    return findings


def _build_summary(
    mappings: list[dict[str, Any]],
    *,
    source_scan_result_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    sensitivity_dist: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "moderate": 0,
        "low": 0,
        "unknown": 0,
    }
    readiness_dist: dict[str, int] = {
        "governed": 0,
        "partially_governed": 0,
        "ungoverned": 0,
        "unknown": 0,
    }
    scope_dist: dict[str, int] = {
        "tenant": 0,
        "group": 0,
        "department": 0,
        "user": 0,
        "unknown": 0,
    }
    owner_dist: dict[str, int] = {}
    all_categories: set[str] = set()

    for m in mappings:
        s = m["sensitivity"]
        sensitivity_dist[s] = sensitivity_dist.get(s, 0) + 1
        r = m["governance_readiness"]
        readiness_dist[r] = readiness_dist.get(r, 0) + 1
        sc = m["exposure_scope"]
        scope_dist[sc] = scope_dist.get(sc, 0) + 1
        ot = m["owner_type"]
        owner_dist[ot] = owner_dist.get(ot, 0) + 1
        all_categories.update(m["data_categories"])

    return {
        "tools_mapped": len(mappings),
        "sensitivity_distribution": sensitivity_dist,
        "governance_readiness_distribution": readiness_dist,
        "scope_distribution": scope_dist,
        "owner_distribution": owner_dist,
        "data_categories_observed": sorted(all_categories),
        "source_scan_result_id": source_scan_result_id,
        "engagement_id": engagement_id,
    }


def map_engagement(
    tools: list[dict[str, Any]],
    *,
    source_scan_result_id: str,
    tenant_id: str,
    engagement_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Map all tools for an engagement. Returns (mappings, findings, summary).

    All outputs are deterministic. The same inputs always produce the same outputs.
    Findings are only generated for tools with evidence-backed risk indicators.
    """
    mappings = [
        map_tool(
            tool,
            source_scan_result_id=source_scan_result_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )
        for tool in tools
    ]
    mappings.sort(key=lambda m: (m["vendor"].casefold(), m["tool_name"].casefold()))
    findings = _generate_findings(mappings)
    summary = _build_summary(
        mappings,
        source_scan_result_id=source_scan_result_id,
        engagement_id=engagement_id,
    )
    return mappings, findings, summary
