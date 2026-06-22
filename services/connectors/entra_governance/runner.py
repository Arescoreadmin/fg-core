"""Entra ID Governance connector — PIM roles, Access Reviews, Identity Protection, Conditional Access."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.connectors.entra_governance.runner")

_GRAPH_BASE_V1 = "https://graph.microsoft.com/v1.0"
_TIMEOUT = 30

# Well-known privileged directory role IDs
_PRIVILEGED_ROLE_IDS: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
}

_STALE_DAYS = 90


def _graph_get(
    access_token: str, path: str, params: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    base: str = f"{_GRAPH_BASE_V1}{path}"
    if params:
        base = base + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    url: str | None = base

    results: list[dict[str, Any]] = []
    pages = 0
    while url and pages < 20:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 403:
            log.info(
                "entra_governance: 403 on %s — endpoint likely requires higher license tier",
                path,
            )
            return []
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1
    return results


def _get_role_definitions(access_token: str) -> dict[str, str]:
    try:
        roles = _graph_get(
            access_token,
            "/directoryRoles",
            {"$select": "id,displayName,roleTemplateId"},
        )
        return {
            r.get("roleTemplateId", r.get("id", "")): r.get("displayName", "")
            for r in roles
        }
    except Exception:
        return {}


def _analyze_role_assignments(
    role_assignments: list[dict],
    eligibility_schedules: list[dict],
    role_def_map: dict[str, str],
) -> tuple[list[dict], dict[str, Any]]:
    findings: list[dict] = []
    now = datetime.now(timezone.utc)

    # Build set of role IDs protected by PIM (have eligibility schedules)
    pim_protected_roles: set[str] = set()
    pim_protected_principals: set[tuple[str, str]] = set()  # (principalId, roleId)
    stale_eligible: list[dict] = []

    for sched in eligibility_schedules:
        role_id = sched.get("roleDefinitionId", "")
        principal_id = sched.get("principalId", "")
        pim_protected_roles.add(role_id)
        pim_protected_principals.add((principal_id, role_id))

        # Check if eligible assignment is stale (created long ago, presumably never activated)
        created_str = sched.get("createdDateTime") or sched.get("startDateTime")
        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                if (now - created).days > _STALE_DAYS:
                    role_name = role_def_map.get(role_id, role_id)
                    stale_eligible.append(
                        {
                            "principal_id": principal_id,
                            "role": role_name,
                            "days_since_assigned": (now - created).days,
                        }
                    )
            except Exception:
                pass

    # Analyze permanent (non-PIM) role assignments
    permanent_global_admins: list[str] = []
    permanent_privileged: list[dict] = []
    global_admin_role_id = "62e90394-69f5-4237-9190-012177145e10"

    for assignment in role_assignments:
        role_id = assignment.get("roleDefinitionId", "")
        principal_id = assignment.get("principalId", "")
        role_name = role_def_map.get(
            role_id, _PRIVILEGED_ROLE_IDS.get(role_id, role_id)
        )

        if role_id == global_admin_role_id:
            permanent_global_admins.append(principal_id)

        if (
            role_id in _PRIVILEGED_ROLE_IDS
            and (principal_id, role_id) not in pim_protected_principals
        ):
            permanent_privileged.append(
                {"principal_id": principal_id, "role": role_name}
            )

    if permanent_global_admins:
        findings.append(
            {
                "type": "permanent_global_admin",
                "severity": "high",
                "title": f"Permanent Global Administrator Assignment ({len(permanent_global_admins)} principal(s))",
                "description": (
                    f"{len(permanent_global_admins)} principal(s) hold Global Administrator as a permanent "
                    f"assignment rather than a time-bound PIM eligible role. Permanent privileged roles increase "
                    f"the blast radius of account compromise."
                ),
            }
        )

    if len(permanent_global_admins) > 5:
        findings.append(
            {
                "type": "excessive_global_admins",
                "severity": "medium",
                "title": f"Excessive Global Administrators ({len(permanent_global_admins)})",
                "description": (
                    f"The tenant has {len(permanent_global_admins)} Global Administrators. "
                    f"Microsoft recommends no more than 5. Excess admins expand the attack surface."
                ),
            }
        )

    if permanent_privileged:
        unique_roles = list({p["role"] for p in permanent_privileged})
        findings.append(
            {
                "type": "permanent_privileged_role",
                "severity": "high",
                "title": f"Permanent Privileged Role Assignments ({len(permanent_privileged)} found)",
                "description": (
                    f"Privileged roles ({', '.join(unique_roles[:5])}) are assigned permanently without PIM. "
                    f"Use PIM eligible assignments with approval workflows and MFA to reduce standing access."
                ),
            }
        )

    if stale_eligible:
        findings.append(
            {
                "type": "stale_pim_eligible_assignment",
                "severity": "medium",
                "title": f"Stale PIM Eligible Assignments ({len(stale_eligible)} role(s))",
                "description": (
                    f"{len(stale_eligible)} PIM eligible role assignment(s) have not been activated in "
                    f"over {_STALE_DAYS} days. Review and revoke unused eligible assignments to limit standing access."
                ),
            }
        )

    summary = {
        "total_permanent_assignments": len(role_assignments),
        "total_pim_eligible": len(eligibility_schedules),
        "permanent_global_admins": len(permanent_global_admins),
        "permanent_privileged_roles": len(permanent_privileged),
        "stale_eligible_assignments": len(stale_eligible),
    }
    return findings, summary


def _analyze_access_reviews(review_definitions: list[dict]) -> list[dict]:
    findings: list[dict] = []
    if not review_definitions:
        findings.append(
            {
                "type": "no_access_reviews_configured",
                "severity": "high",
                "title": "No Access Reviews Configured",
                "description": (
                    "No access review definitions were found in Entra ID Governance. "
                    "Access reviews ensure that privileged role assignments are regularly validated. "
                    "Configure recurring reviews for Global Administrator and other privileged roles."
                ),
            }
        )
        return findings

    # Check if any reviews cover privileged roles
    covers_privileged = any(
        r.get("scope", {}).get("query", "").lower().count("role") > 0
        or r.get("instanceEnumerationScope", {}).get("query", "").lower().count("role")
        > 0
        for r in review_definitions
    )

    inactive = [
        r
        for r in review_definitions
        if r.get("status") in ("Completed", "Canceled") and not r.get("isRecurring")
    ]

    if not covers_privileged:
        findings.append(
            {
                "type": "access_reviews_missing_privileged_roles",
                "severity": "medium",
                "title": "Access Reviews Do Not Cover Privileged Roles",
                "description": (
                    f"{len(review_definitions)} access review(s) are configured but none appear to target "
                    f"privileged directory role assignments. Add reviews covering Global Administrator, "
                    f"Privileged Role Administrator, and Security Administrator."
                ),
            }
        )

    if inactive:
        findings.append(
            {
                "type": "non_recurring_access_reviews",
                "severity": "low",
                "title": f"Non-Recurring Access Reviews ({len(inactive)} found)",
                "description": (
                    f"{len(inactive)} access review(s) are configured as one-time (non-recurring). "
                    f"Switch to recurring reviews to ensure continuous validation of access rights."
                ),
            }
        )

    return findings


def _analyze_risky_users(risky_users: list[dict]) -> list[dict]:
    findings: list[dict] = []
    if not risky_users:
        return findings

    high_risk = [
        u
        for u in risky_users
        if u.get("riskLevel") == "high"
        and u.get("riskState") not in ("remediated", "dismissed")
    ]
    medium_risk = [
        u
        for u in risky_users
        if u.get("riskLevel") == "medium"
        and u.get("riskState") not in ("remediated", "dismissed")
    ]

    if high_risk:
        findings.append(
            {
                "type": "unmediated_high_risk_users",
                "severity": "critical",
                "title": f"High-Risk Users Not Remediated ({len(high_risk)} user(s))",
                "description": (
                    f"Entra Identity Protection has flagged {len(high_risk)} user(s) at HIGH risk with no remediation action. "
                    f"These accounts may be compromised. Require password reset and MFA re-registration immediately."
                ),
            }
        )

    if medium_risk:
        findings.append(
            {
                "type": "unmediated_medium_risk_users",
                "severity": "high",
                "title": f"Medium-Risk Users Not Remediated ({len(medium_risk)} user(s))",
                "description": (
                    f"Entra Identity Protection has flagged {len(medium_risk)} user(s) at MEDIUM risk. "
                    f"Investigate sign-in activity and enforce secure password change."
                ),
            }
        )

    return findings


def _analyze_ca_policies(ca_policies: list[dict]) -> list[dict]:
    findings: list[dict] = []
    if not ca_policies:
        findings.append(
            {
                "type": "no_conditional_access_policies",
                "severity": "critical",
                "title": "No Conditional Access Policies Found",
                "description": (
                    "No Conditional Access policies are configured. CA policies are the primary control "
                    "for enforcing MFA, blocking legacy auth, and limiting access to trusted locations. "
                    "Requires Azure AD P1 license."
                ),
            }
        )
        return findings

    enabled = [p for p in ca_policies if p.get("state") == "enabled"]
    report_only = [
        p for p in ca_policies if p.get("state") == "enabledForReportingButNotEnforced"
    ]

    if report_only:
        findings.append(
            {
                "type": "ca_policies_report_only",
                "severity": "medium",
                "title": f"Conditional Access Policies in Report-Only Mode ({len(report_only)} found)",
                "description": (
                    f"{len(report_only)} CA policy/policies are in report-only mode and not enforcing controls. "
                    f"Review impact data and switch policies to enforced mode."
                ),
            }
        )

    def _blocks_legacy_auth(policy: dict) -> bool:
        conditions = policy.get("conditions", {})
        client_apps = conditions.get("clientAppTypes", [])
        grant = policy.get("grantControls") or {}
        block = grant.get("operator") == "OR" and "block" in grant.get(
            "builtInControls", []
        )
        legacy_apps = {"exchangeActiveSync", "other"}
        return block and bool(legacy_apps & set(client_apps))

    def _requires_mfa(policy: dict) -> bool:
        grant = policy.get("grantControls") or {}
        return "mfa" in grant.get("builtInControls", [])

    has_legacy_block = any(_blocks_legacy_auth(p) for p in enabled)
    has_mfa_policy = any(_requires_mfa(p) for p in enabled)

    if not has_legacy_block:
        findings.append(
            {
                "type": "legacy_auth_not_blocked",
                "severity": "high",
                "title": "No Conditional Access Policy Blocking Legacy Authentication",
                "description": (
                    "No enabled CA policy blocks legacy authentication protocols (Exchange ActiveSync, SMTP AUTH, IMAP, POP3). "
                    "Legacy auth bypasses MFA and is the entry point for password spray attacks. "
                    "Create a CA policy that blocks clientAppTypes: exchangeActiveSync, other."
                ),
            }
        )

    if not has_mfa_policy:
        findings.append(
            {
                "type": "no_mfa_conditional_access",
                "severity": "high",
                "title": "No Conditional Access Policy Requiring MFA",
                "description": (
                    "No enabled CA policy enforces multi-factor authentication for any user. "
                    "Without a CA-enforced MFA policy, individual user MFA settings can be bypassed "
                    "or left unconfigured."
                ),
            }
        )

    return findings


def run_entra_governance(
    *,
    access_token: str,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Run Entra ID Governance scan.

    Checks PIM role assignments, access reviews, identity protection (P2-gated),
    and conditional access policy posture.

    Returns a raw payload dict compatible with source_type=entra_governance.
    Required top-level key: role_assignments (list).
    """
    scan_initiated_at = datetime.now(timezone.utc).isoformat()

    role_def_map = _get_role_definitions(access_token)

    try:
        role_assignments = _graph_get(
            access_token,
            "/roleManagement/directory/roleAssignments",
            {"$select": "id,principalId,roleDefinitionId,directoryScopeId"},
        )
    except Exception as exc:
        log.warning("entra_governance: failed to fetch role assignments: %s", exc)
        role_assignments = []

    try:
        eligibility_schedules = _graph_get(
            access_token,
            "/roleManagement/directory/roleEligibilitySchedules",
            {
                "$select": "id,principalId,roleDefinitionId,createdDateTime,startDateTime,status"
            },
        )
    except Exception as exc:
        log.warning("entra_governance: failed to fetch eligibility schedules: %s", exc)
        eligibility_schedules = []

    try:
        access_reviews = _graph_get(
            access_token,
            "/identityGovernance/accessReviews/definitions",
            {
                "$select": "id,displayName,status,isRecurring,scope,instanceEnumerationScope"
            },
        )
    except Exception as exc:
        log.warning("entra_governance: failed to fetch access reviews: %s", exc)
        access_reviews = []

    # P2-gated — gracefully skip on 403
    risky_users = _graph_get(
        access_token,
        "/identityProtection/riskyUsers",
        {
            "$select": "id,riskLevel,riskState,riskLastUpdatedDateTime",
            "$filter": "riskState ne 'remediated'",
        },
    )

    try:
        ca_policies = _graph_get(
            access_token,
            "/identity/conditionalAccess/policies",
            {"$select": "id,displayName,state,conditions,grantControls"},
        )
    except Exception as exc:
        log.warning("entra_governance: failed to fetch CA policies: %s", exc)
        ca_policies = []

    role_findings, role_summary = _analyze_role_assignments(
        role_assignments, eligibility_schedules, role_def_map
    )
    review_findings = _analyze_access_reviews(access_reviews)
    risk_findings = _analyze_risky_users(risky_users)
    ca_findings = _analyze_ca_policies(ca_policies)

    all_findings = role_findings + review_findings + risk_findings + ca_findings

    return {
        "role_assignments": role_assignments,
        "eligibility_schedules": eligibility_schedules,
        "access_reviews": access_reviews,
        "risky_users": risky_users,
        "ca_policies": ca_policies,
        "findings": all_findings,
        "summary": {
            **role_summary,
            "access_review_definitions": len(access_reviews),
            "risky_users_flagged": len(risky_users),
            "ca_policies_total": len(ca_policies),
            "ca_policies_enabled": len(
                [p for p in ca_policies if p.get("state") == "enabled"]
            ),
            "total_findings": len(all_findings),
        },
        "scan_initiated_at": scan_initiated_at,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
    }
