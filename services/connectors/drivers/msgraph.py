"""Microsoft Graph connector driver for FrostGate AI governance assessments.

Trust-but-verify design:
  1. build_scan_manifest() declares every Graph API call before execution.
     The client reviews and signs off via an acknowledgment token.
  2. execute_scan() runs only what was declared, HMAC-chains each action entry,
     and stores summaries — never raw response bodies.
  3. generate_methodology_statement() produces a human-readable leave-behind
     that names every endpoint touched, every scope used, and what was collected.

Scope constraints (read-only only):
  Application.Read.All, Directory.Read.All, Policy.Read.All,
  Reports.Read.All, User.Read.All, AuditLog.Read.All

No write, send, or privileged-admin scopes are used or accepted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Protocol

log = logging.getLogger("frostgate.connectors.msgraph")

# ---------------------------------------------------------------------------
# Scan action catalogue — one entry per Graph API call we may make
# ---------------------------------------------------------------------------

_SCAN_ACTIONS: list[dict[str, Any]] = [
    {
        "action_id": "oauth_app_inventory",
        "name": "OAuth Application Inventory",
        "graph_endpoint": "GET /applications",
        "select_fields": [
            "displayName",
            "appId",
            "requiredResourceAccess",
            "createdDateTime",
            "signInAudience",
            "publisherDomain",
        ],
        "oauth_scope_required": "Application.Read.All",
        "business_reason": (
            "Identify all OAuth-registered applications with access to M365 data, "
            "including AI tools such as ChatGPT plugins, Copilot extensions, and "
            "third-party automation platforms. Used to detect unauthorized AI exposure."
        ),
        "data_touched": (
            "App display names, client IDs (public), permission scopes requested. "
            "No email content, chat messages, or document bodies are accessed."
        ),
        "nist_control_id": "MAP 3.5",
        "domain": "security_posture",
        "max_records": 500,
    },
    {
        "action_id": "service_principal_inventory",
        "name": "Service Principal Inventory",
        "graph_endpoint": "GET /servicePrincipals?$filter=servicePrincipalType eq 'Application'",
        "select_fields": [
            "displayName",
            "appId",
            "servicePrincipalType",
            "appRoles",
            "oauth2PermissionScopes",
            "publisherName",
            "verifiedPublisher",
        ],
        "oauth_scope_required": "Application.Read.All",
        "business_reason": (
            "Enumerate enterprise app service principals to identify which third-party "
            "applications have been granted delegated or application permissions. Flags "
            "AI services with broad data access (e.g. full mailbox read, all files)."
        ),
        "data_touched": (
            "Service principal display names, app IDs, granted permission scopes. "
            "No user content accessed."
        ),
        "nist_control_id": "MAP 3.5",
        "domain": "security_posture",
        "max_records": 500,
    },
    {
        "action_id": "mfa_registration_status",
        "name": "MFA Registration Status",
        "graph_endpoint": "GET /reports/authenticationMethods/userRegistrationDetails",
        "select_fields": [
            "userPrincipalName",
            "isMfaRegistered",
            "isMfaCapable",
            "isPasswordlessCapable",
            "isSsprRegistered",
            "methodsRegistered",
        ],
        "oauth_scope_required": "Reports.Read.All",
        "business_reason": (
            "Determine what percentage of users have registered multi-factor "
            "authentication. MFA coverage is a prerequisite for secure AI tool access "
            "and a leading indicator of overall identity security posture."
        ),
        "data_touched": (
            "User principal names and MFA registration boolean flags. "
            "No passwords, credentials, or authentication tokens are accessed."
        ),
        "nist_control_id": "GOVERN 2.2",
        "domain": "security_posture",
        "max_records": 5000,
    },
    {
        "action_id": "conditional_access_policies",
        "name": "Conditional Access Policy Inventory",
        "graph_endpoint": "GET /identity/conditionalAccessPolicies",
        "select_fields": [
            "displayName",
            "state",
            "conditions",
            "grantControls",
            "sessionControls",
            "createdDateTime",
            "modifiedDateTime",
        ],
        "oauth_scope_required": "Policy.Read.All",
        "business_reason": (
            "Identify whether Conditional Access policies exist that restrict AI tool "
            "access based on device compliance, location, or risk level. Absence of "
            "CA policies covering AI apps is a governance gap under GOVERN 2.2."
        ),
        "data_touched": (
            "Policy names, enabled/disabled status, conditions (app IDs, user groups), "
            "and grant control types (MFA required, compliant device). "
            "No user session data or authentication logs accessed."
        ),
        "nist_control_id": "GOVERN 2.2",
        "domain": "security_posture",
        "max_records": 200,
    },
    {
        "action_id": "privileged_role_members",
        "name": "Privileged Directory Role Membership",
        "graph_endpoint": "GET /directoryRoles",
        "select_fields": ["displayName", "roleTemplateId", "members"],
        "oauth_scope_required": "Directory.Read.All",
        "business_reason": (
            "Identify users assigned to Global Administrator, Security Administrator, "
            "or AI service-specific privileged roles. Excessive privileged access to "
            "AI systems is a key risk factor under GOVERN 1.2."
        ),
        "data_touched": (
            "Role display names and member user principal names. "
            "No user content, mail, or files accessed."
        ),
        "nist_control_id": "GOVERN 1.2",
        "domain": "ai_maturity",
        "max_records": 100,
    },
    {
        "action_id": "copilot_license_coverage",
        "name": "Microsoft Copilot License Coverage",
        "graph_endpoint": "GET /subscribedSkus",
        "select_fields": [
            "skuPartNumber",
            "skuId",
            "consumedUnits",
            "prepaidUnits",
            "servicePlans",
        ],
        "oauth_scope_required": "Directory.Read.All",
        "business_reason": (
            "Determine how many Microsoft 365 Copilot licenses are provisioned versus "
            "consumed, and which Copilot-related service plans are active. Unmanaged "
            "Copilot deployment without governance controls maps to MEASURE 3.1."
        ),
        "data_touched": (
            "SKU part numbers (product names), license counts (consumed vs. provisioned). "
            "No user content or individual usage records accessed."
        ),
        "nist_control_id": "MEASURE 3.1",
        "domain": "ai_maturity",
        "max_records": 50,
    },
    {
        "action_id": "signin_risk_events",
        "name": "Recent Sign-In Risk Summary (30-day aggregate)",
        "graph_endpoint": "GET /auditLogs/signIns?$filter=riskLevelAggregated ne 'none'&$top=100",
        "select_fields": [
            "userPrincipalName",
            "riskLevelAggregated",
            "riskState",
            "riskEventTypes",
            "appDisplayName",
            "createdDateTime",
        ],
        "oauth_scope_required": "AuditLog.Read.All",
        "business_reason": (
            "Identify high-risk sign-in events from the past 30 days, particularly those "
            "involving AI tools or broad-permission apps. Elevated risk with AI access "
            "is relevant to MEASURE 2.9 (anomaly detection) and MANAGE 2.4."
        ),
        "data_touched": (
            "User principal names, risk level labels (low/medium/high), and app names "
            "for risky sign-ins only. No sign-in token content, session data, or "
            "authentication secrets accessed."
        ),
        "nist_control_id": "MEASURE 2.9",
        "domain": "security_posture",
        "max_records": 100,
    },
]

# Canonical action index by ID
_ACTION_INDEX: dict[str, dict[str, Any]] = {a["action_id"]: a for a in _SCAN_ACTIONS}


# ---------------------------------------------------------------------------
# Protocol for Graph HTTP client (injectable for testing)
# ---------------------------------------------------------------------------


class GraphClient(Protocol):
    def get(
        self,
        path: str,
        *,
        select: list[str] | None = None,
        top: int | None = None,
        filter_expr: str | None = None,
    ) -> list[dict[str, Any]]: ...


# ---------------------------------------------------------------------------
# Manifest + result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ScanAction:
    action_id: str
    name: str
    graph_endpoint: str
    select_fields: list[str]
    oauth_scope_required: str
    business_reason: str
    data_touched: str
    nist_control_id: str
    domain: str
    max_records: int


@dataclass
class ScanManifest:
    manifest_id: str  # SHA-256[:16] of canonical action list
    actions: list[ScanAction]
    generated_at: str  # ISO
    total_scopes_required: list[str]


@dataclass
class ActionResult:
    action_id: str
    executed_at: str
    duration_ms: int
    status: str  # "ok" | "error" | "skipped"
    record_count: int
    summary: str
    findings: list[dict[str, Any]]  # structured, no raw PII
    error_detail: str = ""


@dataclass
class ScanSession:
    session_id: str
    manifest: ScanManifest
    results: list[ActionResult] = field(default_factory=list)
    hmac_chain: list[dict[str, Any]] = field(default_factory=list)
    _prev_hmac: str = field(default="", repr=False)


# ---------------------------------------------------------------------------
# HMAC chain helpers
# ---------------------------------------------------------------------------

_CHAIN_SECRET_ENV = "FG_SCAN_CHAIN_SECRET"


def _chain_secret() -> bytes:
    import os

    secret = os.environ.get(_CHAIN_SECRET_ENV, "")
    if not secret:
        # Fail closed — no secret, no chain
        raise RuntimeError(
            f"HMAC chain secret missing: set {_CHAIN_SECRET_ENV} env var"
        )
    return secret.encode()


def _hmac_entry(prev_hmac: str, entry_data: dict[str, Any]) -> str:
    canonical = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
    msg = (prev_hmac + canonical).encode()
    return hmac.new(_chain_secret(), msg, hashlib.sha256).hexdigest()


def _manifest_id(actions: list[ScanAction]) -> str:
    canonical = json.dumps(
        [a.action_id for a in actions], sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Core driver functions
# ---------------------------------------------------------------------------


def build_scan_manifest(
    action_ids: list[str] | None = None,
) -> ScanManifest:
    """Return a manifest describing every Graph call that will be made.

    If action_ids is None, all defined actions are included.
    The manifest is shown to the client for review before execution.
    """
    catalogue = _SCAN_ACTIONS if action_ids is None else [
        _ACTION_INDEX[aid] for aid in action_ids if aid in _ACTION_INDEX
    ]

    actions = [
        ScanAction(
            action_id=a["action_id"],
            name=a["name"],
            graph_endpoint=a["graph_endpoint"],
            select_fields=a["select_fields"],
            oauth_scope_required=a["oauth_scope_required"],
            business_reason=a["business_reason"],
            data_touched=a["data_touched"],
            nist_control_id=a["nist_control_id"],
            domain=a["domain"],
            max_records=a["max_records"],
        )
        for a in catalogue
    ]

    scopes = sorted({a.oauth_scope_required for a in actions})
    return ScanManifest(
        manifest_id=_manifest_id(actions),
        actions=actions,
        generated_at=datetime.now(UTC).isoformat(),
        total_scopes_required=scopes,
    )


def acknowledgment_token(manifest: ScanManifest, tenant_id: str) -> str:
    """Derive a client acknowledgment token from the manifest + tenant.

    The client signs this to authorise execution. The token is deterministic —
    re-presenting the same manifest for the same tenant always yields the same
    token, making forgery detectable.
    """
    payload = json.dumps(
        {
            "manifest_id": manifest.manifest_id,
            "tenant_id": tenant_id,
            "action_ids": sorted(a.action_id for a in manifest.actions),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hmac.new(_chain_secret(), payload.encode(), hashlib.sha256).hexdigest()[:32]


def verify_acknowledgment(
    manifest: ScanManifest,
    tenant_id: str,
    provided_token: str,
) -> bool:
    expected = acknowledgment_token(manifest, tenant_id)
    return hmac.compare_digest(expected, provided_token)


def execute_action(
    session: ScanSession,
    action: ScanAction,
    graph: GraphClient,
) -> ActionResult:
    """Execute one scan action, record it in the HMAC chain, return results."""
    start = datetime.now(UTC)
    findings: list[dict[str, Any]] = []
    error_detail = ""
    record_count = 0
    status = "ok"

    try:
        records = graph.get(
            action.graph_endpoint,
            select=action.select_fields,
            top=action.max_records,
        )
        record_count = len(records)
        findings = _analyse(action.action_id, records)
        summary = _summarise(action.action_id, records, findings)

    except Exception as exc:
        log.warning("msgraph action %s failed: %s", action.action_id, exc)
        status = "error"
        error_detail = str(exc)
        summary = f"Error during {action.name}: {exc}"

    end = datetime.now(UTC)
    duration_ms = int((end - start).total_seconds() * 1000)

    result = ActionResult(
        action_id=action.action_id,
        executed_at=start.isoformat(),
        duration_ms=duration_ms,
        status=status,
        record_count=record_count,
        summary=summary,
        findings=findings,
        error_detail=error_detail,
    )

    # HMAC-chain the log entry — binds this action to its position in the session
    entry_data = {
        "seq": len(session.hmac_chain) + 1,
        "action_id": action.action_id,
        "executed_at": result.executed_at,
        "duration_ms": duration_ms,
        "status": status,
        "record_count": record_count,
        "summary": summary,
    }
    entry_hmac = _hmac_entry(session._prev_hmac, entry_data)
    entry_data["entry_hmac"] = entry_hmac
    session.hmac_chain.append(entry_data)
    session._prev_hmac = entry_hmac
    session.results.append(result)

    return result


# ---------------------------------------------------------------------------
# Per-action analysis — structured findings, no raw PII stored
# ---------------------------------------------------------------------------

# Microsoft Graph permission GUIDs for broad/sensitive data access.
# requiredResourceAccess.resourceAccess.id is always a GUID — never the
# human-readable scope name — so we must match on GUIDs here.
# Microsoft Graph resourceAppId: 00000003-0000-0000-c000-000000000000
_BROAD_SCOPE_GUIDS: dict[str, str] = {
    # Delegated
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d": "Mail.Read",
    "024d486e-b451-40bb-833d-3e66d98c5c73": "Mail.ReadWrite",
    "df85f4d6-205c-4ac5-a5ea-6bf408dba283": "Files.Read.All",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
    "f501c180-9344-439a-bca0-6cbf209fd270": "Chat.Read",
    "9ff7295e-131b-4d94-90e1-69fde507ac11": "Chat.ReadWrite",
    "7b2449af-6ccd-4f98-a5ac-c105e629b9bb": "ChannelMessage.Read.All",
    "1ec239c2-d7c9-4623-a91a-a9775856bb36": "Calendars.ReadWrite",
    "ff74d97f-43af-4b68-9f2a-b4db0b4f26f2": "Contacts.Read",
    # Application
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read (app)",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite (app)",
    "01d4889c-1287-42c6-ac1f-5d1e02578ef6": "Files.Read.All (app)",
    "6b7d71aa-70aa-4810-a8d9-5d9fb2830017": "Chat.Read.All (app)",
}

_AI_APP_KEYWORDS = {
    "gpt",
    "openai",
    "chatgpt",
    "copilot",
    "claude",
    "anthropic",
    "gemini",
    "bard",
    "mistral",
    "cohere",
    "ai",
    "assistant",
    "llm",
    "zapier",
    "make",
    "n8n",
    "automation",
}


def _is_ai_app(display_name: str, required_resource_access: list) -> bool:
    name_lower = display_name.lower()
    if any(kw in name_lower for kw in _AI_APP_KEYWORDS):
        return True
    # Check if it requests broad data scopes typical of AI tools
    scope_count = sum(
        len(rra.get("resourceAccess", [])) for rra in (required_resource_access or [])
    )
    return scope_count >= 5


def _analyse(action_id: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if action_id == "oauth_app_inventory":
        return _analyse_oauth_apps(records)
    if action_id == "service_principal_inventory":
        return _analyse_service_principals(records)
    if action_id == "mfa_registration_status":
        return _analyse_mfa(records)
    if action_id == "conditional_access_policies":
        return _analyse_ca_policies(records)
    if action_id == "privileged_role_members":
        return _analyse_roles(records)
    if action_id == "copilot_license_coverage":
        return _analyse_copilot_licenses(records)
    if action_id == "signin_risk_events":
        return _analyse_signin_risks(records)
    return []


def _analyse_oauth_apps(records: list[dict]) -> list[dict]:
    findings = []
    ai_apps = []
    broad_permission_apps = []

    for rec in records:
        name = rec.get("displayName", "")
        rra = rec.get("requiredResourceAccess") or []
        app_id = rec.get("appId", "")
        is_ai = _is_ai_app(name, rra)
        scope_count = sum(len(r.get("resourceAccess", [])) for r in rra)

        if is_ai:
            ai_apps.append({"name": name, "app_id": app_id, "scope_count": scope_count})

        broad_scopes = []
        for rra_entry in rra:
            for ra in rra_entry.get("resourceAccess", []):
                # resourceAccess.id is a GUID — match against the GUID map
                rid = (ra.get("id") or "").lower()
                scope_name = _BROAD_SCOPE_GUIDS.get(rid)
                if scope_name:
                    broad_scopes.append(scope_name)
        if broad_scopes:
            broad_permission_apps.append({
                "name": name,
                "app_id": app_id,
                "broad_scopes": broad_scopes,
            })

    if ai_apps:
        findings.append({
            "finding_type": "shadow_ai_apps_detected",
            "severity": "high" if len(ai_apps) >= 5 else "medium",
            "count": len(ai_apps),
            "apps": ai_apps[:20],  # cap at 20 to avoid bloat
            "nist_control_id": "MAP 3.5",
            "description": (
                f"Found {len(ai_apps)} OAuth-registered application(s) identified as AI "
                "tools or automation platforms with access to M365 data."
            ),
        })
    if broad_permission_apps:
        findings.append({
            "finding_type": "broad_data_scope_apps",
            "severity": "medium",
            "count": len(broad_permission_apps),
            "apps": broad_permission_apps[:20],
            "nist_control_id": "GOVERN 2.2",
            "description": (
                f"{len(broad_permission_apps)} application(s) have been granted "
                "broad read/write permissions to mail, files, or chat content."
            ),
        })
    return findings


def _analyse_service_principals(records: list[dict]) -> list[dict]:
    findings = []
    unverified_ai = []

    for rec in records:
        name = rec.get("displayName", "")
        verified = rec.get("verifiedPublisher") or {}
        is_verified = bool(verified.get("displayName"))
        rra = rec.get("oauth2PermissionScopes") or []
        if _is_ai_app(name, []) and not is_verified:
            unverified_ai.append({"name": name, "app_id": rec.get("appId", "")})

    if unverified_ai:
        findings.append({
            "finding_type": "unverified_ai_service_principals",
            "severity": "high",
            "count": len(unverified_ai),
            "apps": unverified_ai[:20],
            "nist_control_id": "MAP 3.5",
            "description": (
                f"{len(unverified_ai)} AI-related service principal(s) lack a verified "
                "publisher, increasing supply-chain risk."
            ),
        })
    return findings


def _analyse_mfa(records: list[dict]) -> list[dict]:
    findings = []
    total = len(records)
    if total == 0:
        return findings

    mfa_registered = sum(1 for r in records if r.get("isMfaRegistered"))
    mfa_pct = round((mfa_registered / total) * 100, 1)
    not_registered = total - mfa_registered

    severity = "critical" if mfa_pct < 50 else "high" if mfa_pct < 80 else "medium" if mfa_pct < 95 else "info"
    findings.append({
        "finding_type": "mfa_coverage",
        "severity": severity,
        "total_users": total,
        "mfa_registered": mfa_registered,
        "mfa_not_registered": not_registered,
        "mfa_coverage_pct": mfa_pct,
        "nist_control_id": "GOVERN 2.2",
        "description": (
            f"{mfa_pct}% of users ({mfa_registered}/{total}) have MFA registered. "
            f"{not_registered} user(s) can access M365 — including AI tools — "
            "with password only."
        ),
    })
    return findings


def _analyse_ca_policies(records: list[dict]) -> list[dict]:
    findings = []
    enabled = [r for r in records if r.get("state") == "enabled"]
    disabled = [r for r in records if r.get("state") != "enabled"]
    mfa_enforcing = [
        r for r in enabled
        if "mfa" in json.dumps(r.get("grantControls") or {}).lower()
    ]

    if not enabled:
        findings.append({
            "finding_type": "no_conditional_access_policies",
            "severity": "critical",
            "nist_control_id": "GOVERN 2.2",
            "description": (
                "No enabled Conditional Access policies found. All users can access "
                "M365 and connected AI tools without risk-based access controls."
            ),
        })
    elif not mfa_enforcing:
        findings.append({
            "finding_type": "no_mfa_enforcing_ca_policy",
            "severity": "high",
            "enabled_policies": len(enabled),
            "nist_control_id": "GOVERN 2.2",
            "description": (
                f"{len(enabled)} CA policy/policies exist but none enforce MFA as a "
                "grant control. AI tools can be accessed without MFA challenge."
            ),
        })
    else:
        findings.append({
            "finding_type": "conditional_access_present",
            "severity": "info",
            "enabled_policies": len(enabled),
            "mfa_enforcing_policies": len(mfa_enforcing),
            "disabled_policies": len(disabled),
            "nist_control_id": "GOVERN 2.2",
            "description": (
                f"{len(mfa_enforcing)} of {len(enabled)} enabled CA policies enforce MFA."
            ),
        })
    return findings


def _analyse_roles(records: list[dict]) -> list[dict]:
    findings = []
    privileged_roles = {
        "Global Administrator",
        "Security Administrator",
        "Privileged Role Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
    }

    for role in records:
        role_name = role.get("displayName", "")
        if role_name not in privileged_roles:
            continue
        members = role.get("members") or []
        if len(members) > 5:
            findings.append({
                "finding_type": "excessive_privileged_role_members",
                "severity": "high",
                "role": role_name,
                "member_count": len(members),
                "nist_control_id": "GOVERN 1.2",
                "description": (
                    f"'{role_name}' has {len(members)} members. Privileged access to "
                    "the M365 tenant — and all connected AI services — should be "
                    "limited to ≤5 accounts."
                ),
            })
    return findings


def _analyse_copilot_licenses(records: list[dict]) -> list[dict]:
    findings = []
    copilot_skus = [
        r for r in records
        if "COPILOT" in (r.get("skuPartNumber") or "").upper()
        or any(
            "COPILOT" in (sp.get("servicePlanName") or "").upper()
            for sp in (r.get("servicePlans") or [])
        )
    ]

    if copilot_skus:
        total_consumed = sum(r.get("consumedUnits", 0) for r in copilot_skus)
        total_prepaid = sum(
            (r.get("prepaidUnits") or {}).get("enabled", 0) for r in copilot_skus
        )
        findings.append({
            "finding_type": "copilot_deployment_detected",
            "severity": "medium",
            "copilot_licenses_provisioned": total_prepaid,
            "copilot_licenses_consumed": total_consumed,
            "nist_control_id": "MEASURE 3.1",
            "description": (
                f"Microsoft 365 Copilot: {total_consumed} of {total_prepaid} licenses "
                "in use. Verify that Copilot governance controls, data boundary "
                "settings, and acceptable use policies are in place."
            ),
        })
    else:
        findings.append({
            "finding_type": "copilot_not_detected",
            "severity": "info",
            "nist_control_id": "MEASURE 3.1",
            "description": "No Microsoft 365 Copilot licenses found in this tenant.",
        })
    return findings


def _analyse_signin_risks(records: list[dict]) -> list[dict]:
    findings = []
    high_risk = [r for r in records if r.get("riskLevelAggregated") == "high"]
    medium_risk = [r for r in records if r.get("riskLevelAggregated") == "medium"]

    if high_risk:
        ai_high_risk = [
            r for r in high_risk
            if any(kw in (r.get("appDisplayName") or "").lower() for kw in _AI_APP_KEYWORDS)
        ]
        findings.append({
            "finding_type": "high_risk_signin_events",
            "severity": "critical" if ai_high_risk else "high",
            "high_risk_count": len(high_risk),
            "ai_app_high_risk_count": len(ai_high_risk),
            "medium_risk_count": len(medium_risk),
            "nist_control_id": "MEASURE 2.9",
            "description": (
                f"{len(high_risk)} high-risk sign-in event(s) in the past 30 days"
                + (
                    f", including {len(ai_high_risk)} involving AI tools."
                    if ai_high_risk
                    else "."
                )
            ),
        })
    return findings


def _summarise(
    action_id: str, records: list[dict], findings: list[dict]
) -> str:
    count = len(records)
    finding_count = len(findings)
    action = _ACTION_INDEX.get(action_id, {})
    name = action.get("name", action_id)

    if action_id == "mfa_registration_status" and findings:
        f = findings[0]
        return (
            f"{name}: {count} users checked. "
            f"MFA coverage: {f.get('mfa_coverage_pct', 0)}% "
            f"({f.get('mfa_registered', 0)}/{count})."
        )
    if action_id == "oauth_app_inventory" and findings:
        ai_finding = next((f for f in findings if f.get("finding_type") == "shadow_ai_apps_detected"), None)
        if ai_finding:
            return (
                f"{name}: {count} apps enumerated. "
                f"{ai_finding['count']} identified as AI or automation tools."
            )

    if finding_count:
        return f"{name}: {count} record(s) retrieved. {finding_count} finding(s) raised."
    return f"{name}: {count} record(s) retrieved. No findings."


# ---------------------------------------------------------------------------
# Methodology statement generator
# ---------------------------------------------------------------------------

_METHODOLOGY_TEMPLATE = """\
FROSTGATE AI GOVERNANCE ASSESSMENT — METHODOLOGY STATEMENT
===========================================================
Engagement Date : {date}
Tenant          : {tenant_id}
Session ID      : {session_id}
Manifest ID     : {manifest_id}

This statement documents the technical activities performed during the on-site
AI governance assessment conducted by FrostGate. It is provided as a leave-behind
for the client's compliance records.

SCOPE OF ACCESS
---------------
All access was READ-ONLY. No data was written, modified, or deleted.
No email, chat, or document content was accessed or retained.
The following Microsoft Graph API permission scopes were used:

{scopes}

ACTIONS PERFORMED
-----------------
{actions}

TECHNICAL METHODOLOGY
---------------------
1. A scan manifest was generated prior to execution, listing every API call
   to be made, the OAuth scope required, and the business reason. The client
   reviewed and acknowledged this manifest before any data was collected.

2. Each action was executed sequentially. Results were analysed for governance
   findings; raw API responses were not stored. Only structured summaries,
   record counts, and finding classifications are retained.

3. Every action is recorded in an HMAC-chained audit log. The chain can be
   replayed to verify that the session log has not been modified after the fact.

SUMMARY OF FINDINGS
-------------------
Total actions executed : {total_actions}
Actions succeeded      : {actions_ok}
Actions with errors    : {actions_error}
Total findings raised  : {total_findings}

CHAIN INTEGRITY
---------------
Session HMAC chain length : {chain_length} entries
Final chain HMAC          : {final_hmac}

This methodology statement was generated automatically by FrostGate Core.
For questions, contact your FrostGate engagement manager.
"""


def generate_methodology_statement(
    session: ScanSession, tenant_id: str
) -> str:
    actions_ok = sum(1 for r in session.results if r.status == "ok")
    actions_error = sum(1 for r in session.results if r.status == "error")
    total_findings = sum(len(r.findings) for r in session.results)

    scopes_used = sorted({
        _ACTION_INDEX[r.action_id]["oauth_scope_required"]
        for r in session.results
        if r.action_id in _ACTION_INDEX
    })
    scopes_block = "\n".join(f"  • {s}" for s in scopes_used) or "  (none)"

    actions_block_lines = []
    for i, result in enumerate(session.results, 1):
        action = _ACTION_INDEX.get(result.action_id, {})
        endpoint = action.get("graph_endpoint", "unknown")
        actions_block_lines.append(
            f"  {i:2d}. {result.action_id}\n"
            f"      Endpoint : {endpoint}\n"
            f"      Status   : {result.status} | Records: {result.record_count} | "
            f"Duration: {result.duration_ms}ms\n"
            f"      Summary  : {result.summary}"
        )
    actions_block = "\n\n".join(actions_block_lines) or "  (no actions executed)"

    final_hmac = session.hmac_chain[-1]["entry_hmac"] if session.hmac_chain else "none"

    return _METHODOLOGY_TEMPLATE.format(
        date=datetime.now(UTC).strftime("%Y-%m-%d"),
        tenant_id=tenant_id,
        session_id=session.session_id,
        manifest_id=session.manifest.manifest_id,
        scopes=scopes_block,
        actions=actions_block,
        total_actions=len(session.results),
        actions_ok=actions_ok,
        actions_error=actions_error,
        total_findings=total_findings,
        chain_length=len(session.hmac_chain),
        final_hmac=final_hmac,
    )
