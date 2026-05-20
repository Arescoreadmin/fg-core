"""Enterprise App / Service Principal Analyzer — Step 11."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.findings.derivation import derive_finding_id
from services.connectors.msgraph.findings.registry import (
    APP_001,
    APP_002,
    APP_003,
    APP_004,
    APP_005,
)
from services.connectors.msgraph.schema.analyzer_outputs import EnterpriseAppResult
from services.connectors.msgraph.schema.scan_result import EvidenceRef, Finding

_HIGH_PRIV_PERMISSIONS = frozenset(
    {
        "Mail.ReadWrite",
        "Files.ReadWrite",
        "Directory.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Application.ReadWrite.All",
        "Sites.FullControl.All",
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
    }
)


def _evidence_hash(record_count: int, config_keys: list[str]) -> str:
    raw = f"{record_count}:{','.join(sorted(config_keys))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_unverified(sp: dict[str, Any]) -> bool:
    vp = sp.get("verifiedPublisher") or {}
    return not vp.get("verifiedPublisherId")


def _has_high_priv_permissions(sp: dict[str, Any]) -> bool:
    perms: list[str] = []
    for rra in sp.get("requiredResourceAccess", []):
        for ra in rra.get("resourceAccess", []):
            perms.append(ra.get("id", ""))
    # We check displayValue if available; otherwise treat as unknown
    return bool(perms)  # simplified: presence of any permission request


def _days_since(dt_str: str | None) -> int | None:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def run(
    client: GraphClient, tenant_id: str
) -> tuple[EnterpriseAppResult, list[Finding], list[EvidenceRef]]:
    now = datetime.now(timezone.utc).isoformat()

    apps = client.get_all(
        "/applications",
        params={
            "$select": "id,displayName,publisherDomain,verifiedPublisher,createdDateTime,requiredResourceAccess"
        },
    )
    sps = client.get_all(
        "/servicePrincipals",
        params={
            "$select": "id,displayName,appId,publisherName,verifiedPublisher,accountEnabled,appRoleAssignmentRequired,servicePrincipalType,createdDateTime,signInActivity"
        },
    )

    # Count metrics
    unverified_high_priv = 0
    stale_90d = 0
    new_30d = 0
    user_consented_sensitive = 0
    admin_consented = 0

    for app in apps:
        days = _days_since(app.get("createdDateTime"))
        if days is not None and days <= 30:
            new_30d += 1

    for sp in sps:
        if not sp.get("accountEnabled"):
            continue
        last_signin = (sp.get("signInActivity") or {}).get("lastSignInDateTime")
        days_inactive = _days_since(last_signin)
        if days_inactive is not None and days_inactive >= 90:
            stale_90d += 1
        if _is_unverified(sp) and _has_high_priv_permissions(sp):
            unverified_high_priv += 1

    # Check OAuth grants for user consent
    grants = client.get_all(
        "/oauth2PermissionGrants",
        params={"$select": "clientId,consentType,principalId,resourceId,scope"},
    )
    for grant in grants:
        if grant.get("consentType") == "Principal":
            user_consented_sensitive += 1
        else:
            admin_consented += 1

    result = EnterpriseAppResult(
        total_apps=len(apps),
        total_service_principals=len(sps),
        unverified_publisher_high_priv=unverified_high_priv,
        stale_apps_90d=stale_90d,
        new_apps_30d=new_30d,
        user_consented_sensitive=user_consented_sensitive,
        admin_consented=admin_consented,
    )

    config_state = {
        "total_apps": len(apps),
        "total_service_principals": len(sps),
        "unverified_publisher_high_priv": unverified_high_priv,
        "stale_apps_90d": stale_90d,
        "new_apps_30d": new_30d,
        "user_consented_sensitive": user_consented_sensitive,
    }
    evidence = EvidenceRef(
        ref_id=f"enterprise-apps-{tenant_id[:8]}",
        endpoint="/applications",
        record_count=len(apps) + len(sps),
        config_state=config_state,
        collected_at=now,
        data_hash=_evidence_hash(len(apps) + len(sps), list(config_state.keys())),
    )

    findings: list[Finding] = []

    def _f(fdef: Any, count: int, summary: str, evidence_key: str) -> Finding:
        return Finding(
            finding_id=derive_finding_id(
                tenant_id=tenant_id,
                control_id=fdef.control_id,
                evidence_key=evidence_key,
            ),
            control_id=fdef.control_id,
            framework_refs=list(fdef.framework_refs),
            severity=fdef.severity,
            title=fdef.title,
            evidence_summary=summary,
            affected_count=count,
            affected_entities=list(fdef.affected_entities),
            recommendation=fdef.recommendation,
            remediation_effort=fdef.remediation_effort,
            remediation_owner=fdef.remediation_owner,
            evidence_refs=[evidence.ref_id],
        )

    if unverified_high_priv > 0:
        findings.append(
            _f(
                APP_001,
                unverified_high_priv,
                f"{unverified_high_priv} app(s) have unverified publisher with active permissions.",
                f"unverified_high_priv:{unverified_high_priv}",
            )
        )
    if stale_90d > 0:
        findings.append(
            _f(
                APP_002,
                stale_90d,
                f"{stale_90d} app(s) inactive for 90+ days with active permissions.",
                f"stale_90d:{stale_90d}",
            )
        )
    if new_30d > 0:
        findings.append(
            _f(
                APP_003,
                new_30d,
                f"{new_30d} application(s) created in the last 30 days.",
                f"new_30d:{new_30d}",
            )
        )
    if user_consented_sensitive > 0:
        findings.append(
            _f(
                APP_004,
                user_consented_sensitive,
                f"{user_consented_sensitive} user-consented grant(s) to apps with resource access.",
                f"user_consented:{user_consented_sensitive}",
            )
        )

    findings.append(
        _f(
            APP_005,
            len(apps),
            f"{len(apps)} registered apps and {len(sps)} service principals in tenant.",
            f"inventory:{len(apps)}:{len(sps)}",
        )
    )

    return result, findings, [evidence]
