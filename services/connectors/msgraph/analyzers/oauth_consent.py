"""OAuth Consent Grant Analyzer — Step 12."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.findings.derivation import derive_finding_id
from services.connectors.msgraph.findings.registry import (
    OAUTH_001,
    OAUTH_002,
    OAUTH_003,
    OAUTH_004,
    OAUTH_005,
)
from services.connectors.msgraph.schema.analyzer_outputs import OAuthConsentResult
from services.connectors.msgraph.schema.scan_result import EvidenceRef, Finding

# Scopes that indicate persistent background data access
_OFFLINE_ACCESS_SCOPE = "offline_access"
# Scopes that indicate reading sensitive user data
_DATA_ACCESS_SCOPES = frozenset(
    {
        "Mail.Read",
        "Mail.ReadWrite",
        "Files.Read",
        "Files.ReadWrite",
        "Calendars.Read",
        "Contacts.Read",
        "User.Read.All",
    }
)
_STALE_DAYS = 180


def _evidence_hash(record_count: int, config_keys: list[str]) -> str:
    raw = f"{record_count}:{','.join(sorted(config_keys))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_unverified_sp(sp: dict[str, Any]) -> bool:
    vp = sp.get("verifiedPublisher") or {}
    return not vp.get("verifiedPublisherId")


def _days_since(dt_str: str | None) -> int | None:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _score_grant(grant: dict[str, Any], sp_map: dict[str, dict[str, Any]]) -> int:
    """Risk score 0-3: +1 unverified publisher, +1 offline_access, +1 data-access scope."""
    score = 0
    client_id = grant.get("clientId", "")
    sp = sp_map.get(client_id, {})
    if _is_unverified_sp(sp):
        score += 1

    scope_str: str = grant.get("scope", "") or ""
    scopes = set(scope_str.split())
    if _OFFLINE_ACCESS_SCOPE in scopes:
        score += 1
    if scopes & _DATA_ACCESS_SCOPES:
        score += 1

    return score


def run(
    client: GraphClient, tenant_id: str
) -> tuple[OAuthConsentResult, list[Finding], list[EvidenceRef]]:
    now = datetime.now(timezone.utc).isoformat()

    grants = client.get_all(
        "/oauth2PermissionGrants",
        params={
            "$select": "clientId,consentType,principalId,resourceId,scope,expiryTime,startTime"
        },
    )

    # Fetch service principal verification status for all unique clientIds
    client_ids: set[str] = {g.get("clientId", "") for g in grants if g.get("clientId")}
    sp_map: dict[str, dict[str, Any]] = {}
    for cid in client_ids:
        try:
            sp = client.get_one(
                f"/servicePrincipals/{cid}?$select=id,verifiedPublisher,publisherName"
            )
            sp_map[cid] = sp
        except Exception:
            sp_map[cid] = {}

    total = len(grants)
    admin_consented = 0
    user_consented = 0
    score_3 = 0
    score_2 = 0
    score_1 = 0
    stale_180d = 0
    unverified_publisher = 0

    admin_unverified_with_data: list[dict[str, Any]] = []

    for grant in grants:
        consent_type = grant.get("consentType", "")
        if consent_type == "AllPrincipals":
            admin_consented += 1
        else:
            user_consented += 1

        # Staleness: use expiryTime as proxy for last modification
        # startTime is when the grant was created
        stale_days = _days_since(grant.get("startTime"))
        if stale_days is not None and stale_days >= _STALE_DAYS:
            stale_180d += 1

        client_id = grant.get("clientId", "")
        sp = sp_map.get(client_id, {})
        if _is_unverified_sp(sp):
            unverified_publisher += 1

        score = _score_grant(grant, sp_map)
        if score >= 3:
            score_3 += 1
        elif score == 2:
            score_2 += 1
        elif score == 1:
            score_1 += 1

        # Admin-consented to unverified with data-access scopes
        if consent_type == "AllPrincipals" and _is_unverified_sp(sp):
            scope_str: str = grant.get("scope", "") or ""
            scopes = set(scope_str.split())
            if scopes & _DATA_ACCESS_SCOPES:
                admin_unverified_with_data.append(grant)

    result = OAuthConsentResult(
        total_grants=total,
        admin_consented=admin_consented,
        user_consented=user_consented,
        score_3_critical=score_3,
        score_2_high=score_2,
        score_1_medium=score_1,
        stale_grants_180d=stale_180d,
        unverified_publisher_grants=unverified_publisher,
    )

    config_state = {
        "total_grants": total,
        "admin_consented": admin_consented,
        "user_consented": user_consented,
        "score_3_critical": score_3,
        "score_2_high": score_2,
        "stale_grants_180d": stale_180d,
        "unverified_publisher_grants": unverified_publisher,
    }
    evidence = EvidenceRef(
        ref_id=f"oauth-grants-{tenant_id[:8]}",
        endpoint="/oauth2PermissionGrants",
        record_count=total,
        config_state=config_state,
        collected_at=now,
        data_hash=_evidence_hash(total, list(config_state.keys())),
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

    if score_3 > 0:
        findings.append(
            _f(
                OAUTH_001,
                score_3,
                f"{score_3} user-consented grant(s) with full risk profile (unverified publisher + offline_access + data scope).",
                f"score_3:{score_3}",
            )
        )
    if score_2 > 0:
        findings.append(
            _f(
                OAUTH_002,
                score_2,
                f"{score_2} grant(s) with elevated risk score (2/3 risk criteria met).",
                f"score_2:{score_2}",
            )
        )
    if admin_unverified_with_data:
        findings.append(
            _f(
                OAUTH_003,
                len(admin_unverified_with_data),
                f"{len(admin_unverified_with_data)} admin-consented grant(s) to unverified publishers with data-access scopes.",
                f"admin_unverified_data:{len(admin_unverified_with_data)}",
            )
        )
    if stale_180d > 0:
        findings.append(
            _f(
                OAUTH_004,
                stale_180d,
                f"{stale_180d} OAuth grant(s) created 180+ days ago with no rotation.",
                f"stale_180d:{stale_180d}",
            )
        )

    findings.append(
        _f(
            OAUTH_005,
            total,
            f"{total} OAuth grants: {admin_consented} admin-consented, {user_consented} user-consented. {unverified_publisher} to unverified publishers.",
            f"inventory:{total}:{admin_consented}:{user_consented}",
        )
    )

    return result, findings, [evidence]
