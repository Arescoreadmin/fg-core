"""AI Signals Analyzer — Step 13.

Detects Copilot licensing, third-party AI apps, shadow AI, and user-consented AI grants.
Cross-references vendor_db/ai_vendors.json and vendor_db/approved_vendors.json.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.findings.derivation import derive_finding_id
from services.connectors.msgraph.findings.registry import (
    AI_001,
    AI_002,
    AI_003,
    AI_005,
    AI_006,
)
from services.connectors.msgraph.schema.analyzer_outputs import AISignalResult
from services.connectors.msgraph.schema.scan_result import EvidenceRef, Finding

_VENDOR_DB = Path(__file__).parent.parent / "vendor_db"

# Copilot service plan GUIDs (from Microsoft SKU reference)
_COPILOT_PLAN_IDS = frozenset(
    {
        "663a804f-1c30-4ff0-9915-9db84f0d1cea",  # Microsoft 365 Copilot
        "b4bac898-59da-4f50-a36c-8acd2395cc5a",  # Copilot in M365 Apps
    }
)

# High data-access scopes that indicate AI app can exfiltrate content
_DATA_SCOPES = frozenset(
    {
        "Mail.Read",
        "Mail.ReadWrite",
        "Files.Read",
        "Files.ReadWrite",
        "Calendars.Read",
        "Contacts.Read",
        "User.Read.All",
        "Chat.Read",
        "ChannelMessage.Read.All",
    }
)


def _load_vendor_db() -> tuple[set[str], set[str], list[str]]:
    """Returns (known_app_ids, approved_app_ids, display_name_patterns)."""
    try:
        ai_data = json.loads((_VENDOR_DB / "ai_vendors.json").read_text())
        approved_data = json.loads((_VENDOR_DB / "approved_vendors.json").read_text())
    except Exception:
        return set(), set(), []

    known_ids = {entry["app_id"] for entry in ai_data.get("known_ai_apps", [])}
    patterns: list[str] = ai_data.get("ai_display_name_patterns", [])
    approved_ids = set(approved_data.get("approved_app_ids", []))
    return known_ids, approved_ids, patterns


def _is_ai_app(sp: dict[str, Any], known_ids: set[str], patterns: list[str]) -> bool:
    app_id = sp.get("appId", "")
    if app_id in known_ids:
        return True
    name = (sp.get("displayName") or "").lower()
    return any(p in name for p in patterns)


def _evidence_hash(record_count: int, config_keys: list[str]) -> str:
    raw = f"{record_count}:{','.join(sorted(config_keys))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def run(
    client: GraphClient, tenant_id: str
) -> tuple[AISignalResult, list[Finding], list[EvidenceRef]]:
    now = datetime.now(timezone.utc).isoformat()

    known_ai_ids, approved_ids, ai_patterns = _load_vendor_db()

    # Fetch service principals to identify AI apps present in tenant
    sps = client.get_all(
        "/servicePrincipals",
        params={
            "$select": "id,appId,displayName,verifiedPublisher,servicePrincipalType,accountEnabled"
        },
    )

    # Fetch OAuth grants to identify consent type and scope for AI apps
    grants = client.get_all(
        "/oauth2PermissionGrants",
        params={"$select": "clientId,consentType,principalId,scope"},
    )

    # Fetch subscribed SKUs for Copilot licensing detection
    # Fetch users to count Copilot-assigned licenses
    try:
        users_with_copilot = client.get_all(
            "/users",
            params={"$select": "id,assignedPlans,accountEnabled"},
        )
    except Exception:
        users_with_copilot = []

    # -- Copilot detection --
    copilot_licensed = 0
    copilot_active = 0
    for user in users_with_copilot:
        if not user.get("accountEnabled"):
            continue
        plans: list[dict[str, Any]] = user.get("assignedPlans") or []
        user_has_copilot = any(
            p.get("servicePlanId") in _COPILOT_PLAN_IDS
            and p.get("capabilityStatus") == "Enabled"
            for p in plans
        )
        if user_has_copilot:
            copilot_licensed += 1

    # Copilot activity count would require Copilot usage reports — use licensed as proxy
    copilot_active = copilot_licensed

    # -- AI SP classification --
    ai_sps: list[dict[str, Any]] = [
        sp
        for sp in sps
        if sp.get("accountEnabled") and _is_ai_app(sp, known_ai_ids, ai_patterns)
    ]

    licensed_ai = {sp["appId"] for sp in ai_sps if sp.get("appId") in approved_ids}
    third_party_ai = len([sp for sp in ai_sps if sp.get("appId") not in approved_ids])
    shadow_ai = len(
        [
            sp
            for sp in ai_sps
            if sp.get("appId") not in approved_ids
            and sp.get("appId") not in known_ai_ids
        ]
    )
    unapproved_ai = len([sp for sp in ai_sps if sp.get("appId") not in approved_ids])

    # -- Consent analysis for AI apps --
    ai_client_ids = {sp.get("id", "") for sp in ai_sps}

    user_consented_ai = 0
    admin_consented_ai = 0
    dlp_score_3 = 0
    dlp_score_2 = 0

    for grant in grants:
        client_id = grant.get("clientId", "")
        if client_id not in ai_client_ids:
            continue

        consent_type = grant.get("consentType", "")
        if consent_type == "AllPrincipals":
            admin_consented_ai += 1
        else:
            user_consented_ai += 1

        # DLP score for this grant: data scope presence + consent type
        scope_str: str = grant.get("scope", "") or ""
        scopes = set(scope_str.split())
        data_scope_hit = bool(scopes & _DATA_SCOPES)
        offline_hit = "offline_access" in scopes
        score = (
            int(data_scope_hit)
            + int(offline_hit)
            + int(consent_type != "AllPrincipals")
        )
        if score >= 3:
            dlp_score_3 += 1
        elif score == 2:
            dlp_score_2 += 1

    result = AISignalResult(
        copilot_licensed_users=copilot_licensed,
        copilot_active_users=copilot_active,
        third_party_ai_apps=third_party_ai,
        shadow_ai_apps=shadow_ai,
        user_consented_ai=user_consented_ai,
        admin_consented_ai=admin_consented_ai,
        dlp_score_3_critical=dlp_score_3,
        dlp_score_2_high=dlp_score_2,
        unapproved_ai_apps=unapproved_ai,
    )

    config_state = {
        "copilot_licensed_users": copilot_licensed,
        "third_party_ai_apps": third_party_ai,
        "shadow_ai_apps": shadow_ai,
        "user_consented_ai": user_consented_ai,
        "dlp_score_3_critical": dlp_score_3,
        "dlp_score_2_high": dlp_score_2,
        "unapproved_ai_apps": unapproved_ai,
    }
    evidence = EvidenceRef(
        ref_id=f"ai-signals-{tenant_id[:8]}",
        endpoint="/servicePrincipals",
        record_count=len(ai_sps),
        config_state=config_state,
        collected_at=now,
        data_hash=_evidence_hash(len(ai_sps), list(config_state.keys())),
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

    if dlp_score_3 > 0:
        findings.append(
            _f(
                AI_001,
                dlp_score_3,
                f"{dlp_score_3} AI app grant(s) with maximum DLP exposure score (user-consented + offline_access + data scope).",
                f"dlp_score_3:{dlp_score_3}",
            )
        )
    if dlp_score_2 > 0:
        findings.append(
            _f(
                AI_002,
                dlp_score_2,
                f"{dlp_score_2} AI app grant(s) with elevated DLP exposure score.",
                f"dlp_score_2:{dlp_score_2}",
            )
        )
    if unapproved_ai > 0:
        findings.append(
            _f(
                AI_003,
                unapproved_ai,
                f"{unapproved_ai} AI application(s) detected with no admin approval record.",
                f"unapproved:{unapproved_ai}",
            )
        )
    if copilot_licensed > 0 and unapproved_ai == 0:
        # Copilot active but no shadow AI — check for policy gap (heuristic: flag if no CA policy for AI)
        pass  # Policy check is deferred to CA analyzer cross-reference
    if user_consented_ai > 0:
        findings.append(
            _f(
                AI_005,
                user_consented_ai,
                f"{user_consented_ai} AI application grant(s) made by users, not governed by admin consent.",
                f"user_consented_ai:{user_consented_ai}",
            )
        )

    findings.append(
        _f(
            AI_006,
            len(ai_sps),
            f"AI app inventory: {len(ai_sps)} total ({len(licensed_ai)} approved, {unapproved_ai} unapproved, {shadow_ai} shadow). Copilot licensed users: {copilot_licensed}.",
            f"inventory:{len(ai_sps)}:{unapproved_ai}",
        )
    )

    return result, findings, [evidence]
