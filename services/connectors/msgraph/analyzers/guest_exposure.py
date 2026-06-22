"""Guest Account Exposure Analyzer — Step 14."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.findings.derivation import derive_finding_id
from services.connectors.msgraph.findings.registry import (
    GUEST_001,
    GUEST_002,
    GUEST_003,
    GUEST_004,
    GUEST_005,
)
from services.connectors.msgraph.schema.analyzer_outputs import GuestExposureResult
from services.connectors.msgraph.schema.scan_result import EvidenceRef, Finding

_STALE_DAYS = 90
_ADMIN_ROLE_IDS = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # Privileged Role Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Authentication Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Role Administrator (AAD)
    }
)
# Group display name keywords that indicate sensitivity
_SENSITIVE_GROUP_PATTERNS = (
    "admin",
    "security",
    "compliance",
    "finance",
    "executive",
    "privileged",
    "sensitive",
    "confidential",
    "restricted",
)


def _evidence_hash(record_count: int, config_keys: list[str]) -> str:
    raw = f"{record_count}:{','.join(sorted(config_keys))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _days_since(dt_str: str | None) -> int | None:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _is_sensitive_group(group: dict[str, Any]) -> bool:
    name = (group.get("displayName") or "").lower()
    return any(p in name for p in _SENSITIVE_GROUP_PATTERNS)


def run(
    client: GraphClient, tenant_id: str
) -> tuple[GuestExposureResult, list[Finding], list[EvidenceRef]]:
    now = datetime.now(timezone.utc).isoformat()

    guests = client.get_all(
        "/users",
        params={
            "$filter": "userType eq 'Guest'",
            "$select": "id,accountEnabled,createdDateTime,signInActivity,userType",
        },
    )

    # Directory role members — fetch global admin and other high-priv roles
    # to find guest overlap
    role_member_ids: set[str] = set()
    for role_id in _ADMIN_ROLE_IDS:
        try:
            members = client.get_all(
                f"/directoryRoles/roleTemplateId={role_id}/members?$select=id,userType"
            )
            for m in members:
                if m.get("userType") == "Guest":
                    role_member_ids.add(m.get("id", ""))
        except Exception:
            pass

    # Groups — find sensitive groups containing guests
    groups = client.get_all(
        "/groups",
        params={"$select": "id,displayName,groupTypes"},
    )
    sensitive_group_ids = {g["id"] for g in groups if _is_sensitive_group(g)}
    guest_ids = {g.get("id", "") for g in guests}

    sensitive_group_guests: set[str] = set()
    for gid in sensitive_group_ids:
        try:
            members = client.get_all(f"/groups/{gid}/members?$select=id,userType")
            for m in members:
                if m.get("id") in guest_ids:
                    sensitive_group_guests.add(m["id"])
        except Exception:
            pass

    # Count metrics
    stale_90d = 0
    never_activated = 0
    privileged_role_guests = len(role_member_ids & guest_ids)

    for guest in guests:
        if not guest.get("accountEnabled"):
            continue
        last_signin = (guest.get("signInActivity") or {}).get("lastSignInDateTime")
        if last_signin is None:
            # Never signed in — check creation date to determine if invitation expired
            created_days = _days_since(guest.get("createdDateTime"))
            if created_days is not None and created_days > 30:
                never_activated += 1
        else:
            days_inactive = _days_since(last_signin)
            if days_inactive is not None and days_inactive >= _STALE_DAYS:
                stale_90d += 1

    result = GuestExposureResult(
        total_guests=len(guests),
        stale_guests_90d=stale_90d,
        never_activated=never_activated,
        privileged_role_guests=privileged_role_guests,
        sensitive_group_guests=len(sensitive_group_guests),
    )

    config_state = {
        "total_guests": len(guests),
        "stale_guests_90d": stale_90d,
        "never_activated": never_activated,
        "privileged_role_guests": privileged_role_guests,
        "sensitive_group_guests": len(sensitive_group_guests),
    }
    evidence = EvidenceRef(
        ref_id=f"guest-exposure-{tenant_id[:8]}",
        endpoint="/users?$filter=userType eq 'Guest'",
        record_count=len(guests),
        config_state=config_state,
        collected_at=now,
        data_hash=_evidence_hash(len(guests), list(config_state.keys())),
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

    if privileged_role_guests > 0:
        findings.append(
            _f(
                GUEST_001,
                privileged_role_guests,
                f"{privileged_role_guests} guest account(s) hold privileged directory roles.",
                f"priv_guests:{privileged_role_guests}",
            )
        )
    if len(sensitive_group_guests) > 0:
        findings.append(
            _f(
                GUEST_002,
                len(sensitive_group_guests),
                f"{len(sensitive_group_guests)} guest account(s) are members of sensitive groups.",
                f"sensitive_group_guests:{len(sensitive_group_guests)}",
            )
        )
    if stale_90d > 0:
        findings.append(
            _f(
                GUEST_003,
                stale_90d,
                f"{stale_90d} guest account(s) with no sign-in activity in 90+ days.",
                f"stale_90d:{stale_90d}",
            )
        )
    if never_activated > 0:
        findings.append(
            _f(
                GUEST_004,
                never_activated,
                f"{never_activated} guest invitation(s) accepted but never signed in (30+ days old).",
                f"never_activated:{never_activated}",
            )
        )

    findings.append(
        _f(
            GUEST_005,
            len(guests),
            f"{len(guests)} guest accounts total. Stale: {stale_90d}, never activated: {never_activated}, privileged: {privileged_role_guests}.",
            f"inventory:{len(guests)}",
        )
    )

    return result, findings, [evidence]
