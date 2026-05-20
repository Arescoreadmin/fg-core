"""Privileged Role Inventory Analyzer — Step 15."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.findings.derivation import derive_finding_id
from services.connectors.msgraph.findings.registry import (
    PRIV_001,
    PRIV_002,
    PRIV_003,
    PRIV_004,
    PRIV_005,
    PRIV_006,
)
from services.connectors.msgraph.schema.analyzer_outputs import PrivilegedRoleResult
from services.connectors.msgraph.schema.scan_result import EvidenceRef, Finding

# Roles that warrant privileged role analysis
_WATCHED_ROLES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "Privileged Role Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
    "0964bb5e-9bdb-4d7b-ac29-58e794862a40": "SharePoint Administrator",
}

_GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


def _evidence_hash(record_count: int, config_keys: list[str]) -> str:
    raw = f"{record_count}:{','.join(sorted(config_keys))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_synced_account(member: dict[str, Any]) -> bool:
    # on-prem synced accounts have onPremisesSyncEnabled=True or onPremisesImmutableId set
    return bool(
        member.get("onPremisesSyncEnabled") or member.get("onPremisesImmutableId")
    )


def _has_mfa(member: dict[str, Any], reg_by_id: dict[str, dict[str, Any]]) -> bool:
    reg = reg_by_id.get(member.get("id", ""), {})
    return reg.get("isMfaRegistered", False) or reg.get("isMfaCapable", False)


def run(
    client: GraphClient, tenant_id: str
) -> tuple[PrivilegedRoleResult, list[Finding], list[EvidenceRef]]:
    now = datetime.now(timezone.utc).isoformat()

    # Fetch MFA registration to cross-reference admin MFA status
    try:
        reg_details = client.get_all(
            "/reports/authenticationMethods/userRegistrationDetails"
        )
        reg_by_id: dict[str, dict[str, Any]] = {
            r["id"]: r for r in reg_details if "id" in r
        }
    except Exception:
        reg_by_id = {}

    # Fetch PIM role assignments (time-bound) if available
    # Eligible assignments = PIM; Active permanent = no PIM
    try:
        pim_eligible = client.get_all(
            "/roleManagement/directory/roleEligibilitySchedules",
            params={"$select": "id,principalId,roleDefinitionId,scheduleInfo"},
        )
    except Exception:
        pim_eligible = []

    pim_enrolled_ids: set[str] = {a.get("principalId", "") for a in pim_eligible}

    roles_by_type: dict[str, int] = {}
    global_admin_members: list[dict[str, Any]] = []
    all_admin_ids: set[str] = set()
    synced_admin_count = 0
    total_member_records = 0

    for role_id, role_name in _WATCHED_ROLES.items():
        try:
            members = client.get_all(
                f"/directoryRoles/roleTemplateId={role_id}/members",
                params={
                    "$select": "id,userType,onPremisesSyncEnabled,onPremisesImmutableId"
                },
            )
        except Exception:
            members = []

        # Filter to user objects only (not service principals in roles)
        user_members = [m for m in members if m.get("userType") in ("Member", None, "")]
        roles_by_type[role_name] = len(user_members)
        total_member_records += len(user_members)

        for m in user_members:
            mid = m.get("id", "")
            all_admin_ids.add(mid)
            if _is_synced_account(m):
                synced_admin_count += 1

        if role_id == _GLOBAL_ADMIN_ROLE_ID:
            global_admin_members = user_members

    global_admin_count = len(global_admin_members)
    pim_enrolled_admins = len(all_admin_ids & pim_enrolled_ids)

    # Permanent assignments: admins NOT in PIM eligible set
    permanent_assignments = len(all_admin_ids - pim_enrolled_ids)
    time_bound_assignments = len(all_admin_ids & pim_enrolled_ids)

    # Admin MFA check — for global admins
    admin_no_mfa = sum(1 for m in global_admin_members if not _has_mfa(m, reg_by_id))

    result = PrivilegedRoleResult(
        global_admin_count=global_admin_count,
        pim_enrolled_admins=pim_enrolled_admins,
        synced_account_admins=synced_admin_count,
        permanent_assignments=permanent_assignments,
        time_bound_assignments=time_bound_assignments,
        admin_no_mfa=admin_no_mfa,
        roles_by_type=roles_by_type,
    )

    config_state = {
        "global_admin_count": global_admin_count,
        "pim_enrolled_admins": pim_enrolled_admins,
        "synced_account_admins": synced_admin_count,
        "permanent_assignments": permanent_assignments,
        "admin_no_mfa": admin_no_mfa,
        "total_watched_role_members": total_member_records,
    }
    evidence = EvidenceRef(
        ref_id=f"priv-roles-{tenant_id[:8]}",
        endpoint="/directoryRoles/members",
        record_count=total_member_records,
        config_state=config_state,
        collected_at=now,
        data_hash=_evidence_hash(total_member_records, list(config_state.keys())),
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

    if admin_no_mfa > 0:
        findings.append(
            _f(
                PRIV_001,
                admin_no_mfa,
                f"{admin_no_mfa} Global Administrator account(s) have no MFA registered.",
                f"admin_no_mfa:{admin_no_mfa}",
            )
        )
    if global_admin_count > 5:
        findings.append(
            _f(
                PRIV_002,
                global_admin_count,
                f"{global_admin_count} Global Administrator accounts (recommended maximum: 4).",
                f"ga_count_over_5:{global_admin_count}",
            )
        )
    elif global_admin_count >= 3:
        findings.append(
            _f(
                PRIV_005,
                global_admin_count,
                f"{global_admin_count} Global Administrator accounts (recommended: 2).",
                f"ga_count_3_5:{global_admin_count}",
            )
        )
    if synced_admin_count > 0:
        findings.append(
            _f(
                PRIV_003,
                synced_admin_count,
                f"{synced_admin_count} administrator account(s) are on-premises synced identities.",
                f"synced_admins:{synced_admin_count}",
            )
        )
    if permanent_assignments > 0:
        findings.append(
            _f(
                PRIV_004,
                permanent_assignments,
                f"{permanent_assignments} permanent privileged role assignment(s) without PIM time-bounding.",
                f"permanent:{permanent_assignments}",
            )
        )

    role_summary = ", ".join(f"{k}: {v}" for k, v in roles_by_type.items() if v > 0)
    findings.append(
        _f(
            PRIV_006,
            total_member_records,
            f"Privileged role inventory: {role_summary}. PIM enrolled: {pim_enrolled_admins}.",
            f"inventory:{total_member_records}:{global_admin_count}",
        )
    )

    return result, findings, [evidence]
