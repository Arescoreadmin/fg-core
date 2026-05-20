"""Conditional Access Analyzer — Step 10."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.findings.derivation import derive_finding_id
from services.connectors.msgraph.findings.registry import (
    CA_001,
    CA_002,
    CA_003,
    CA_004,
    CA_005,
    CA_006,
    CA_007,
)
from services.connectors.msgraph.schema.analyzer_outputs import ConditionalAccessResult
from services.connectors.msgraph.schema.scan_result import EvidenceRef, Finding

_LEGACY_AUTH_CLIENT_APPS = frozenset(
    {
        "exchangeActiveSync",
        "other",
    }
)
_ADMIN_ROLE_IDS = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # Privileged Role Administrator
    }
)


def _evidence_hash(record_count: int, config_keys: list[str]) -> str:
    raw = f"{record_count}:{','.join(sorted(config_keys))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _policy_blocks_legacy_auth(policy: dict[str, Any]) -> bool:
    conditions = policy.get("conditions", {})
    client_apps = conditions.get("clientAppTypes", [])
    grant = policy.get("grantControls") or {}
    # Block policy has no grant controls or explicit block
    is_block = grant.get("operator") is None or grant.get("builtInControls", []) == []
    has_legacy_apps = any(a in _LEGACY_AUTH_CLIENT_APPS for a in client_apps)
    return has_legacy_apps and is_block


def _policy_requires_mfa_for_admins(policy: dict[str, Any]) -> bool:
    conditions = policy.get("conditions", {})
    users = conditions.get("users", {})
    included_roles = users.get("includeRoles", [])
    all_users = "All" in users.get("includeUsers", [])
    covers_admins = all_users or any(r in _ADMIN_ROLE_IDS for r in included_roles)
    grant = policy.get("grantControls") or {}
    requires_mfa = "mfa" in (grant.get("builtInControls") or [])
    return covers_admins and requires_mfa


def _exclusion_count(policy: dict[str, Any]) -> int:
    users = policy.get("conditions", {}).get("users", {})
    return len(users.get("excludeUsers", [])) + len(users.get("excludeGroups", []))


def run(
    client: GraphClient, tenant_id: str
) -> tuple[ConditionalAccessResult, list[Finding], list[EvidenceRef]]:
    now = datetime.now(timezone.utc).isoformat()

    policies = client.get_all("/identity/conditionalAccessPolicies")

    enabled = [p for p in policies if p.get("state") == "enabled"]
    disabled = [p for p in policies if p.get("state") == "disabled"]
    report_only = [
        p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"
    ]

    has_legacy_block = any(_policy_blocks_legacy_auth(p) for p in enabled)
    has_admin_mfa = any(_policy_requires_mfa_for_admins(p) for p in enabled)
    has_compliant_device = any(
        "compliantDevice" in (p.get("grantControls") or {}).get("builtInControls", [])
        for p in enabled
    )
    has_signin_risk = any(
        p.get("conditions", {}).get("signInRiskLevels") for p in enabled
    )
    has_user_risk = any(p.get("conditions", {}).get("userRiskLevels") for p in enabled)

    broad_excl_count = sum(1 for p in enabled if _exclusion_count(p) > 10)
    all_users_covered = any(
        "All" in (p.get("conditions", {}).get("users", {}).get("includeUsers", []))
        for p in enabled
    )

    result = ConditionalAccessResult(
        total_policies=len(policies),
        enabled_policies=len(enabled),
        disabled_policies=len(disabled),
        report_only_policies=len(report_only),
        has_legacy_auth_block=has_legacy_block,
        has_admin_mfa_requirement=has_admin_mfa,
        has_compliant_device_requirement=has_compliant_device,
        has_signin_risk_policy=has_signin_risk,
        has_user_risk_policy=has_user_risk,
        broad_exclusion_count=broad_excl_count,
        all_users_covered=all_users_covered,
    )

    config_state = {
        "total_policies": len(policies),
        "enabled_policies": len(enabled),
        "has_legacy_auth_block": has_legacy_block,
        "has_admin_mfa_requirement": has_admin_mfa,
        "has_compliant_device_requirement": has_compliant_device,
        "has_signin_risk_policy": has_signin_risk,
        "broad_exclusion_count": broad_excl_count,
    }
    evidence = EvidenceRef(
        ref_id=f"ca-policies-{tenant_id[:8]}",
        endpoint="/identity/conditionalAccessPolicies",
        record_count=len(policies),
        config_state=config_state,
        collected_at=now,
        data_hash=_evidence_hash(len(policies), list(config_state.keys())),
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

    if len(enabled) == 0:
        findings.append(
            _f(
                CA_003,
                0,
                "No Conditional Access policies are enabled.",
                "no_ca_policies",
            )
        )
    else:
        if not has_legacy_block:
            findings.append(
                _f(
                    CA_001,
                    0,
                    "No CA policy blocks legacy authentication protocols.",
                    "no_legacy_auth_block",
                )
            )
        if not has_admin_mfa:
            findings.append(
                _f(
                    CA_002,
                    0,
                    "No CA policy requires MFA for privileged roles.",
                    "no_admin_mfa_policy",
                )
            )
        if broad_excl_count > 0:
            findings.append(
                _f(
                    CA_004,
                    broad_excl_count,
                    f"{broad_excl_count} policy/policies have more than 10 user/group exclusions.",
                    f"broad_exclusions:{broad_excl_count}",
                )
            )
        if not has_compliant_device:
            findings.append(
                _f(
                    CA_005,
                    0,
                    "No CA policy requires compliant device for corporate data access.",
                    "no_compliant_device",
                )
            )
        if not has_signin_risk:
            findings.append(
                _f(
                    CA_006,
                    0,
                    "No sign-in risk policy configured (requires AAD P2).",
                    "no_signin_risk_policy",
                )
            )

    findings.append(
        _f(
            CA_007,
            len(policies),
            f"CA policies: {len(policies)} total ({len(enabled)} enabled, {len(disabled)} disabled, {len(report_only)} report-only).",
            f"policy_summary:{len(policies)}:{len(enabled)}",
        )
    )

    return result, findings, [evidence]
