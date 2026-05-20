"""MFA Coverage Analyzer — Step 9."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.findings.derivation import derive_finding_id
from services.connectors.msgraph.findings.registry import (
    MFA_001,
    MFA_002,
    MFA_003,
    MFA_004,
    MFA_005,
)
from services.connectors.msgraph.schema.analyzer_outputs import MFACoverageResult
from services.connectors.msgraph.schema.scan_result import EvidenceRef, Finding

_SERVICE_ACCOUNT_PATTERNS = ("svc-", "svc_", "service-", "service_", "#ext#")
_STRONG_MFA_METHODS = frozenset({"fido2", "microsoftAuthenticatorApp", "hardwareOath"})
_WEAK_MFA_METHODS = frozenset({"sms", "voice", "softwareOneTimePasscode"})
_ADMIN_ROLES = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # Privileged Role Administrator
    }
)


def _is_service_account(upn: str) -> bool:
    upn_lower = upn.lower()
    return any(p in upn_lower for p in _SERVICE_ACCOUNT_PATTERNS)


def _evidence_hash(record_count: int, config_keys: list[str]) -> str:
    raw = f"{record_count}:{','.join(sorted(config_keys))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def run(
    client: GraphClient, tenant_id: str
) -> tuple[MFACoverageResult, list[Finding], list[EvidenceRef]]:
    """Run MFA coverage analysis. Returns result, findings, evidence refs."""
    now = datetime.now(timezone.utc).isoformat()

    # Fetch users
    users = client.get_all(
        "/users",
        params={
            "$select": "id,userPrincipalName,accountEnabled,userType,assignedRoles"
        },
    )
    enabled_users = [
        u
        for u in users
        if u.get("accountEnabled")
        and u.get("userType", "Member") != "Guest"
        and not _is_service_account(u.get("userPrincipalName", ""))
    ]

    # Fetch registration details
    reg_details = client.get_all(
        "/reports/authenticationMethods/userRegistrationDetails"
    )
    reg_by_id: dict[str, dict[str, Any]] = {
        r["id"]: r for r in reg_details if "id" in r
    }

    total = len(enabled_users)
    mfa_registered = 0
    strong_mfa = 0
    weak_mfa_only = 0
    no_mfa = 0
    admin_no_mfa = 0

    # Identify admin IDs — cross-reference privileged roles endpoint
    priv_members = client.get_all(
        "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members"
    )
    admin_ids: set[str] = {m.get("id", "") for m in priv_members}

    for user in enabled_users:
        uid = user.get("id", "")
        reg = reg_by_id.get(uid, {})
        methods: list[str] = reg.get("methodsRegistered", [])
        is_mfa = reg.get("isMfaRegistered", False) or reg.get("isMfaCapable", False)

        if not is_mfa and not methods:
            no_mfa += 1
            if uid in admin_ids:
                admin_no_mfa += 1
            continue

        mfa_registered += 1
        has_strong = any(m in _STRONG_MFA_METHODS for m in methods)
        has_weak = any(m in _WEAK_MFA_METHODS for m in methods)

        if has_strong:
            strong_mfa += 1
        elif has_weak:
            weak_mfa_only += 1

    coverage_pct = (mfa_registered / total * 100) if total > 0 else 0.0
    strong_pct = (strong_mfa / total * 100) if total > 0 else 0.0

    result = MFACoverageResult(
        total_enabled_users=total,
        mfa_registered=mfa_registered,
        strong_mfa=strong_mfa,
        weak_mfa_only=weak_mfa_only,
        no_mfa=no_mfa,
        admin_no_mfa=admin_no_mfa,
        coverage_pct=round(coverage_pct, 1),
        strong_coverage_pct=round(strong_pct, 1),
    )

    # Build evidence ref
    config_state = {
        "total_enabled_users": total,
        "mfa_registered": mfa_registered,
        "strong_mfa": strong_mfa,
        "weak_mfa_only": weak_mfa_only,
        "no_mfa": no_mfa,
        "admin_no_mfa": admin_no_mfa,
    }
    evidence = EvidenceRef(
        ref_id=f"mfa-coverage-{tenant_id[:8]}",
        endpoint="/reports/authenticationMethods/userRegistrationDetails",
        record_count=len(reg_details),
        config_state=config_state,
        collected_at=now,
        data_hash=_evidence_hash(len(reg_details), list(config_state.keys())),
    )

    findings: list[Finding] = []

    def _make_finding(
        fdef: Any, count: int, summary: str, evidence_key: str
    ) -> Finding:
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
            _make_finding(
                MFA_001,
                admin_no_mfa,
                f"{admin_no_mfa} Global Administrator account(s) have no MFA registered.",
                f"admin_no_mfa:{admin_no_mfa}",
            )
        )

    if coverage_pct < 80:
        findings.append(
            _make_finding(
                MFA_002,
                no_mfa,
                f"MFA coverage: {coverage_pct:.1f}%. {no_mfa} of {total} users have no MFA.",
                f"coverage_pct_below_80:{int(coverage_pct)}",
            )
        )
    elif coverage_pct < 95:
        findings.append(
            _make_finding(
                MFA_003,
                no_mfa,
                f"MFA coverage: {coverage_pct:.1f}%. {no_mfa} of {total} users have no MFA.",
                f"coverage_pct_80_95:{int(coverage_pct)}",
            )
        )
    else:
        findings.append(
            _make_finding(
                MFA_005,
                total,
                f"MFA coverage: {coverage_pct:.1f}%. Strong MFA: {strong_pct:.1f}%.",
                f"coverage_pct_above_95:{int(coverage_pct)}",
            )
        )

    if weak_mfa_only > 0:
        findings.append(
            _make_finding(
                MFA_004,
                weak_mfa_only,
                f"{weak_mfa_only} user(s) rely solely on SMS or voice call MFA (phishable).",
                f"weak_mfa_only:{weak_mfa_only}",
            )
        )

    return result, findings, [evidence]
