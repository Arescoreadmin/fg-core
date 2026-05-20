"""Tests for Conditional Access Analyzer."""

from __future__ import annotations

from .conftest import TENANT_ID, make_client
from services.connectors.msgraph.analyzers import conditional_access


def _policy(
    *,
    state: str,
    include_users=None,
    include_roles=None,
    client_apps=None,
    grant_controls=None,
    session_controls=None,
    sign_in_risk=None,
    exclude_users=None,
) -> dict:
    return {
        "state": state,
        "conditions": {
            "users": {
                "includeUsers": include_users or [],
                "includeRoles": include_roles or [],
                "excludeUsers": exclude_users or [],
                "excludeGroups": [],
            },
            "clientAppTypes": client_apps or [],
            "signInRiskLevels": sign_in_risk or [],
        },
        "grantControls": grant_controls,
        "sessionControls": session_controls,
    }


def test_no_policies_triggers_finding():
    client = make_client({"/identity/conditionalAccessPolicies": []})
    result, findings, _ = conditional_access.run(client, TENANT_ID)
    assert result.total_policies == 0
    assert any("No Conditional Access" in f.evidence_summary for f in findings)


def test_legacy_auth_block_detected():
    policy = _policy(
        state="enabled",
        client_apps=["exchangeActiveSync", "other"],
        grant_controls=None,
    )
    client = make_client({"/identity/conditionalAccessPolicies": [policy]})
    result, findings, _ = conditional_access.run(client, TENANT_ID)
    assert result.has_legacy_auth_block is True


def test_missing_legacy_auth_block_produces_finding():
    policy = _policy(state="enabled", include_users=["All"])
    client = make_client({"/identity/conditionalAccessPolicies": [policy]})
    result, findings, _ = conditional_access.run(client, TENANT_ID)
    assert result.has_legacy_auth_block is False
    assert any("legacy" in f.evidence_summary.lower() for f in findings)


def test_admin_mfa_policy_detected():
    admin_role = "62e90394-69f5-4237-9190-012177145e10"
    policy = _policy(
        state="enabled",
        include_roles=[admin_role],
        grant_controls={"builtInControls": ["mfa"], "operator": "OR"},
    )
    client = make_client({"/identity/conditionalAccessPolicies": [policy]})
    result, _, _ = conditional_access.run(client, TENANT_ID)
    assert result.has_admin_mfa_requirement is True


def test_broad_exclusion_counted():
    policy = _policy(
        state="enabled",
        include_users=["All"],
        exclude_users=[f"u{i}" for i in range(15)],
    )
    client = make_client({"/identity/conditionalAccessPolicies": [policy]})
    result, findings, _ = conditional_access.run(client, TENANT_ID)
    assert result.broad_exclusion_count == 1


def test_summary_finding_always_present():
    client = make_client({"/identity/conditionalAccessPolicies": []})
    _, findings, _ = conditional_access.run(client, TENANT_ID)
    # CA_007 summary is always appended
    assert len(findings) >= 1
