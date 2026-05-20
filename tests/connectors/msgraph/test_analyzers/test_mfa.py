"""Tests for MFA Coverage Analyzer."""

from __future__ import annotations

from .conftest import TENANT_ID, make_client
from services.connectors.msgraph.analyzers import mfa


def _user(
    uid: str,
    *,
    enabled: bool = True,
    upn: str = "user@example.com",
    user_type: str = "Member",
) -> dict:
    return {
        "id": uid,
        "accountEnabled": enabled,
        "userPrincipalName": upn,
        "userType": user_type,
    }


def _reg(uid: str, *, is_mfa: bool, methods: list[str]) -> dict:
    return {
        "id": uid,
        "isMfaRegistered": is_mfa,
        "isMfaCapable": is_mfa,
        "methodsRegistered": methods,
    }


def test_full_mfa_coverage_produces_informational_finding():
    users = [_user(f"u{i}") for i in range(10)]
    regs = [_reg(f"u{i}", is_mfa=True, methods=["fido2"]) for i in range(10)]
    client = make_client(
        {
            "/users": users,
            "/reports/authenticationMethods/userRegistrationDetails": regs,
            "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members": [],
        }
    )
    result, findings, evidence = mfa.run(client, TENANT_ID)
    assert result.coverage_pct == 100.0
    # MFA_005 (above 95%) should be present; MFA_002 should not
    titles = [f.title for f in findings]
    assert any("95" in t or "100" in t or "coverage" in t.lower() for t in titles)


def test_no_mfa_users_triggers_high_finding():
    users = [_user("u1")]
    regs = []  # no registrations
    client = make_client(
        {
            "/users": users,
            "/reports/authenticationMethods/userRegistrationDetails": regs,
            "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members": [],
        }
    )
    result, findings, evidence = mfa.run(client, TENANT_ID)
    assert result.no_mfa == 1
    assert result.coverage_pct == 0.0
    severities = {f.severity for f in findings}
    assert "high" in severities or "critical" in severities


def test_admin_no_mfa_triggers_critical():
    users = [_user("admin1")]
    regs = []
    admin_members = [{"id": "admin1"}]
    client = make_client(
        {
            "/users": users,
            "/reports/authenticationMethods/userRegistrationDetails": regs,
            "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members": admin_members,
        }
    )
    result, findings, evidence = mfa.run(client, TENANT_ID)
    assert result.admin_no_mfa == 1
    assert any(f.severity == "critical" for f in findings)


def test_guest_users_excluded():
    users = [_user("g1", upn="guest#ext#@example.com", user_type="Guest")]
    regs = []
    client = make_client(
        {
            "/users": users,
            "/reports/authenticationMethods/userRegistrationDetails": regs,
            "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members": [],
        }
    )
    result, findings, evidence = mfa.run(client, TENANT_ID)
    assert result.total_enabled_users == 0


def test_evidence_contains_no_upns():
    users = [_user("u1")]
    regs = [_reg("u1", is_mfa=True, methods=["microsoftAuthenticatorApp"])]
    client = make_client(
        {
            "/users": users,
            "/reports/authenticationMethods/userRegistrationDetails": regs,
            "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members": [],
        }
    )
    _, _, evidence_list = mfa.run(client, TENANT_ID)
    for ev in evidence_list:
        config_str = str(ev.config_state)
        assert "user@" not in config_str
        assert "upn" not in config_str.lower()
