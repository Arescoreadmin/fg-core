"""Auth0 adapter unit tests.

Tests cover: URL building, claim normalization, provisioning operations,
configuration validation, and secret-safety invariants. All Auth0 Management
API and JWKS calls are mocked — no network access.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from admin_gateway.identity.auth0_adapter import (
    Auth0Adapter,
    Auth0AdapterError,
    PROVIDER_NAME,
)
from admin_gateway.identity.auth0_config import (
    Auth0Config,
    Auth0ConfigError,
    clear_auth0_config_cache,
    get_auth0_config,
)
from admin_gateway.identity.auth0_management import (
    Auth0ManagementClient,
    Auth0ManagementError,
)
from admin_gateway.identity.auth0_models import Auth0ConnectionResult, Auth0OrgResult
from admin_gateway.identity.provider_adapter import AuthInstructions

DOMAIN = "example.us.auth0.com"
CLIENT_ID = "test-client-id"
ISSUER = f"https://{DOMAIN}/"
CALLBACK = "https://app.example.com/identity/callback"

AUTH0_ENV = {
    "AUTH0_DOMAIN": DOMAIN,
    "AUTH0_AUDIENCE": "https://api.example.com/",
    "AUTH0_CLIENT_ID": CLIENT_ID,
    "AUTH0_CLIENT_SECRET": "test-client-secret",
    "AUTH0_MGMT_AUDIENCE": f"https://{DOMAIN}/api/v2/",
    "AUTH0_MGMT_CLIENT_ID": "mgmt-client-id",
    "AUTH0_MGMT_CLIENT_SECRET": "mgmt-client-secret",
    "AUTH0_CALLBACK_URL": CALLBACK,
    "AUTH0_LOGOUT_RETURN_URL": "https://app.example.com/logout",
    "AUTH0_ORG_LOGIN": "true",
}


def _make_config(**overrides: str) -> Auth0Config:
    env = {**AUTH0_ENV, **overrides}
    return Auth0Config(
        domain=env["AUTH0_DOMAIN"],
        audience=env["AUTH0_AUDIENCE"],
        client_id=env["AUTH0_CLIENT_ID"],
        client_secret=env["AUTH0_CLIENT_SECRET"],
        mgmt_audience=env["AUTH0_MGMT_AUDIENCE"],
        mgmt_client_id=env["AUTH0_MGMT_CLIENT_ID"],
        mgmt_client_secret=env["AUTH0_MGMT_CLIENT_SECRET"],
        callback_url=env["AUTH0_CALLBACK_URL"],
        logout_return_url=env["AUTH0_LOGOUT_RETURN_URL"],
        org_login_required=True,
        allowed_connection_strategies=(),
    )


def _make_adapter(mgmt: Any = None) -> Auth0Adapter:
    config = _make_config()
    mock_mgmt = mgmt or MagicMock(spec=Auth0ManagementClient)
    return Auth0Adapter(config=config, management_client=mock_mgmt)


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------


def test_config_raises_on_missing_required_env(monkeypatch):
    for name in [
        "AUTH0_DOMAIN",
        "AUTH0_AUDIENCE",
        "AUTH0_CLIENT_ID",
        "AUTH0_CLIENT_SECRET",
        "AUTH0_MGMT_AUDIENCE",
        "AUTH0_MGMT_CLIENT_ID",
        "AUTH0_MGMT_CLIENT_SECRET",
        "AUTH0_CALLBACK_URL",
        "AUTH0_LOGOUT_RETURN_URL",
    ]:
        monkeypatch.delenv(name, raising=False)
    clear_auth0_config_cache()
    with pytest.raises(Auth0ConfigError) as exc_info:
        get_auth0_config()
    assert "AUTH0_CONFIG_MISSING" in exc_info.value.code
    clear_auth0_config_cache()


def test_config_loads_from_env(monkeypatch):
    for k, v in AUTH0_ENV.items():
        monkeypatch.setenv(k, v)
    clear_auth0_config_cache()
    cfg = get_auth0_config()
    assert cfg.domain == DOMAIN
    assert cfg.issuer == ISSUER
    assert cfg.client_id == CLIENT_ID
    clear_auth0_config_cache()


def test_adapter_fails_closed_when_config_missing(monkeypatch):
    for name in [
        "AUTH0_DOMAIN",
        "AUTH0_AUDIENCE",
        "AUTH0_CLIENT_ID",
        "AUTH0_CLIENT_SECRET",
        "AUTH0_MGMT_AUDIENCE",
        "AUTH0_MGMT_CLIENT_ID",
        "AUTH0_MGMT_CLIENT_SECRET",
        "AUTH0_CALLBACK_URL",
        "AUTH0_LOGOUT_RETURN_URL",
    ]:
        monkeypatch.delenv(name, raising=False)
    clear_auth0_config_cache()
    with pytest.raises(Auth0AdapterError):
        Auth0Adapter()
    clear_auth0_config_cache()


# ------------------------------------------------------------------
# URL building — org-aware SSO login
# ------------------------------------------------------------------


def test_build_org_aware_login_url_includes_org_and_connection():
    adapter = _make_adapter()
    url = adapter.build_org_aware_login_url(
        state="test-state",
        connection_id="conn-123",
        organization_id="org-456",
    )
    assert "organization=org-456" in url
    assert "connection=conn-123" in url
    assert "state=test-state" in url
    assert f"https://{DOMAIN}/authorize" in url
    assert f"client_id={CLIENT_ID}" in url


def test_build_org_aware_login_url_omits_org_when_none():
    adapter = _make_adapter()
    url = adapter.build_org_aware_login_url(
        state="s", connection_id=None, organization_id=None
    )
    assert "organization" not in url
    assert "connection" not in url


def test_build_org_aware_login_url_does_not_include_raw_invite_token():
    adapter = _make_adapter()
    url = adapter.build_org_aware_login_url(
        state="state",
        connection_id="c",
        organization_id="o",
    )
    # raw invite tokens must not appear in the URL
    assert "invite" not in url.lower() or "invite_token" not in url


# ------------------------------------------------------------------
# URL building — managed signup/login
# ------------------------------------------------------------------


def test_build_managed_signup_url_includes_screen_hint():
    adapter = _make_adapter()
    url = adapter.build_managed_signup_or_login_url(state="s", screen_hint="signup")
    assert "screen_hint=signup" in url
    assert f"client_id={CLIENT_ID}" in url


def test_build_managed_login_url_no_enterprise_connection():
    adapter = _make_adapter()
    url = adapter.build_managed_signup_or_login_url(state="s", connection_id=None)
    assert "connection" not in url


def test_build_managed_login_with_org():
    adapter = _make_adapter()
    url = adapter.build_managed_signup_or_login_url(
        state="s", organization_id="org-789"
    )
    assert "organization=org-789" in url


# ------------------------------------------------------------------
# start_invitation_auth protocol dispatch
# ------------------------------------------------------------------


def test_start_invitation_auth_returns_auth_instructions():
    adapter = _make_adapter()
    result = adapter.start_invitation_auth(
        provider=PROVIDER_NAME,
        state="state-abc",
        connection_id="conn-1",
        organization_id="org-1",
    )
    assert isinstance(result, AuthInstructions)
    assert result.provider == PROVIDER_NAME
    assert result.adapter == "auth0"
    assert result.connection_id == "conn-1"
    assert result.organization_id == "org-1"
    assert "org-1" in result.auth_start_url


def test_start_invitation_auth_rejects_wrong_provider():
    adapter = _make_adapter()
    with pytest.raises(Auth0AdapterError, match="PROVIDER_NOT_SUPPORTED"):
        adapter.start_invitation_auth(
            provider="keycloak", state="s", connection_id=None, organization_id=None
        )


# ------------------------------------------------------------------
# Claim normalization
# ------------------------------------------------------------------


def test_normalize_identity_claims_normalizes_email():
    raw = {
        "sub": "auth0|abc123",
        "email": "  User@EXAMPLE.COM  ",
        "email_verified": True,
        "iss": ISSUER,
        "org_id": "org-x",
    }
    claims = Auth0Adapter.normalize_identity_claims(raw)
    assert claims.email == "user@example.com"
    assert claims.subject == "auth0|abc123"
    assert claims.email_verified is True
    assert claims.organization_id == "org-x"
    assert claims.provider == PROVIDER_NAME


def test_normalize_identity_claims_handles_missing_org():
    raw = {"sub": "s", "email": "a@b.com", "email_verified": True, "iss": ISSUER}
    claims = Auth0Adapter.normalize_identity_claims(raw)
    assert claims.organization_id is None


# ------------------------------------------------------------------
# validate_callback — claim enforcement
# ------------------------------------------------------------------


def _make_valid_claims(
    *,
    sub: str = "auth0|valid",
    email: str = "user@example.com",
    email_verified: bool = True,
    iss: str = ISSUER,
    org_id: str | None = "org-1",
) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "sub": sub,
        "email": email,
        "email_verified": email_verified,
        "iss": iss,
    }
    if org_id is not None:
        claims["org_id"] = org_id
    return claims


def _adapter_with_token_mock(claims: dict[str, Any]) -> Auth0Adapter:
    adapter = _make_adapter()
    adapter._verify_id_token = MagicMock(return_value=claims)  # type: ignore[method-assign]
    return adapter


def test_validate_callback_returns_authenticated_identity():
    adapter = _adapter_with_token_mock(_make_valid_claims())
    identity = adapter.validate_callback({"id_token": "tok", "connection": "conn-1"})
    assert identity.provider == PROVIDER_NAME
    assert identity.email == "user@example.com"
    assert identity.email_verified is True
    assert identity.subject == "auth0|valid"
    assert identity.organization_id == "org-1"
    assert identity.connection_id == "conn-1"


def test_validate_callback_rejects_unverified_email():
    adapter = _adapter_with_token_mock(_make_valid_claims(email_verified=False))
    with pytest.raises(Auth0AdapterError, match="EMAIL_NOT_VERIFIED"):
        adapter.validate_callback({"id_token": "tok"})


def test_validate_callback_rejects_missing_subject():
    adapter = _adapter_with_token_mock(_make_valid_claims(sub=""))
    with pytest.raises(Auth0AdapterError, match="MISSING_SUBJECT"):
        adapter.validate_callback({"id_token": "tok"})


def test_validate_callback_rejects_missing_email():
    adapter = _adapter_with_token_mock(_make_valid_claims(email=""))
    with pytest.raises(Auth0AdapterError, match="MISSING_EMAIL"):
        adapter.validate_callback({"id_token": "tok"})


def test_validate_callback_rejects_wrong_issuer():
    adapter = _adapter_with_token_mock(
        _make_valid_claims(iss="https://evil.example.com/")
    )
    with pytest.raises(Auth0AdapterError, match="ISSUER_MISMATCH"):
        adapter.validate_callback({"id_token": "tok"})


def test_validate_callback_rejects_missing_id_token():
    adapter = _make_adapter()
    with pytest.raises(Auth0AdapterError, match="MISSING_ID_TOKEN"):
        adapter.validate_callback({})


def test_validate_callback_org_id_comes_from_claims_not_payload():
    """org_id from callback_payload body must not override claim."""
    claims = _make_valid_claims(org_id="org-legitimate")
    adapter = _adapter_with_token_mock(claims)
    # attacker tries to inject different org via payload body
    identity = adapter.validate_callback({"id_token": "tok", "org_id": "org-ATTACKER"})
    assert identity.organization_id == "org-legitimate"


# ------------------------------------------------------------------
# Provisioning operations
# ------------------------------------------------------------------


def test_ensure_organization_creates_new_org():
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.create_organization.return_value = Auth0OrgResult(
        organization_id="org-new", organization_name="acme", was_created=True
    )
    adapter = _make_adapter(mgmt)
    result = adapter.ensure_organization(
        tenant_id="t1", org_name="acme", display_name="Acme Co"
    )
    assert result.organization_id == "org-new"
    assert result.was_created is True
    mgmt.create_organization.assert_called_once()


def test_ensure_organization_associates_existing_org():
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.associate_organization.return_value = Auth0OrgResult(
        organization_id="org-existing", organization_name="acme", was_created=False
    )
    adapter = _make_adapter(mgmt)
    result = adapter.ensure_organization(
        tenant_id="t1",
        org_name="acme",
        display_name="Acme",
        existing_org_id="org-existing",
    )
    assert result.organization_id == "org-existing"
    assert result.was_created is False
    mgmt.associate_organization.assert_called_once_with("org-existing")


def test_ensure_organization_raises_adapter_error_on_mgmt_failure():
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.create_organization.side_effect = Auth0ManagementError("ORG_CREATE_FAILED")
    adapter = _make_adapter(mgmt)
    with pytest.raises(Auth0AdapterError, match="ORG_PROVISION_FAILED"):
        adapter.ensure_organization(
            tenant_id="t1", org_name="acme", display_name="Acme"
        )


def test_ensure_connection_attached_success():
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.attach_connection_to_org.return_value = Auth0ConnectionResult(
        connection_id="conn-1",
        connection_name="saml",
        strategy="samlp",
        was_attached=True,
    )
    adapter = _make_adapter(mgmt)
    result = adapter.ensure_connection_attached(org_id="org-1", connection_id="conn-1")
    assert result.connection_id == "conn-1"
    assert result.was_attached is True


def test_ensure_connection_attached_raises_on_mgmt_failure():
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.attach_connection_to_org.side_effect = Auth0ManagementError(
        "CONNECTION_NOT_FOUND"
    )
    adapter = _make_adapter(mgmt)
    with pytest.raises(Auth0AdapterError, match="CONNECTION_ATTACH_FAILED"):
        adapter.ensure_connection_attached(org_id="org-1", connection_id="conn-bad")


def test_provision_tenant_identity_success():
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.create_organization.return_value = Auth0OrgResult(
        organization_id="org-1", organization_name="acme", was_created=True
    )
    mgmt.attach_connection_to_org.return_value = Auth0ConnectionResult(
        connection_id="conn-1",
        connection_name="saml",
        strategy="samlp",
        was_attached=True,
    )
    adapter = _make_adapter(mgmt)
    result = adapter.provision_tenant_identity(
        tenant_id="t1",
        org_name="acme",
        display_name="Acme",
        connection_id="conn-1",
    )
    assert result.status == "success"
    assert result.organization_id == "org-1"
    assert result.connection_id == "conn-1"
    assert result.error_code is None


def test_provision_tenant_identity_org_failure_leaves_membership_pending():
    """Org creation failure must return status=failed, never partial activation."""
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.create_organization.side_effect = Auth0ManagementError("ORG_CREATE_FAILED")
    adapter = _make_adapter(mgmt)
    result = adapter.provision_tenant_identity(
        tenant_id="t1", org_name="x", display_name="X", connection_id="c"
    )
    assert result.status == "failed"
    assert result.organization_id is None
    assert result.connection_id is None
    assert result.error_code is not None


def test_provision_tenant_identity_connection_failure_is_partial():
    """Connection attach failure returns partial — org was created but SSO is not ready."""
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.create_organization.return_value = Auth0OrgResult(
        organization_id="org-1", organization_name="x", was_created=True
    )
    mgmt.attach_connection_to_org.side_effect = Auth0ManagementError(
        "CONNECTION_NOT_FOUND"
    )
    adapter = _make_adapter(mgmt)
    result = adapter.provision_tenant_identity(
        tenant_id="t1", org_name="x", display_name="X", connection_id="c"
    )
    assert result.status == "partial"
    assert result.organization_id == "org-1"
    assert result.connection_id is None


def test_provision_retry_is_idempotent_via_associate():
    """Second provision using existing_org_id goes through associate, not create."""
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.associate_organization.return_value = Auth0OrgResult(
        organization_id="org-1", organization_name="x", was_created=False
    )
    mgmt.attach_connection_to_org.return_value = Auth0ConnectionResult(
        connection_id="conn-1",
        connection_name="saml",
        strategy="samlp",
        was_attached=False,
    )
    adapter = _make_adapter(mgmt)
    result = adapter.provision_tenant_identity(
        tenant_id="t1",
        org_name="x",
        display_name="X",
        connection_id="conn-1",
        existing_org_id="org-1",
    )
    assert result.status == "success"
    mgmt.create_organization.assert_not_called()
    mgmt.associate_organization.assert_called_once_with("org-1")


# ------------------------------------------------------------------
# Secret-safety assertions
# ------------------------------------------------------------------


def test_adapter_does_not_expose_client_secret():
    adapter = _make_adapter()
    # Config must never return client_secret through public repr/str
    public = repr(adapter)
    assert "test-client-secret" not in public
    assert "mgmt-client-secret" not in public


def test_management_client_hash_subject_is_non_reversible():
    h = Auth0ManagementClient.hash_subject("auth0|secret-subject")
    assert "secret-subject" not in h
    assert len(h) == 16
