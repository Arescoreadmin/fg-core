"""tests/identity_authority/test_entra_provider.py — Entra ID provider tests."""

from __future__ import annotations

import pytest

from api.identity_authority.providers.entra_provider import EntraOIDCProvider
from api.identity_authority.providers.base import IdentityValidationError


@pytest.fixture
def entra_provider(monkeypatch):
    monkeypatch.setenv("FG_ENTRA_TENANT_ID", "tenant-id-123")
    monkeypatch.setenv("FG_ENTRA_CLIENT_ID", "client-id-abc")
    return EntraOIDCProvider()


def test_is_configured_true(entra_provider):
    assert entra_provider.is_configured() is True


def test_is_configured_false_when_no_env(monkeypatch):
    monkeypatch.delenv("FG_ENTRA_TENANT_ID", raising=False)
    monkeypatch.delenv("FG_ENTRA_CLIENT_ID", raising=False)
    provider = EntraOIDCProvider()
    assert provider.is_configured() is False


def test_provider_name(entra_provider):
    assert entra_provider.provider_name == "entra"


def test_get_jwks_uri(entra_provider):
    uri = entra_provider.get_jwks_uri()
    assert "login.microsoftonline.com" in uri
    assert "tenant-id-123" in uri


def test_get_issuer(entra_provider):
    issuer = entra_provider.get_issuer()
    assert "tenant-id-123" in issuer or "microsoftonline.com" in issuer


def test_validate_token_malformed_raises(entra_provider):
    with pytest.raises(IdentityValidationError) as exc_info:
        entra_provider.validate_token("not.a.valid.jwt")
    assert exc_info.value.provider == "entra"


def test_validate_token_garbage_raises(entra_provider):
    with pytest.raises(IdentityValidationError):
        entra_provider.validate_token("garbage")


def test_validate_token_not_configured_raises(monkeypatch):
    monkeypatch.delenv("FG_ENTRA_TENANT_ID", raising=False)
    monkeypatch.delenv("FG_ENTRA_CLIENT_ID", raising=False)
    provider = EntraOIDCProvider()
    with pytest.raises((IdentityValidationError, Exception)):
        provider.validate_token("any.token.here")


def test_mfa_detection_from_amr(entra_provider):
    """MFA AMR values are correctly classified."""
    mfa_amr_values = {"mfa", "ngcmfa", "fido2", "fido", "rsa"}
    non_mfa_amr = {"pwd", "kmsi", "sso"}

    from api.identity_authority.providers.entra_provider import _ENTRA_MFA_AMR_VALUES

    for v in mfa_amr_values:
        assert v in _ENTRA_MFA_AMR_VALUES, f"{v!r} should be MFA AMR"
    for v in non_mfa_amr:
        assert v not in _ENTRA_MFA_AMR_VALUES, f"{v!r} should not be MFA AMR"


def test_multi_tenant_mode(monkeypatch):
    monkeypatch.setenv("FG_ENTRA_TENANT_ID", "common")
    monkeypatch.setenv("FG_ENTRA_CLIENT_ID", "client-id-abc")
    monkeypatch.setenv("FG_ENTRA_ALLOWED_TENANTS", "tenant-a,tenant-b")
    provider = EntraOIDCProvider()
    assert provider.is_configured() is True
    # In multi-tenant mode, the JWKS URL uses "common"
    uri = provider.get_jwks_uri()
    assert "common" in uri


def test_require_mfa_env(monkeypatch):
    monkeypatch.setenv("FG_ENTRA_TENANT_ID", "tid")
    monkeypatch.setenv("FG_ENTRA_CLIENT_ID", "cid")
    monkeypatch.setenv("FG_ENTRA_REQUIRE_MFA", "1")
    from api.identity_authority.providers.entra_provider import _require_mfa

    assert _require_mfa() is True


def test_require_mfa_default_false(monkeypatch):
    monkeypatch.setenv("FG_ENTRA_TENANT_ID", "tid")
    monkeypatch.setenv("FG_ENTRA_CLIENT_ID", "cid")
    monkeypatch.delenv("FG_ENTRA_REQUIRE_MFA", raising=False)
    from api.identity_authority.providers.entra_provider import _require_mfa

    assert _require_mfa() is False
