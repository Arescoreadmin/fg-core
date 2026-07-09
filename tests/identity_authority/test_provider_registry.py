"""tests/identity_authority/test_provider_registry.py — Provider registry tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityValidationError,
)
from api.identity_authority.providers.registry import IdentityProviderRegistry


def _make_provider(name: str, *, configured: bool = True, raises=None):
    from api.identity_authority.models import IdentityProvider

    provider = MagicMock()
    provider.provider_name = name
    provider.is_configured.return_value = configured
    if raises is not None:
        provider.validate_token.side_effect = raises
    else:
        identity = MagicMock()
        identity.provider = IdentityProvider(
            name=name, issuer="https://example.com/", subject="sub"
        )
        provider.validate_token.return_value = identity
    return provider


def test_resolve_jwt_tries_each_provider_in_order(monkeypatch):
    p1 = _make_provider(
        "auth0", raises=IdentityValidationError("bad", "INVALID", "auth0")
    )
    p2 = _make_provider("entra")

    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [p1, p2]

    result = registry.resolve_jwt("token")
    p1.validate_token.assert_called_once_with("token")
    p2.validate_token.assert_called_once_with("token")
    assert result.provider.name == "entra"


def test_resolve_jwt_stops_on_provider_error():
    p1 = _make_provider("auth0", raises=IdentityProviderError("down", "auth0"))
    p2 = _make_provider("entra")

    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [p1, p2]

    with pytest.raises(IdentityProviderError):
        registry.resolve_jwt("token")
    p2.validate_token.assert_not_called()


def test_resolve_jwt_all_rejected_raises():
    p1 = _make_provider(
        "auth0", raises=IdentityValidationError("bad", "INVALID", "auth0")
    )
    p2 = _make_provider(
        "entra", raises=IdentityValidationError("bad", "INVALID", "entra")
    )

    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [p1, p2]

    with pytest.raises(IdentityValidationError) as exc_info:
        registry.resolve_jwt("token")
    assert exc_info.value.code == "ALL_PROVIDERS_REJECTED"


def test_resolve_jwt_no_providers_raises():
    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = []

    with pytest.raises(IdentityValidationError) as exc_info:
        registry.resolve_jwt("token")
    assert exc_info.value.code == "NO_PROVIDER"


def test_configured_providers_returns_names():
    p1 = _make_provider("auth0")
    p2 = _make_provider("entra")

    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [p1, p2]

    assert registry.configured_providers() == ["auth0", "entra"]


def test_get_provider_by_name():
    p1 = _make_provider("auth0")
    p2 = _make_provider("entra")

    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [p1, p2]

    assert registry.get_provider("entra") is p2
    assert registry.get_provider("okta") is None


def test_len_returns_provider_count():
    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [_make_provider("auth0"), _make_provider("entra")]
    assert len(registry) == 2


def test_build_chain_skips_unconfigured(monkeypatch):
    monkeypatch.delenv("FG_AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("FG_ENTRA_TENANT_ID", raising=False)
    monkeypatch.delenv("FG_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("FG_OIDC_ISSUER", raising=False)

    registry = IdentityProviderRegistry()
    assert len(registry) == 0


def test_provider_error_skipped_when_issuer_does_not_match():
    """An IdentityProviderError from Auth0 should not block an Entra token."""
    from api.identity_authority.providers.registry import IdentityProviderRegistry

    auth0_provider = _make_provider(
        "auth0",
        raises=IdentityProviderError("JWKS fetch failed", "auth0"),
    )
    auth0_provider.get_issuer.return_value = "https://my-tenant.auth0.com/"

    entra_provider = _make_provider("entra")
    entra_provider.get_issuer.return_value = (
        "https://login.microsoftonline.com/tid/v2.0"
    )

    # Fake an Entra token (iss = login.microsoftonline.com)
    import base64
    import json

    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"iss": "https://login.microsoftonline.com/abc-123/v2.0"}
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    entra_token = f"header.{payload}.sig"

    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [auth0_provider, entra_provider]

    result = registry.resolve_jwt(entra_token)
    entra_provider.validate_token.assert_called_once_with(entra_token)
    assert result.provider.name == "entra"


def test_provider_error_propagated_when_issuer_matches():
    """An IdentityProviderError propagates when the token's iss matches that provider."""
    from api.identity_authority.providers.registry import IdentityProviderRegistry

    auth0_provider = _make_provider(
        "auth0",
        raises=IdentityProviderError("JWKS fetch failed", "auth0"),
    )
    auth0_provider.get_issuer.return_value = "https://my-tenant.auth0.com/"

    import base64
    import json

    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"iss": "https://my-tenant.auth0.com/"}).encode()
        )
        .decode()
        .rstrip("=")
    )
    auth0_token = f"header.{payload}.sig"

    registry = IdentityProviderRegistry.__new__(IdentityProviderRegistry)
    registry._providers = [auth0_provider]

    with pytest.raises(IdentityProviderError):
        registry.resolve_jwt(auth0_token)


def test_build_chain_includes_auth0_when_configured(monkeypatch):
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    monkeypatch.delenv("FG_ENTRA_TENANT_ID", raising=False)
    monkeypatch.delenv("FG_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("FG_OIDC_ISSUER", raising=False)

    registry = IdentityProviderRegistry()
    assert "auth0" in registry.configured_providers()
