from __future__ import annotations

import httpx
import time
import pytest

from services.cgin.key_management.vault_transit import (
    AppRoleAuthenticator,
    TrustRole,
    VaultSession,
    VaultTransitClient,
    VaultTransitError,
)


def response(
    request: httpx.Request, status: int = 200, body: dict | None = None
) -> httpx.Response:
    return httpx.Response(
        status,
        json=body
        or {
            "auth": {
                "client_token": "session-secret",
                "lease_duration": 60,
                "renewable": True,
            }
        },
        request=request,
    )


def roles() -> dict[TrustRole, str]:
    return {
        TrustRole.IDENTITY: "identity-role",
        TrustRole.ACCEPTANCE: "acceptance-role",
        TrustRole.APPROVAL: "approval-role",
    }


def secrets() -> dict[TrustRole, str]:
    return {role: f"secret-{role.value}" for role in TrustRole}


def test_approle_sessions_are_role_specific_and_cached():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return response(request)

    auth = AppRoleAuthenticator(
        "https://vault.example",
        roles(),
        secrets(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    first = auth.session(TrustRole.IDENTITY)
    second = auth.session(TrustRole.IDENTITY)
    assert first is second
    assert calls == ["/v1/auth/approle/login"]


def test_expired_session_reauthenticates_without_exposing_token():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return response(request)

    auth = AppRoleAuthenticator(
        "https://vault.example",
        roles(),
        secrets(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    auth._sessions[TrustRole.APPROVAL] = VaultSession("hidden-token", 1, False, 0, 0)
    session = auth.session(TrustRole.APPROVAL)
    assert session.usable()
    assert calls == ["/v1/auth/approle/login"]
    assert "hidden-token" not in repr(session)


def test_renewable_session_renews_before_reauth():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return response(request)

    auth = AppRoleAuthenticator(
        "https://vault.example",
        roles(),
        secrets(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    auth._sessions[TrustRole.IDENTITY] = VaultSession(
        "old-token", 60, True, time.time(), time.time() + 1
    )
    auth.session(TrustRole.IDENTITY)
    assert calls == ["/v1/auth/token/renew-self"]


def test_authentication_denial_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        return response(request, 403, {"errors": ["denied"]})

    auth = AppRoleAuthenticator(
        "https://vault.example",
        roles(),
        secrets(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(VaultTransitError, match="denied"):
        auth.session(TrustRole.IDENTITY)


def test_operational_client_requires_https_and_session_provider():
    with pytest.raises(ValueError):
        VaultTransitClient("http://vault.example", token="token", operational=True)
    with pytest.raises(ValueError):
        VaultTransitClient("https://vault.example", operational=True)


def test_static_token_requires_explicit_nonproduction_mode(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("FG_CUSTOMER_ZERO_VAULT_ADDR", "https://vault.example")
    monkeypatch.setenv("FG_CUSTOMER_ZERO_VAULT_TOKEN", "dev-token")
    monkeypatch.delenv("FG_CUSTOMER_ZERO_VAULT_AUTH_MODE", raising=False)
    with pytest.raises(ValueError, match="test/development"):
        VaultTransitClient.from_environment()
    monkeypatch.setenv("FG_CUSTOMER_ZERO_VAULT_AUTH_MODE", "static_token")
    monkeypatch.setenv("FG_CUSTOMER_ZERO_ENVIRONMENT", "production")
    with pytest.raises(ValueError):
        VaultTransitClient.from_environment()


def test_namespace_and_address_validation():
    with pytest.raises(ValueError):
        AppRoleAuthenticator(
            "https://vault.example", roles(), secrets(), namespace="team\r\nX: bad"
        )
    with pytest.raises(ValueError):
        AppRoleAuthenticator("https://user:pass@vault.example", roles(), secrets())
    with pytest.raises(ValueError):
        AppRoleAuthenticator("https://vault.example?redirect=1", roles(), secrets())


def test_role_ids_must_be_distinct_and_safe():
    duplicate = roles()
    duplicate[TrustRole.APPROVAL] = duplicate[TrustRole.IDENTITY]
    with pytest.raises(ValueError, match="distinct"):
        AppRoleAuthenticator("https://vault.example", duplicate, secrets())
    unsafe = roles()
    unsafe[TrustRole.IDENTITY] = "../identity"
    with pytest.raises(ValueError, match="role ID"):
        AppRoleAuthenticator("https://vault.example", unsafe, secrets())


def test_vault_client_rejects_redirects_and_invalid_correlation():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": "https://evil.example"}, request=request
        )

    provider = type(
        "Provider",
        (),
        {"session": lambda self, role: VaultSession("safe", 60, True, 0, 9999999999)},
    )()
    client = VaultTransitClient(
        "https://vault.example",
        session_provider=provider,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        operational=True,
    )
    with pytest.raises(VaultTransitError, match="redirect"):
        client.sign("approval-key", b"payload", TrustRole.APPROVAL)
    with pytest.raises(VaultTransitError, match="transport failure"):
        client.sign("approval-key", b"payload", TrustRole.APPROVAL, "bad\nheader")


def test_key_path_validation_rejects_traversal():
    provider = type(
        "Provider",
        (),
        {"session": lambda self, role: VaultSession("safe", 60, True, 0, 9999999999)},
    )()
    client = VaultTransitClient(
        "https://vault.example",
        session_provider=provider,
        http_client=httpx.Client(
            transport=httpx.MockTransport(lambda request: response(request))
        ),
        operational=True,
    )
    with pytest.raises(ValueError, match="key ID"):
        client.sign("../approval", b"payload", TrustRole.APPROVAL)
