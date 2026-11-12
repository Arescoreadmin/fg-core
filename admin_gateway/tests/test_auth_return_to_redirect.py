"""CODEQL-REMEDIATE-001 — open redirect via ``return_to`` (CWE-601, CodeQL #125).

``/auth/login?return_to=...`` stored the caller-supplied value and, after a
successful OIDC login, ``/auth/callback`` redirected to it unvalidated (the
dev-bypass login redirected to it directly). An unauthenticated attacker could
send an operator a genuine login link that lands on an attacker site right
after real SSO. Only same-origin relative paths may be honoured; anything else
falls back to ``/admin/me``.

These tests drive the real routes; only the IdP network exchange is stubbed.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

DEFAULT = "/admin/me"
STATE = "state-codeql-125"

HOSTILE = [
    "https://evil.example/phish",
    "http://evil.example",
    "//evil.example/x",
    "///evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "/\t/evil.example",  # browsers strip tab/newline, yielding //evil.example
    "/\n/evil.example",
    "javascript:alert(1)",
    "http:evil.example",
    "evil.example/x",
    " //evil.example",
]
SAFE = ["/admin/tenants", "/admin/tenants/t-1?tab=keys#audit", "/"]

_BASE_ENV = {
    "FG_ENV": "dev",
    "FG_SESSION_SECRET": "codeql-125-test-session-secret-32",
    "AG_CORE_BASE_URL": "http://core.local",
    "AG_CORE_API_KEY": "test-core-key",
}
_OIDC_ENV = {
    "FG_OIDC_ISSUER": "http://idp.test/realms/FrostGate",
    "FG_OIDC_CLIENT_ID": "fg-service",
    "FG_OIDC_CLIENT_SECRET": "fg-service-ci-secret",
    "FG_OIDC_REDIRECT_URL": "http://localhost:18080/auth/callback",
    "FG_DEV_AUTH_BYPASS": "false",
}
_OIDC_VARS = (
    "FG_OIDC_ISSUER",
    "FG_OIDC_CLIENT_ID",
    "FG_OIDC_CLIENT_SECRET",
    "FG_OIDC_REDIRECT_URL",
)


def _build(monkeypatch, tmp_path, env: dict[str, str], unset=()):
    for k, v in {**_BASE_ENV, **env, "AG_SQLITE_PATH": str(tmp_path / "ag.db")}.items():
        monkeypatch.setenv(k, v)
    for k in unset:
        monkeypatch.delenv(k, raising=False)
    for m in [m for m in sys.modules if m.startswith("admin_gateway")]:
        del sys.modules[m]
    from admin_gateway.auth.config import reset_auth_config
    from admin_gateway.main import build_app

    reset_auth_config()
    return build_app()


@pytest.fixture()
def oidc_client(monkeypatch, tmp_path):
    app = _build(monkeypatch, tmp_path, _OIDC_ENV)
    from admin_gateway.auth.session import Session

    with (
        patch(
            "admin_gateway.auth.oidc.OIDCClient.get_authorization_url",
            new=AsyncMock(
                return_value=("http://idp.test/authorize?state=" + STATE, STATE, "n")
            ),
        ),
        patch(
            "admin_gateway.auth.oidc.OIDCClient.exchange_code",
            new=AsyncMock(return_value={"access_token": "t"}),
        ),
        patch(
            "admin_gateway.auth.oidc.OIDCClient.create_session_from_tokens",
            new=AsyncMock(return_value=Session(user_id="operator-1")),
        ),
        TestClient(app, raise_server_exceptions=False) as client,
    ):
        yield client


def _login_then_callback(client: TestClient, return_to: str) -> str:
    login = client.get(
        "/auth/login", params={"return_to": return_to}, follow_redirects=False
    )
    assert login.status_code == 302
    assert login.headers["location"].startswith("http://idp.test/authorize")
    cb = client.get(
        "/auth/callback", params={"code": "c", "state": STATE}, follow_redirects=False
    )
    assert cb.status_code == 302, cb.text
    assert "set-cookie" in cb.headers  # the login itself still succeeds
    return cb.headers["location"]


@pytest.mark.parametrize("return_to", HOSTILE)
def test_oidc_callback_never_redirects_off_site(oidc_client, return_to):
    assert _login_then_callback(oidc_client, return_to) == DEFAULT


@pytest.mark.parametrize("return_to", HOSTILE)
def test_hostile_return_to_is_not_stored(oidc_client, return_to):
    oidc_client.get(
        "/auth/login", params={"return_to": return_to}, follow_redirects=False
    )
    pending = getattr(oidc_client.app.state, "pending_returns", {})
    assert STATE not in pending


@pytest.mark.parametrize("return_to", SAFE)
def test_oidc_callback_honours_same_origin_paths(oidc_client, return_to):
    assert _login_then_callback(oidc_client, return_to) == return_to


def test_overlong_return_to_falls_back_to_default(oidc_client):
    assert _login_then_callback(oidc_client, "/" + "a" * 4096) == DEFAULT


def test_oidc_callback_without_return_to_uses_default(oidc_client):
    oidc_client.get("/auth/login", follow_redirects=False)
    cb = oidc_client.get(
        "/auth/callback", params={"code": "c", "state": STATE}, follow_redirects=False
    )
    assert cb.headers["location"] == DEFAULT


def test_callback_revalidates_stored_value(oidc_client):
    # Defence in depth: a value that reached the store by any other route is
    # still checked at the redirect sink.
    oidc_client.app.state.pending_returns = {STATE: "https://evil.example"}
    cb = oidc_client.get(
        "/auth/callback", params={"code": "c", "state": STATE}, follow_redirects=False
    )
    assert cb.headers["location"] == DEFAULT


# --- Dev-bypass login (the sink CodeQL #125 reported) -------------------------


@pytest.fixture()
def bypass_client(monkeypatch, tmp_path):
    app = _build(
        monkeypatch, tmp_path, {"FG_DEV_AUTH_BYPASS": "true"}, unset=_OIDC_VARS
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.mark.parametrize("return_to", HOSTILE)
def test_dev_bypass_login_never_redirects_off_site(bypass_client, return_to):
    r = bypass_client.get(
        "/auth/login", params={"return_to": return_to}, follow_redirects=False
    )
    assert r.status_code == 302, r.text
    assert r.headers["location"] == DEFAULT


@pytest.mark.parametrize("return_to", SAFE)
def test_dev_bypass_login_honours_same_origin_paths(bypass_client, return_to):
    r = bypass_client.get(
        "/auth/login", params={"return_to": return_to}, follow_redirects=False
    )
    assert r.status_code == 302, r.text
    assert r.headers["location"] == return_to
