"""Task 6.2 — End-to-end auth flow: HTTP-level validation.

Proves all DoD requirements at the HTTP endpoint layer:

1. Valid Keycloak-issued token accepted on POST /auth/token-exchange → 200 + session cookie
2. Session cookie issued by token exchange accepted on protected endpoints → 200
3. Request without Bearer token to /auth/token-exchange → 401
4. Token exchange with invalid/tampered token → 401
5. Token exchange with wrong issuer → 401
6. Token exchange with wrong audience → 401
7. Token exchange with expired token → 401
8. Valid token but session has insufficient scope → 403 on scope-guarded endpoint
9. Valid token but session is bound to wrong tenant → 403 on tenant-guarded endpoint
10. OIDC not configured → 503 (fail-closed, no silent fallback)

JWT cryptographic validation (sig/issuer/aud/expiry) is already proven at the unit
level in test_token_exchange_security.py.  This file proves the HTTP layer correctly
propagates those rejections and enforces scope/tenant isolation end-to-end.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

ISSUER = "http://fg-idp.test:8080/realms/FrostGate"
CLIENT_ID = "fg-service"
SESSION_SECRET = "task62-test-session-secret-32c"

_OIDC_ENV: dict[str, str] = {
    "FG_ENV": "dev",
    "FG_SESSION_SECRET": SESSION_SECRET,
    "FG_OIDC_ISSUER": ISSUER,
    "FG_OIDC_CLIENT_ID": CLIENT_ID,
    "FG_OIDC_CLIENT_SECRET": "fg-service-ci-secret",
    "FG_OIDC_REDIRECT_URL": "http://localhost:18080/auth/callback",
    "FG_DEV_AUTH_BYPASS": "false",
    "AG_CORE_BASE_URL": "http://core.local",
    "AG_CORE_API_KEY": "test-core-key",
}


# ---------------------------------------------------------------------------
# RSA helpers
# ---------------------------------------------------------------------------


def _make_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk_for_key(private_key: rsa.RSAPrivateKey, kid: str = "k62") -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = kid
    jwk["use"] = "sig"
    return jwk


def _sign_token(
    private_key: rsa.RSAPrivateKey,
    claims: dict[str, Any],
    *,
    kid: str = "k62",
    alg: str = "RS256",
) -> str:
    return str(
        jwt.encode(
            claims,
            private_key,
            algorithm=alg,
            headers={"kid": kid, "alg": alg},
        )
    )


def _valid_claims(
    *,
    iss: str = ISSUER,
    aud: str = CLIENT_ID,
    sub: str = "svc-task62",
    fg_scopes: list[str] | None = None,
    tenant_id: str | None = "tenant-alpha",
    allowed_tenants: list[str] | None = None,
    offset: int = 300,
) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "exp": now + offset,
        "iat": now,
    }
    if fg_scopes is not None:
        claims["fg_scopes"] = fg_scopes
    if tenant_id is not None:
        claims["tenant_id"] = tenant_id
    if allowed_tenants is not None:
        claims["allowed_tenants"] = allowed_tenants
    return claims


# ---------------------------------------------------------------------------
# App fixture: OIDC configured, no dev bypass
# ---------------------------------------------------------------------------


@pytest.fixture()
def oidc_app(tmp_path, monkeypatch):
    """App with OIDC configured and dev bypass disabled."""
    db_path = tmp_path / "task62.db"
    env = {**_OIDC_ENV, "AG_SQLITE_PATH": str(db_path)}
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    # Ensure stale module cache is cleared
    mods = [m for m in sys.modules if m.startswith("admin_gateway")]
    for m in mods:
        del sys.modules[m]

    from admin_gateway.auth.config import reset_auth_config
    from admin_gateway.main import build_app
    from admin_gateway.routers import admin as admin_router

    reset_auth_config()
    app = build_app()

    # Mock core proxy (no real core service in tests)
    async def _mock_proxy(
        request, method, path, params=None, json_body=None, session=None, tenant_id=None
    ):
        return {}

    monkeypatch.setattr(admin_router, "_proxy_to_core", _mock_proxy, raising=False)
    return app


@pytest.fixture()
def oidc_client(oidc_app):
    with TestClient(oidc_app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Helper: mock verify_access_token to return controlled claims
# ---------------------------------------------------------------------------


def _patch_verify(claims: dict[str, Any]):
    """Return a context manager that stubs verify_access_token to return claims."""
    return patch(
        "admin_gateway.auth.oidc.OIDCClient.verify_access_token",
        new=AsyncMock(return_value=claims),
    )


def _patch_verify_raises(status_code: int = 401, detail: str = "Invalid token"):
    """Return a context manager that stubs verify_access_token to raise HTTPException."""
    return patch(
        "admin_gateway.auth.oidc.OIDCClient.verify_access_token",
        new=AsyncMock(
            side_effect=HTTPException(status_code=status_code, detail=detail)
        ),
    )


# ---------------------------------------------------------------------------
# 1 + 2: Happy path — valid token → session cookie → protected endpoint
# ---------------------------------------------------------------------------


def test_token_exchange_valid_token_returns_200_and_cookie(oidc_client):
    """Valid token → 200 JSON body with session_id + Set-Cookie header."""
    claims = _valid_claims(fg_scopes=["console:admin"])

    with _patch_verify(claims):
        resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer valid.token.here"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "session_id" in body
    assert "user_id" in body
    assert body["user_id"] == "svc-task62"
    assert "fg_admin_session" in resp.cookies


def test_session_from_token_exchange_reaches_protected_endpoint(oidc_client):
    """Session cookie from token exchange allows access to a protected endpoint."""
    claims = _valid_claims(fg_scopes=["console:admin"])

    with _patch_verify(claims):
        exchange_resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer valid.token.here"},
        )

    assert exchange_resp.status_code == 200
    session_cookie = exchange_resp.cookies.get("fg_admin_session")
    assert session_cookie is not None, "No session cookie in token-exchange response"

    # Use session cookie on a scope-protected endpoint
    resp = oidc_client.get(
        "/api/v1/tenants",
        cookies={"fg_admin_session": session_cookie},
    )
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# 3: Missing Bearer header → 401
# ---------------------------------------------------------------------------


def test_token_exchange_no_bearer_returns_401(oidc_client):
    """POST /auth/token-exchange without Authorization header → 401."""
    resp = oidc_client.post("/auth/token-exchange")
    assert resp.status_code == 401
    assert "Bearer" in resp.json().get("detail", "")


def test_token_exchange_non_bearer_scheme_returns_401(oidc_client):
    """POST /auth/token-exchange with Basic auth (wrong scheme) → 401."""
    resp = oidc_client.post(
        "/auth/token-exchange",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4–7: JWT validation failures at HTTP level (invalid sig, issuer, aud, expiry)
# ---------------------------------------------------------------------------


def test_token_exchange_tampered_token_returns_401(oidc_client):
    """Token with invalid signature must be rejected (401) at the exchange endpoint."""
    with _patch_verify_raises(401, "Invalid token"):
        resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer tampered.jwt.token"},
        )
    assert resp.status_code == 401


def test_token_exchange_wrong_issuer_returns_401(oidc_client):
    """Token with mismatched issuer must be rejected (401) at the exchange endpoint."""
    with _patch_verify_raises(401, "Invalid token"):
        resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer wrong.issuer.token"},
        )
    assert resp.status_code == 401


def test_token_exchange_wrong_audience_returns_401(oidc_client):
    """Token with mismatched audience must be rejected (401) at the exchange endpoint."""
    with _patch_verify_raises(401, "Invalid token"):
        resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer wrong.audience.token"},
        )
    assert resp.status_code == 401


def test_token_exchange_expired_token_returns_401(oidc_client):
    """Expired token must be rejected (401) at the exchange endpoint."""
    with _patch_verify_raises(401, "Invalid token"):
        resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer expired.jwt.token"},
        )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4 (cryptographic): prove real RSA validation at HTTP level via mocked JWKS
# ---------------------------------------------------------------------------


def test_token_exchange_real_rsa_tamper_rejected(oidc_client):
    """Token signed by a different RSA key (forged) is rejected by real JWT validation."""
    signing_key = _make_rsa_key()
    verifying_key = _make_rsa_key()  # different key in JWKS
    jwk = _jwk_for_key(verifying_key)

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value={"keys": [jwk]})

    from admin_gateway.auth.oidc import OIDCProvider

    fake_provider = OIDCProvider(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/auth",
        token_endpoint=f"{ISSUER}/token",
        userinfo_endpoint=None,
        jwks_uri=f"{ISSUER}/certs",
    )

    token = _sign_token(signing_key, _valid_claims())

    with (
        patch(
            "admin_gateway.auth.oidc.OIDCClient.get_provider",
            new=AsyncMock(return_value=fake_provider),
        ),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_httpx.return_value.__aenter__ = AsyncMock(
            return_value=AsyncMock(get=AsyncMock(return_value=mock_resp))
        )
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)

        resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 8: Insufficient scope → 403
# ---------------------------------------------------------------------------


def test_insufficient_scope_returns_403_on_scope_guarded_endpoint(oidc_client):
    """Session from token with no admin scopes is denied on console:admin endpoint."""
    # No fg_scopes, no admin roles → empty scopes after extraction
    claims = _valid_claims(fg_scopes=[], tenant_id="tenant-alpha")

    with _patch_verify(claims):
        exchange_resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer limited.scope.token"},
        )

    assert exchange_resp.status_code == 200
    session_cookie = exchange_resp.cookies.get("fg_admin_session")
    assert session_cookie is not None

    # /api/v1/tenants requires console:admin
    resp = oidc_client.get(
        "/api/v1/tenants",
        cookies={"fg_admin_session": session_cookie},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 9: Wrong tenant → 403
# ---------------------------------------------------------------------------


def test_wrong_tenant_returns_403_on_tenant_guarded_endpoint(oidc_client):
    """Session bound to tenant-alpha cannot access resources for tenant-beta."""
    claims = _valid_claims(
        fg_scopes=["keys:read"],
        tenant_id="tenant-alpha",
        allowed_tenants=["tenant-alpha"],
    )

    with _patch_verify(claims):
        exchange_resp = oidc_client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer tenant-alpha.token"},
        )

    assert exchange_resp.status_code == 200
    session_cookie = exchange_resp.cookies.get("fg_admin_session")
    assert session_cookie is not None

    # Attempt to access tenant-beta resources (not in allowed_tenants)
    resp = oidc_client.get(
        "/api/v1/keys",
        params={"tenant_id": "tenant-beta"},
        cookies={"fg_admin_session": session_cookie},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 10: OIDC not configured → 503 (fail-closed)
# ---------------------------------------------------------------------------


def test_token_exchange_oidc_not_configured_returns_503(tmp_path, monkeypatch):
    """Token exchange with OIDC unconfigured must return 503 — no silent fallback."""
    db_path = tmp_path / "task62-nooidc.db"
    monkeypatch.setenv("AG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_SESSION_SECRET", SESSION_SECRET)
    monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "false")
    monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.local")
    monkeypatch.setenv("AG_CORE_API_KEY", "test-core-key")
    for key in (
        "FG_OIDC_ISSUER",
        "FG_OIDC_CLIENT_ID",
        "FG_OIDC_CLIENT_SECRET",
        "FG_OIDC_REDIRECT_URL",
        "FG_KEYCLOAK_BASE_URL",
        "FG_KEYCLOAK_REALM",
        "FG_KEYCLOAK_CLIENT_ID",
        "FG_KEYCLOAK_CLIENT_SECRET",
    ):
        monkeypatch.delenv(key, raising=False)

    mods = [m for m in sys.modules if m.startswith("admin_gateway")]
    for m in mods:
        del sys.modules[m]

    from admin_gateway.auth.config import reset_auth_config
    from admin_gateway.main import build_app

    reset_auth_config()
    app = build_app()

    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/auth/token-exchange",
            headers={"Authorization": "Bearer any.token.here"},
        )

    assert resp.status_code == 503
    detail = resp.json().get("detail", "")
    assert (
        "OIDC" in detail or "oidc" in detail.lower() or "configured" in detail.lower()
    )
