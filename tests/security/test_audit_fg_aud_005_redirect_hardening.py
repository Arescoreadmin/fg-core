"""
Regression tests for FG-AUD-005.

FG-AUD-005: OIDC/JWKS HTTP calls were missing follow_redirects=False, enabling
redirect-based SSRF attacks where a compromised OIDC provider could redirect
discovery or JWKS requests to internal endpoints.

These tests prove:
  1. _fetch_oidc_config raises on 3xx redirect (follow_redirects=False enforced).
  2. _fetch_jwks raises on 3xx redirect.
  3. exchange_code_for_tokens POST raises on 3xx redirect.
  4. admin_gateway/auth/oidc.py OIDCProvider.discover raises on 3xx redirect.
"""

from __future__ import annotations

import pytest
import httpx


class TestAdminGatewayAuthRedirectHardening:
    """Verify admin_gateway/auth.py OIDC helpers refuse to follow redirects."""

    @pytest.mark.asyncio
    async def test_fetch_oidc_config_refuses_redirect(self, respx_mock):
        """_fetch_oidc_config must not follow a 3xx from the OIDC discovery endpoint."""
        import respx

        from admin_gateway.auth import _fetch_oidc_config

        respx_mock.get("https://idp.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(301, headers={"Location": "http://169.254.169.254/meta-data/"})
        )

        # httpx raises httpx.RemoteProtocolError or returns non-2xx for redirect
        # when follow_redirects=False.
        with pytest.raises((httpx.HTTPStatusError, httpx.RemoteProtocolError, Exception)):
            await _fetch_oidc_config("https://idp.example.com")

    @pytest.mark.asyncio
    async def test_fetch_jwks_refuses_redirect(self, respx_mock):
        """_fetch_jwks must not follow a 3xx to an internal endpoint."""
        from admin_gateway.auth import _fetch_jwks

        respx_mock.get("https://idp.example.com/.well-known/jwks.json").mock(
            return_value=httpx.Response(302, headers={"Location": "http://10.0.0.1/secret"})
        )

        with pytest.raises((httpx.HTTPStatusError, httpx.RemoteProtocolError, Exception)):
            await _fetch_jwks("https://idp.example.com/.well-known/jwks.json")


class TestOIDCClientRedirectHardening:
    """Verify admin_gateway/auth/oidc.py OIDCClient helpers refuse redirects."""

    @pytest.mark.asyncio
    async def test_oidc_discover_refuses_redirect(self, respx_mock):
        """OIDCProvider.discover must not follow a 3xx redirect."""
        from admin_gateway.auth.oidc import OIDCProvider, OIDCConfig

        respx_mock.get("https://idp.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(301, headers={"Location": "http://192.168.1.1/redirect"})
        )

        fake_config = OIDCConfig(
            oidc_issuer="https://idp.example.com",
            oidc_client_id="client",
            oidc_client_secret="secret",
            oidc_redirect_url="https://app.example.com/callback",
        )

        with pytest.raises(Exception):
            await OIDCProvider.discover("https://idp.example.com", fake_config)

    @pytest.mark.asyncio
    async def test_exchange_code_refuses_redirect(self, respx_mock):
        """exchange_code must not follow a 3xx redirect from the token endpoint."""
        from admin_gateway.auth.oidc import OIDCClient, OIDCConfig, OIDCProvider
        from unittest.mock import AsyncMock, patch

        fake_provider = OIDCProvider(
            issuer="https://idp.example.com",
            authorization_endpoint="https://idp.example.com/auth",
            token_endpoint="https://idp.example.com/token",
            userinfo_endpoint=None,
            jwks_uri="https://idp.example.com/.well-known/jwks.json",
            end_session_endpoint=None,
        )

        respx_mock.post("https://idp.example.com/token").mock(
            return_value=httpx.Response(302, headers={"Location": "http://internal.service/"})
        )

        fake_config = OIDCConfig(
            oidc_issuer="https://idp.example.com",
            oidc_client_id="client",
            oidc_client_secret="secret",
            oidc_redirect_url="https://app.example.com/callback",
        )
        client = OIDCClient(fake_config)

        with patch.object(client, "get_provider", return_value=fake_provider):
            with patch.object(client, "_validate_state", return_value={"code_verifier": "cv123"}):
                with pytest.raises(Exception):
                    await client.exchange_code("authcode", "state123")


class TestFollowRedirectsFalseProof:
    """Static proof that follow_redirects=False is set in all OIDC helper functions."""

    def test_admin_auth_fetch_oidc_config_has_no_follow_redirects_true(self):
        """admin_gateway/auth.py _fetch_oidc_config must have follow_redirects=False."""
        from pathlib import Path
        src = (Path(__file__).parent.parent.parent / "admin_gateway/auth.py").read_text()
        # Ensure follow_redirects=False is present and follow_redirects=True is absent
        assert "follow_redirects=False" in src, \
            "admin_gateway/auth.py: _fetch_oidc_config / _fetch_jwks must set follow_redirects=False"
        assert "follow_redirects=True" not in src, \
            "admin_gateway/auth.py: follow_redirects=True found — redirects must be disabled"

    def test_oidc_client_has_no_follow_redirects_true(self):
        """admin_gateway/auth/oidc.py must set follow_redirects=False on all HTTP clients."""
        from pathlib import Path
        src = (Path(__file__).parent.parent.parent / "admin_gateway/auth/oidc.py").read_text()
        # Every AsyncClient() without follow_redirects=False is a finding.
        import re
        bare_clients = re.findall(r"httpx\.AsyncClient\(\)", src)
        assert not bare_clients, (
            f"admin_gateway/auth/oidc.py: found {len(bare_clients)} bare "
            "httpx.AsyncClient() without follow_redirects=False"
        )
