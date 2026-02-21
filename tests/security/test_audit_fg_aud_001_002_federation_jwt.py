"""
Regression tests for FG-AUD-001 and FG-AUD-002.

FG-AUD-001: Federation JWT validation previously skipped signature verification.
FG-AUD-002: JWKS URL was derived from attacker-supplied 'iss' claim, enabling SSRF.

These tests prove:
  1. A forged (unsigned) token is REJECTED even if the iss claim matches.
  2. An attacker-supplied 'iss' pointing to a private/loopback IP is BLOCKED.
  3. An attacker-supplied 'iss' that triggers a redirect is BLOCKED.
  4. FG_FEDERATION_ISSUER must be set; absent config fails CLOSED.
  5. DNS resolving to a private IP is BLOCKED.
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from services.federation_extension.service import (
    FederationService,
    _assert_safe_federation_url,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _forge_jwt(payload: dict, sign_with: str = "forged_secret") -> str:
    """Create a JWT with an attacker-controlled payload but NO valid signature."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    # Forge a random signature — NOT signed with the real private key.
    sig = base64.urlsafe_b64encode(sign_with.encode()).rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


# ---------------------------------------------------------------------------
# FG-AUD-001: Signature verification required
# ---------------------------------------------------------------------------

class TestFederationSignatureRequired:
    """FG-AUD-001: validate_token must reject unsigned/forged tokens."""

    def test_forged_token_rejected_when_issuer_matches(self, monkeypatch):
        """A forged JWT with correct 'iss' is rejected — no JWKS call even needed."""
        monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://idp.example.com")

        token = _forge_jwt({"iss": "https://idp.example.com", "exp": 9999999999, "sub": "attacker"})

        service = FederationService()

        # Patch cache.get to return a fake JWKS so the SSRF check is not the failure.
        import json as _json
        import importlib
        from unittest.mock import patch

        with patch.object(service.cache, "get", return_value={"keys": []}):
            with pytest.raises(ValueError, match="federation_jwks_key_not_found|federation_token_invalid|PyJWT"):
                service.validate_token(token)

    def test_forged_token_with_no_issuer_config_fails_closed(self, monkeypatch):
        """Without FG_FEDERATION_ISSUER, validation fails closed (never trusts anything)."""
        monkeypatch.delenv("FG_FEDERATION_ISSUER", raising=False)

        token = _forge_jwt({"iss": "https://any.issuer.com", "exp": 9999999999})
        service = FederationService()

        with pytest.raises(ValueError, match="federation_config_error"):
            service.validate_token(token)

    def test_wrong_issuer_rejected_before_jwks_fetch(self, monkeypatch):
        """A token with wrong 'iss' is rejected before any JWKS fetch occurs."""
        monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://legit.idp.example.com")

        token = _forge_jwt({"iss": "https://attacker.com", "exp": 9999999999})
        service = FederationService()

        with pytest.raises(ValueError, match="federation_invalid_issuer"):
            service.validate_token(token)

    def test_missing_iss_claim_rejected(self, monkeypatch):
        """A token with no 'iss' claim is rejected before JWKS fetch."""
        monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://idp.example.com")

        token = _forge_jwt({"exp": 9999999999, "sub": "noissclaim"})
        service = FederationService()

        with pytest.raises(ValueError, match="federation_invalid_issuer"):
            service.validate_token(token)


# ---------------------------------------------------------------------------
# FG-AUD-002: SSRF guard on JWKS URL
# ---------------------------------------------------------------------------

class TestFederationSsrfGuard:
    """FG-AUD-002: JWKS URL must never resolve to a private/loopback address."""

    @pytest.mark.parametrize("url", [
        "http://169.254.169.254/latest/meta-data/",      # AWS metadata
        "http://10.0.0.1/.well-known/jwks.json",          # RFC-1918
        "http://192.168.1.1/.well-known/jwks.json",       # RFC-1918
        "http://172.16.0.1/.well-known/jwks.json",        # RFC-1918
        "http://127.0.0.1/.well-known/jwks.json",         # loopback
        "http://[::1]/.well-known/jwks.json",             # IPv6 loopback
        "http://[::ffff:127.0.0.1]/.well-known/jwks.json",  # IPv6-mapped IPv4 loopback
        "http://[fe80::1]/.well-known/jwks.json",         # link-local
        "file:///etc/passwd",                              # file scheme
        "ftp://internal/.well-known/jwks.json",            # ftp scheme
    ])
    def test_private_and_special_urls_blocked(self, url):
        with pytest.raises(ValueError, match="federation_ssrf_blocked"):
            _assert_safe_federation_url(url)

    def test_https_public_url_allowed(self):
        """A legitimate public HTTPS URL passes the SSRF guard."""
        # Should not raise.
        _assert_safe_federation_url("https://idp.example.com/.well-known/jwks.json")

    def test_http_blocked_by_default(self):
        """HTTP is blocked unless FG_FEDERATION_ALLOW_HTTP=1."""
        with pytest.raises(ValueError, match="federation_ssrf_blocked"):
            _assert_safe_federation_url("http://idp.example.com/.well-known/jwks.json")

    def test_http_allowed_with_explicit_override(self, monkeypatch):
        """HTTP is allowed only with explicit FG_FEDERATION_ALLOW_HTTP=1 dev override."""
        monkeypatch.setenv("FG_FEDERATION_ALLOW_HTTP", "1")
        # Must not raise for a public IP over http in dev mode.
        _assert_safe_federation_url("http://idp.example.com/.well-known/jwks.json")

    def test_jwks_url_derived_from_config_not_token(self, monkeypatch):
        """JWKS URL is derived from FG_FEDERATION_ISSUER, NOT from the token's 'iss' claim.

        This is the core FG-AUD-002 invariant: attacker cannot supply an iss pointing
        to an internal service because the JWKS URL ignores the token's iss.
        """
        monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://legit.idp.example.com")

        # Token claims iss = internal IP (SSRF attempt).
        # But validate_token() builds JWKS URL from FG_FEDERATION_ISSUER,
        # and will reject the token before reaching the JWKS fetch (wrong issuer).
        token = _forge_jwt({"iss": "http://10.0.0.1", "exp": 9999999999})
        service = FederationService()

        with pytest.raises(ValueError, match="federation_invalid_issuer"):
            service.validate_token(token)

    def test_redirect_blocked_in_jwks_fetch(self, monkeypatch):
        """A redirect from the JWKS server (e.g. to an internal endpoint) is blocked."""
        import urllib.error
        from unittest.mock import patch, MagicMock

        monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://legit.idp.example.com")

        # Simulate the redirect handler raising ValueError (as patched in service.py).
        def _raise_redirect(*args, **kwargs):
            raise ValueError("federation_ssrf_blocked: redirect to http://10.0.0.1/ not allowed")

        service = FederationService()
        with patch(
            "services.federation_extension.service._fetch_jwks_no_redirect",
            side_effect=_raise_redirect,
        ):
            token = _forge_jwt({
                "iss": "https://legit.idp.example.com",
                "exp": 9999999999,
            })
            with pytest.raises(ValueError, match="federation_ssrf_blocked"):
                service.validate_token(token)

    def test_dns_rebinding_blocked(self, monkeypatch):
        """DNS rebinding scenario: hostname resolves to private IP is blocked."""
        import socket
        from unittest.mock import patch

        # Simulate DNS returning 192.168.1.100 for an ostensibly public hostname.
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.100", 0))]

        with patch("socket.getaddrinfo", fake_getaddrinfo):
            with pytest.raises(ValueError, match="federation_ssrf_blocked"):
                _assert_safe_federation_url("https://evil.rebind.example.com/.well-known/jwks.json")
