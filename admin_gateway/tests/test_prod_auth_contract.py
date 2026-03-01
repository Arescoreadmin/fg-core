"""Tests for mandatory production authentication contract compliance.

Covers:
- FG_OIDC_SCOPES required in production
- return_to redirect allowlist (open-redirect prevention)
- Dev bypass restricted to localhost origins
"""

from __future__ import annotations

import os
from typing import Optional
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from admin_gateway.auth.config import AuthConfig, reset_auth_config
from admin_gateway.routers.auth import _is_safe_return_to, _safe_return_to


# ---------------------------------------------------------------------------
# GAP-1: FG_OIDC_SCOPES required in production
# ---------------------------------------------------------------------------


class TestOidcScopesProductionRequired:
    """FG_OIDC_SCOPES must be present when FG_ENV=production."""

    def _make_config(self, **kwargs) -> AuthConfig:
        base = dict(
            oidc_issuer="https://issuer.example.com",
            oidc_client_id="client",
            oidc_client_secret="secret",
            oidc_redirect_url="https://console.example.com/auth/callback",
            env="prod",
            dev_auth_bypass=False,
            session_secret="test-secret",
        )
        base.update(kwargs)
        return AuthConfig(**base)

    def test_prod_without_oidc_scopes_fails_validation(self):
        cfg = self._make_config(oidc_scopes=None)
        errors = cfg.validate()
        assert any("FG_OIDC_SCOPES" in e for e in errors), (
            f"Expected FG_OIDC_SCOPES validation error, got: {errors}"
        )

    def test_prod_with_oidc_scopes_passes_validation(self):
        cfg = self._make_config(oidc_scopes="openid profile email")
        errors = cfg.validate()
        assert not any("FG_OIDC_SCOPES" in e for e in errors), (
            f"Unexpected FG_OIDC_SCOPES error with scopes set: {errors}"
        )

    def test_dev_without_oidc_scopes_passes_validation(self):
        cfg = AuthConfig(env="dev", session_secret="s")
        errors = cfg.validate()
        assert not any("FG_OIDC_SCOPES" in e for e in errors)

    def test_oidc_scopes_list_space_separated(self):
        cfg = AuthConfig(oidc_scopes="openid profile email", session_secret="s")
        assert cfg.oidc_scopes_list == ["openid", "profile", "email"]

    def test_oidc_scopes_list_comma_separated(self):
        cfg = AuthConfig(oidc_scopes="openid,profile,email", session_secret="s")
        assert cfg.oidc_scopes_list == ["openid", "profile", "email"]

    def test_oidc_scopes_list_default_when_unset(self):
        cfg = AuthConfig(oidc_scopes=None, session_secret="s")
        result = cfg.oidc_scopes_list
        assert "openid" in result

    def test_get_auth_config_loads_fg_oidc_scopes(self, monkeypatch):
        monkeypatch.setenv("FG_OIDC_SCOPES", "openid email")
        reset_auth_config()
        from admin_gateway.auth.config import get_auth_config
        cfg = get_auth_config()
        assert cfg.oidc_scopes == "openid email"
        reset_auth_config()

    def test_prod_startup_fails_without_oidc_scopes(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FG_ENV", "prod")
        monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "false")
        monkeypatch.setenv("FG_SESSION_SECRET", "test-secret")
        monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example.com")
        monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client")
        monkeypatch.setenv("FG_OIDC_CLIENT_SECRET", "secret")
        monkeypatch.setenv(
            "FG_OIDC_REDIRECT_URL", "https://console.example.com/auth/callback"
        )
        monkeypatch.setenv("AG_CORS_ORIGINS", "https://console.example.com")
        monkeypatch.setenv("AG_SQLITE_PATH", str(tmp_path / "test.db"))
        monkeypatch.delenv("FG_OIDC_SCOPES", raising=False)
        reset_auth_config()

        import sys
        sys.modules.pop("admin_gateway.main", None)
        from admin_gateway.main import build_app

        with pytest.raises(RuntimeError, match="FG_OIDC_SCOPES"):
            build_app()

        reset_auth_config()

    def test_prod_startup_passes_with_oidc_scopes(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FG_ENV", "prod")
        monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "false")
        monkeypatch.setenv("FG_SESSION_SECRET", "test-secret")
        monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example.com")
        monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client")
        monkeypatch.setenv("FG_OIDC_CLIENT_SECRET", "secret")
        monkeypatch.setenv(
            "FG_OIDC_REDIRECT_URL", "https://console.example.com/auth/callback"
        )
        monkeypatch.setenv("FG_OIDC_SCOPES", "openid profile email")
        monkeypatch.setenv("AG_CORS_ORIGINS", "https://console.example.com")
        monkeypatch.setenv("AG_SQLITE_PATH", str(tmp_path / "test.db"))
        reset_auth_config()

        import sys
        sys.modules.pop("admin_gateway.main", None)
        from admin_gateway.main import build_app

        # Should not raise
        app = build_app()
        assert app is not None

        reset_auth_config()


# ---------------------------------------------------------------------------
# GAP-2: return_to redirect allowlist
# ---------------------------------------------------------------------------


class TestRedirectAllowlist:
    """Open-redirect prevention: return_to must be a safe relative path."""

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("/admin/me", True),
            ("/dashboard", True),
            ("/some/deep/path?foo=bar", True),
            ("", False),
            (None, False),
            ("https://evil.com/phish", False),
            ("http://evil.com", False),
            ("//evil.com/steal", False),
            ("//evil.com", False),
            ("javascript:alert(1)", False),
            ("data:text/html,<script>", False),
        ],
    )
    def test_is_safe_return_to(self, url: Optional[str], expected: bool):
        assert _is_safe_return_to(url) is expected, f"url={url!r} expected={expected}"

    def test_safe_return_to_passes_relative(self):
        assert _safe_return_to("/admin/me") == "/admin/me"

    def test_safe_return_to_rejects_absolute(self):
        assert _safe_return_to("https://evil.com") == "/admin/me"

    def test_safe_return_to_rejects_protocol_relative(self):
        assert _safe_return_to("//evil.com") == "/admin/me"

    def test_safe_return_to_rejects_none(self):
        assert _safe_return_to(None) == "/admin/me"

    def test_login_rejects_unsafe_return_to(self, monkeypatch, tmp_path):
        """Login with unsafe return_to must redirect to safe default, not to attacker URL."""
        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "true")
        monkeypatch.setenv("FG_SESSION_SECRET", "test-secret")
        monkeypatch.setenv("AG_SQLITE_PATH", str(tmp_path / "test.db"))
        monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.local")
        monkeypatch.setenv("AG_CORE_API_KEY", "test-key")
        for k in ("FG_OIDC_ISSUER", "FG_OIDC_CLIENT_ID", "FG_OIDC_CLIENT_SECRET",
                  "FG_OIDC_REDIRECT_URL"):
            monkeypatch.delenv(k, raising=False)
        reset_auth_config()

        import sys
        sys.modules.pop("admin_gateway.main", None)
        from admin_gateway.main import build_app

        app = build_app()
        with TestClient(app, headers={"host": "localhost"}) as client:
            response = client.get(
                "/auth/login",
                params={"return_to": "https://evil.com/phish"},
                follow_redirects=False,
            )
        # Must redirect to safe default, NOT to the attacker URL
        assert response.status_code == 302
        location = response.headers.get("location", "")
        assert "evil.com" not in location
        assert location == "/admin/me" or location.startswith("/admin")

        reset_auth_config()

    def test_login_allows_safe_return_to(self, monkeypatch, tmp_path):
        """Login with safe relative return_to must use that path."""
        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "true")
        monkeypatch.setenv("FG_SESSION_SECRET", "test-secret")
        monkeypatch.setenv("AG_SQLITE_PATH", str(tmp_path / "test.db"))
        monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.local")
        monkeypatch.setenv("AG_CORE_API_KEY", "test-key")
        for k in ("FG_OIDC_ISSUER", "FG_OIDC_CLIENT_ID", "FG_OIDC_CLIENT_SECRET",
                  "FG_OIDC_REDIRECT_URL"):
            monkeypatch.delenv(k, raising=False)
        reset_auth_config()

        import sys
        sys.modules.pop("admin_gateway.main", None)
        from admin_gateway.main import build_app

        app = build_app()
        with TestClient(app, headers={"host": "localhost"}) as client:
            response = client.get(
                "/auth/login",
                params={"return_to": "/dashboard"},
                follow_redirects=False,
            )
        assert response.status_code == 302
        location = response.headers.get("location", "")
        assert location == "/dashboard"

        reset_auth_config()


# ---------------------------------------------------------------------------
# GAP-3: Dev bypass restricted to localhost origins
# ---------------------------------------------------------------------------


class TestDevBypassLocalhostRestriction:
    """Dev bypass must only respond to requests with a localhost Host header."""

    def _make_bypass_app(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "true")
        monkeypatch.setenv("FG_SESSION_SECRET", "test-secret")
        monkeypatch.setenv("AG_SQLITE_PATH", str(tmp_path / "test.db"))
        monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.local")
        monkeypatch.setenv("AG_CORE_API_KEY", "test-key")
        for k in ("FG_OIDC_ISSUER", "FG_OIDC_CLIENT_ID", "FG_OIDC_CLIENT_SECRET",
                  "FG_OIDC_REDIRECT_URL"):
            monkeypatch.delenv(k, raising=False)
        reset_auth_config()

        import sys
        sys.modules.pop("admin_gateway.main", None)
        from admin_gateway.main import build_app

        return build_app()

    def test_bypass_allowed_from_localhost(self, monkeypatch, tmp_path):
        app = self._make_bypass_app(monkeypatch, tmp_path)
        with TestClient(app, headers={"host": "localhost"}) as client:
            response = client.get("/admin/me")
        assert response.status_code == 200
        reset_auth_config()

    def test_bypass_allowed_from_127_0_0_1(self, monkeypatch, tmp_path):
        app = self._make_bypass_app(monkeypatch, tmp_path)
        with TestClient(app, headers={"host": "127.0.0.1"}) as client:
            response = client.get("/admin/me")
        assert response.status_code == 200
        reset_auth_config()

    def test_bypass_blocked_from_public_host(self, monkeypatch, tmp_path):
        app = self._make_bypass_app(monkeypatch, tmp_path)
        with TestClient(app, headers={"host": "admin.example.com"}) as client:
            response = client.get("/admin/me")
        # Must return 401 — bypass must not activate for non-localhost hosts
        assert response.status_code == 401
        reset_auth_config()

    def test_bypass_blocked_from_internal_ip_host(self, monkeypatch, tmp_path):
        """Bypass must be blocked even for private-range IP hosts that aren't loopback."""
        app = self._make_bypass_app(monkeypatch, tmp_path)
        with TestClient(app, headers={"host": "10.0.0.1"}) as client:
            response = client.get("/admin/me")
        assert response.status_code == 401
        reset_auth_config()
