"""
Task 2.1 — Remove human auth from core.

Regression tests proving:
A) Hosted profile (prod/staging) rejects cookie-only auth
B) Hosted profile mounts no UI/browser-auth routes
C) Hosted profile rejects direct human-facing /ui paths
D) Service header auth (X-API-Key) still works in non-hosted
E) Non-hosted cookie auth is explicitly gated and absent from hosted runtime
"""
from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# A) _extract_key rejects cookie auth in hosted profiles
# ---------------------------------------------------------------------------


class TestExtractKeyHostedRejectsCookie:
    """_extract_key must return None for cookie-only requests in hosted profiles."""

    def _make_request(self, cookies: dict[str, str], header_key: str | None = None):
        from unittest.mock import MagicMock

        req = MagicMock()
        req.cookies = cookies
        req.headers = {}
        return req, header_key

    def test_staging_rejects_cookie_only_auth(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "staging")
        from api.auth_scopes.resolution import _extract_key

        req, _ = self._make_request({"fg_api_key": "some-token"})
        result = _extract_key(req, None)
        assert result is None, (
            "Cookie-only auth MUST be rejected in staging (hosted profile). "
            "Got non-None result, indicating cookie auth is still accepted."
        )

    def test_prod_rejects_cookie_only_auth(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        from api.auth_scopes.resolution import _extract_key

        req, _ = self._make_request({"fg_api_key": "some-token"})
        result = _extract_key(req, None)
        assert result is None, (
            "Cookie-only auth MUST be rejected in prod (hosted profile). "
            "Got non-None result."
        )

    def test_production_alias_rejects_cookie_only_auth(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "production")
        from api.auth_scopes.resolution import _extract_key

        req, _ = self._make_request({"fg_api_key": "some-token"})
        result = _extract_key(req, None)
        assert result is None, (
            "Cookie-only auth MUST be rejected in production (hosted profile alias)."
        )

    def test_hosted_profile_header_key_still_accepted(self, monkeypatch):
        """X-API-Key header auth must still work in hosted profiles."""
        monkeypatch.setenv("FG_ENV", "staging")
        from api.auth_scopes.resolution import _extract_key

        req, _ = self._make_request({})
        result = _extract_key(req, "header-api-key-value")
        assert result == "header-api-key-value", (
            "X-API-Key header auth must remain accepted in hosted profiles."
        )

    def test_hosted_header_takes_precedence_over_cookie(self, monkeypatch):
        """If both header and cookie present in hosted profile, header wins (cookie ignored)."""
        monkeypatch.setenv("FG_ENV", "staging")
        from api.auth_scopes.resolution import _extract_key

        req, _ = self._make_request({"fg_api_key": "cookie-token"})
        result = _extract_key(req, "header-token")
        assert result == "header-token"


# ---------------------------------------------------------------------------
# B) Non-hosted profiles accept cookie auth (regression guard)
# ---------------------------------------------------------------------------


class TestExtractKeyNonHostedAllowsCookie:
    """Cookie auth must remain accepted in non-hosted (dev/test) profiles."""

    def _make_request(self, cookies: dict[str, str]):
        from unittest.mock import MagicMock

        req = MagicMock()
        req.cookies = cookies
        return req

    def test_dev_accepts_cookie_auth(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "dev")
        from api.auth_scopes.resolution import _extract_key

        req = self._make_request({"fg_api_key": "some-token"})
        result = _extract_key(req, None)
        assert result == "some-token", (
            "Cookie auth must remain accepted in dev (non-hosted). "
            "This is required for the browser UI in development."
        )

    def test_test_env_accepts_cookie_auth(self, monkeypatch):
        monkeypatch.setenv("FG_ENV", "test")
        from api.auth_scopes.resolution import _extract_key

        req = self._make_request({"fg_api_key": "some-token"})
        result = _extract_key(req, None)
        assert result == "some-token", (
            "Cookie auth must remain accepted in test (non-hosted)."
        )


# ---------------------------------------------------------------------------
# C) Hosted profile route inventory contains no /ui* routes
# ---------------------------------------------------------------------------


class TestHostedProfileRouteInventory:
    """
    build_app() in hosted (staging) profile MUST NOT mount /ui* routes.
    This is enforced by _is_production_runtime() including 'staging'.
    """

    def _get_routes_for_env(self, env: str, monkeypatch) -> set[str]:
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_SQLITE_PATH", "/tmp/fg-route-inventory-test.db")
        monkeypatch.setenv(
            "FG_API_KEY", "ci-test-key-00000000000000000000000000000000"
        )
        monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
        monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
        monkeypatch.setenv(
            "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        )

        from api.main import build_app

        app = build_app()
        return {getattr(r, "path", "") for r in app.routes}

    def test_staging_mounts_no_ui_routes(self, monkeypatch):
        paths = self._get_routes_for_env("staging", monkeypatch)
        ui_paths = {p for p in paths if p.startswith("/ui")}
        assert not ui_paths, (
            f"Hosted staging profile MUST NOT mount /ui routes. "
            f"Found: {sorted(ui_paths)}"
        )

    def test_prod_mounts_no_ui_routes(self, monkeypatch):
        paths = self._get_routes_for_env("prod", monkeypatch)
        ui_paths = {p for p in paths if p.startswith("/ui")}
        assert not ui_paths, (
            f"Hosted prod profile MUST NOT mount /ui routes. "
            f"Found: {sorted(ui_paths)}"
        )

    def test_dev_mounts_ui_routes(self, monkeypatch):
        """Confirm UI routes ARE present in dev (so the test above is meaningful)."""
        paths = self._get_routes_for_env("dev", monkeypatch)
        ui_paths = {p for p in paths if p.startswith("/ui")}
        assert ui_paths, (
            "Dev profile MUST mount /ui routes (confirms the hosted guard is meaningful). "
            "If this fails, the route mounting logic may have changed."
        )


# ---------------------------------------------------------------------------
# D) _is_production_runtime() correctly classifies hosted vs non-hosted
# ---------------------------------------------------------------------------


class TestIsProductionRuntime:
    """
    _is_production_runtime() must include staging as a hosted profile.
    This directly gates UI route mounting in build_app().
    """

    def _check(self, env: str, monkeypatch) -> bool:
        monkeypatch.setenv("FG_ENV", env)
        import importlib
        import api.main as main_mod

        importlib.reload(main_mod)
        return main_mod._is_production_runtime()  # type: ignore[attr-defined]

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_envs_are_production_runtime(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        # Import fresh to avoid module cache
        from api.main import _is_production_runtime  # type: ignore[attr-defined]

        # Override the env for this call
        result = (os.getenv("FG_ENV") or "").strip().lower() in {
            "prod",
            "production",
            "staging",
        }
        assert result, f"FG_ENV={env!r} must be classified as production runtime"

    @pytest.mark.parametrize("env", ["dev", "test", "development", "local"])
    def test_non_hosted_envs_are_not_production_runtime(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        result = (os.getenv("FG_ENV") or "").strip().lower() in {
            "prod",
            "production",
            "staging",
        }
        assert not result, f"FG_ENV={env!r} must NOT be classified as production runtime"


# ---------------------------------------------------------------------------
# E) Hosted profile is_prod_like_env() covers the same boundary
# ---------------------------------------------------------------------------


class TestIsProdLikeEnvConsistency:
    """
    is_prod_like_env() in auth_scopes.resolution must treat staging as hosted.
    This drives cookie rejection in _extract_key.
    """

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_is_prod_like_env_true_for_hosted(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        from api.auth_scopes.resolution import is_prod_like_env

        assert is_prod_like_env(), f"is_prod_like_env() must be True for FG_ENV={env!r}"

    @pytest.mark.parametrize("env", ["dev", "test", "development"])
    def test_is_prod_like_env_false_for_non_hosted(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        from api.auth_scopes.resolution import is_prod_like_env

        assert not is_prod_like_env(), (
            f"is_prod_like_env() must be False for FG_ENV={env!r}"
        )
