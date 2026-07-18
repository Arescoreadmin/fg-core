"""
R6 Gateway Secret Convergence — resolver and guard tests.

Covers:
  1. Resolver unit tests — precedence, fallback, blank/whitespace filtering
  2. Guard integration tests — canonical name accepted, legacy-only env works,
     canonical beats legacy when they differ, fail-closed behaviour
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Resolver unit tests
# ---------------------------------------------------------------------------


class TestResolveInternalGatewaySecret:
    """Unit tests for api/config/internal_gateway_secret.py::resolve_internal_gateway_secret."""

    def _resolve(self):
        # Re-import each call so monkeypatch env changes take effect.
        from importlib import import_module, reload
        import api.config.internal_gateway_secret as m

        reload(m)
        return m.resolve_internal_gateway_secret()

    def _clear_all(self, monkeypatch):
        for name in (
            "FG_INTERNAL_GATEWAY_SECRET",
            "FG_ADMIN_GATEWAY_INTERNAL_TOKEN",
            "FG_INTERNAL_AUTH_SECRET",
            "FG_INTERNAL_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)

    def test_canonical_secret_is_preferred(self, monkeypatch):
        """FG_INTERNAL_GATEWAY_SECRET takes precedence over every legacy name."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "canonical-secret")
        monkeypatch.setenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", "legacy-admin-token")
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "legacy-auth-secret")
        monkeypatch.setenv("FG_INTERNAL_TOKEN", "legacy-token")
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        assert resolve_internal_gateway_secret() == "canonical-secret"

    def test_admin_gateway_internal_token_fallback(self, monkeypatch):
        """FG_ADMIN_GATEWAY_INTERNAL_TOKEN is used when canonical is absent."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", "admin-token")
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "auth-secret")
        monkeypatch.setenv("FG_INTERNAL_TOKEN", "legacy-token")
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        assert resolve_internal_gateway_secret() == "admin-token"

    def test_internal_auth_secret_fallback(self, monkeypatch):
        """FG_INTERNAL_AUTH_SECRET is used when canonical and admin token are absent."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "auth-secret")
        monkeypatch.setenv("FG_INTERNAL_TOKEN", "legacy-token")
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        assert resolve_internal_gateway_secret() == "auth-secret"

    def test_internal_token_fallback(self, monkeypatch):
        """FG_INTERNAL_TOKEN is the last resort when all others are absent."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_INTERNAL_TOKEN", "legacy-token")
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        assert resolve_internal_gateway_secret() == "legacy-token"

    def test_blank_values_are_ignored(self, monkeypatch):
        """Blank and whitespace-only values must be skipped; resolver falls through."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "   ")
        monkeypatch.setenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", "")
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "real-secret")
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        assert resolve_internal_gateway_secret() == "real-secret"

    def test_missing_all_secrets_returns_empty(self, monkeypatch):
        """Returns empty string when no variable is set."""
        self._clear_all(monkeypatch)
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        assert resolve_internal_gateway_secret() == ""

    def test_canonical_secret_wins_when_legacy_values_conflict(self, monkeypatch):
        """
        The canonical name must win even when legacy secrets have different values.

        This is the key migration-correctness test: after Deploy 1, services that
        have been rotated to FG_INTERNAL_GATEWAY_SECRET must not fall back to an
        old value in FG_INTERNAL_AUTH_SECRET.
        """
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "canonical")
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "legacy-different-value")
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        result = resolve_internal_gateway_secret()
        assert result == "canonical"
        assert result != "legacy-different-value"

    def test_leading_trailing_whitespace_stripped(self, monkeypatch):
        """Values with surrounding whitespace are stripped."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "  padded-secret  ")
        from api.config.internal_gateway_secret import resolve_internal_gateway_secret

        assert resolve_internal_gateway_secret() == "padded-secret"


# ---------------------------------------------------------------------------
# 2. Guard integration tests — require_internal_admin_gateway
# ---------------------------------------------------------------------------


class TestGuardWithCanonicalSecret:
    """
    require_internal_admin_gateway must accept the canonical secret name.

    These tests complement test_gateway_only_admin_access.py by exercising
    FG_INTERNAL_GATEWAY_SECRET specifically.
    """

    def _make_request(self, token_header: str | None = None):
        from unittest.mock import MagicMock

        req = MagicMock()
        req.headers = {"x-fg-internal-token": token_header} if token_header else {}
        return req

    def _clear_all(self, monkeypatch):
        for name in (
            "FG_INTERNAL_GATEWAY_SECRET",
            "FG_ADMIN_GATEWAY_INTERNAL_TOKEN",
            "FG_INTERNAL_AUTH_SECRET",
            "FG_INTERNAL_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_canonical_secret_accepted(self, env, monkeypatch):
        """Canonical FG_INTERNAL_GATEWAY_SECRET must be accepted in hosted profiles."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "canonical-secret")
        from api.admin import require_internal_admin_gateway

        req = self._make_request(token_header="canonical-secret")
        require_internal_admin_gateway(req)  # must not raise

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_incorrect_secret_denied(self, env, monkeypatch):
        """Wrong token must be rejected even when canonical name is configured."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "canonical-secret")
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        req = self._make_request(token_header="wrong-value")
        with pytest.raises(HTTPException) as exc:
            require_internal_admin_gateway(req)
        assert exc.value.status_code == 403

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_canonical_overrides_legacy_value(self, env, monkeypatch):
        """
        When FG_INTERNAL_GATEWAY_SECRET='canonical' and FG_INTERNAL_AUTH_SECRET='legacy',
        the guard must accept 'canonical' and reject 'legacy'.
        """
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "canonical")
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "legacy")
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        # Sending the legacy value must be rejected when canonical is set.
        req = self._make_request(token_header="legacy")
        with pytest.raises(HTTPException) as exc:
            require_internal_admin_gateway(req)
        assert exc.value.status_code == 403

        # Sending the canonical value must be accepted.
        req2 = self._make_request(token_header="canonical")
        require_internal_admin_gateway(req2)  # must not raise

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_legacy_only_environment_still_works(self, env, monkeypatch):
        """FG_INTERNAL_AUTH_SECRET alone (pre-rotation) must still be accepted."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "legacy-auth-secret")
        from api.admin import require_internal_admin_gateway

        req = self._make_request(token_header="legacy-auth-secret")
        require_internal_admin_gateway(req)  # must not raise

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_fail_closed_no_secret_configured(self, env, monkeypatch):
        """With no secret configured in a hosted profile, all requests must be rejected."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_ENV", env)
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        req = self._make_request(token_header="any-value")
        with pytest.raises(HTTPException) as exc:
            require_internal_admin_gateway(req)
        assert exc.value.status_code == 403

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_whitespace_only_canonical_falls_through_to_legacy(self, env, monkeypatch):
        """A whitespace-only canonical value must not satisfy the guard — falls to legacy."""
        self._clear_all(monkeypatch)
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "   ")
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "real-legacy-secret")
        from api.admin import require_internal_admin_gateway

        req = self._make_request(token_header="real-legacy-secret")
        require_internal_admin_gateway(req)  # must not raise

    def test_guard_and_resolution_py_agree_on_canonical(self, monkeypatch):
        """
        require_internal_admin_gateway and _admin_gateway_internal_token must
        agree when the canonical name is set. Both use the shared resolver,
        so this is a consistency regression test.
        """
        for name in (
            "FG_INTERNAL_GATEWAY_SECRET",
            "FG_ADMIN_GATEWAY_INTERNAL_TOKEN",
            "FG_INTERNAL_AUTH_SECRET",
            "FG_INTERNAL_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("FG_ENV", "prod")
        monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "canonical-secret")

        from api.auth_scopes.resolution import _admin_gateway_internal_token

        assert _admin_gateway_internal_token() == "canonical-secret"

        from api.admin import require_internal_admin_gateway

        req_mock = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        req_mock.headers = {"x-fg-internal-token": "canonical-secret"}
        require_internal_admin_gateway(req_mock)  # must not raise
