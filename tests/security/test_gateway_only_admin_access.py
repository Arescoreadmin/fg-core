"""
Task 2.2 — Enforce gateway-only access.

Regression tests proving:
A) Hosted profiles (prod/staging) reject direct /admin access without gateway token
B) Hosted profiles accept /admin access with valid gateway token
C) Non-hosted profiles without a configured token skip enforcement (dev convenience)
D) require_internal_admin_gateway correctly classifies all hosted profiles
E) Non-hosted profiles WITH a configured internal token enforce the real contract
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# A+B) require_internal_admin_gateway enforces gateway token in hosted profiles
# ---------------------------------------------------------------------------


class TestRequireInternalAdminGateway:
    """
    require_internal_admin_gateway must reject direct (non-gateway) calls to
    /admin in hosted profiles (prod, production, staging).
    """

    def _make_request(
        self,
        internal_token_header: str | None = None,
        internal_caller_header: str | None = None,
    ):
        from unittest.mock import MagicMock

        req = MagicMock()
        headers: dict[str, str] = {}
        if internal_token_header is not None:
            headers["x-fg-internal-token"] = internal_token_header
        if internal_caller_header is not None:
            headers["X-Admin-Gateway-Internal"] = internal_caller_header
        req.headers = headers
        return req

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_rejects_direct_access_without_token(self, env, monkeypatch):
        """Direct /admin call without gateway token must be rejected in hosted profiles."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", "valid-internal-token")
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        req = self._make_request()  # no token header
        with pytest.raises(HTTPException) as exc_info:
            require_internal_admin_gateway(req)
        assert exc_info.value.status_code == 403, (
            f"FG_ENV={env!r}: direct /admin access without gateway token "
            "must return 403. If this fails, staging was dropped from the "
            "hosted enforcement set and admin routes are directly accessible."
        )
        assert exc_info.value.detail == "admin_gateway_internal_required"

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_rejects_wrong_token(self, env, monkeypatch):
        """Wrong internal token must be rejected in hosted profiles."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", "correct-token")
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        req = self._make_request(internal_token_header="wrong-token")
        with pytest.raises(HTTPException) as exc_info:
            require_internal_admin_gateway(req)
        assert exc_info.value.status_code == 403

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_accepts_correct_gateway_token(self, env, monkeypatch):
        """Correct gateway internal token must be accepted in hosted profiles."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.setenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", "correct-token")
        from api.admin import require_internal_admin_gateway

        req = self._make_request(internal_token_header="correct-token")
        # Must not raise
        require_internal_admin_gateway(req)

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_rejects_when_token_not_configured(self, env, monkeypatch):
        """If gateway token is not configured in hosted profile, request must be rejected."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.delenv("FG_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        monkeypatch.delenv("FG_API_KEY", raising=False)
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        req = self._make_request(internal_token_header="any-token")
        with pytest.raises(HTTPException) as exc_info:
            require_internal_admin_gateway(req)
        assert exc_info.value.status_code == 403, (
            f"FG_ENV={env!r}: unconfigured gateway token must reject all /admin "
            "requests (fail-closed)."
        )

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_accepts_fg_internal_auth_secret_fallback(self, env, monkeypatch):
        """FG_INTERNAL_AUTH_SECRET must be accepted when FG_ADMIN_GATEWAY_INTERNAL_TOKEN is absent.

        This is the compose-native path: docker-compose.oidc.yml sets
        AG_CORE_INTERNAL_TOKEN = FG_INTERNAL_AUTH_SECRET on the gateway side, and
        core has FG_INTERNAL_AUTH_SECRET set. Both guards must use the same secret.
        """
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "shared-compose-secret")
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        monkeypatch.delenv("FG_API_KEY", raising=False)
        from api.admin import require_internal_admin_gateway

        req = self._make_request(internal_token_header="shared-compose-secret")
        # Must not raise — FG_INTERNAL_AUTH_SECRET is the compose-native fallback
        require_internal_admin_gateway(req)

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_rejects_api_key_when_internal_auth_secret_differs(
        self, env, monkeypatch
    ):
        """FG_API_KEY must NOT act as an internal auth fallback.

        Sending FG_API_KEY as X-FG-Internal-Token must be rejected when
        FG_INTERNAL_AUTH_SECRET is set to a different value. Conflating the
        global API key with the internal trust token is a security anti-pattern.
        """
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "shared-compose-secret")
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("FG_API_KEY", "global-api-key-different-from-internal")
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        # Sending the global API key value as the internal token must be rejected
        req = self._make_request(
            internal_token_header="global-api-key-different-from-internal"
        )
        with pytest.raises(HTTPException) as exc_info:
            require_internal_admin_gateway(req)
        assert exc_info.value.status_code == 403, (
            "Global API key must not be accepted as internal gateway token "
            "when FG_INTERNAL_AUTH_SECRET is configured."
        )

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_fallback_chain_consistent_with_resolution_py(self, env, monkeypatch):
        """require_internal_admin_gateway and _admin_gateway_internal_token must agree.

        Both functions compute the expected internal token. If they diverge,
        the auth_gate middleware accepts the request but the router dependency
        rejects it — resulting in 403 on valid internal admin calls.
        """
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "shared-compose-secret")
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        monkeypatch.delenv("FG_API_KEY", raising=False)

        from api.admin import require_internal_admin_gateway
        from api.auth_scopes.resolution import _admin_gateway_internal_token

        resolution_token = _admin_gateway_internal_token()
        assert resolution_token == "shared-compose-secret", (
            "_admin_gateway_internal_token() must resolve FG_INTERNAL_AUTH_SECRET"
        )

        # The same token that resolution.py accepts must be accepted by the guard
        req = self._make_request(internal_token_header=resolution_token)
        # Must not raise — both guards must agree on the expected value
        require_internal_admin_gateway(req)


# ---------------------------------------------------------------------------
# C) Non-hosted profiles skip gateway enforcement
# ---------------------------------------------------------------------------


class TestNonHostedAdminGatewayNotEnforced:
    """
    In non-hosted profiles, require_internal_admin_gateway must be a no-op.
    Direct /admin calls without a token must pass through.
    """

    def _make_request(self):
        from unittest.mock import MagicMock

        req = MagicMock()
        req.headers = {}
        return req

    @pytest.mark.parametrize("env", ["dev", "test", "development", "local"])
    def test_non_hosted_allows_direct_admin_access(self, env, monkeypatch):
        """Gateway token must NOT be required in non-hosted profiles when no token is configured."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.delenv("FG_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        from api.admin import require_internal_admin_gateway

        req = self._make_request()
        # Must not raise — no token configured AND non-prod → dev bypass preserved
        require_internal_admin_gateway(req)


# ---------------------------------------------------------------------------
# D) Hosted classification is consistent with is_production_env()
# ---------------------------------------------------------------------------


class TestGatewayHostedClassificationConsistency:
    """
    The enforcement set in require_internal_admin_gateway must match
    is_production_env() so there is no gap between what is "production"
    and what enforces gateway-only access.
    """

    @pytest.mark.parametrize("env", ["prod", "production", "staging"])
    def test_hosted_env_is_classified_as_production(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        from api.config.env import is_production_env

        assert is_production_env(), (
            f"FG_ENV={env!r} must be a production env. "
            "If this fails, is_production_env() and gateway enforcement are inconsistent."
        )

    @pytest.mark.parametrize("env", ["dev", "test", "development", "local"])
    def test_non_hosted_env_is_not_classified_as_production(self, env, monkeypatch):
        monkeypatch.setenv("FG_ENV", env)
        from api.config.env import is_production_env

        assert not is_production_env(), f"FG_ENV={env!r} must NOT be a production env."


# ---------------------------------------------------------------------------
# E) Dev/local WITH a configured internal token must enforce the real contract
# ---------------------------------------------------------------------------


class TestDevWithConfiguredTokenEnforces:
    """
    When FG_INTERNAL_AUTH_SECRET (or another internal token) is configured,
    require_internal_admin_gateway must enforce it regardless of FG_ENV.

    This closes the dev/local auth drift gap: a developer running core locally
    with a configured internal secret should get production-aligned enforcement,
    not a silent bypass that can hide auth contract problems.
    """

    def _make_request(self, token_header: str | None = None):
        from unittest.mock import MagicMock

        req = MagicMock()
        req.headers = {}
        if token_header is not None:
            req.headers["x-fg-internal-token"] = token_header
        return req

    @pytest.mark.parametrize("env", ["dev", "test", "development", "local"])
    def test_dev_with_configured_token_rejects_missing_header(self, env, monkeypatch):
        """Dev env with internal token configured must reject calls without the header."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "dev-internal-secret")
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        req = self._make_request()  # no token header
        with pytest.raises(HTTPException) as exc_info:
            require_internal_admin_gateway(req)
        assert exc_info.value.status_code == 403, (
            f"FG_ENV={env!r} with FG_INTERNAL_AUTH_SECRET configured must enforce "
            "the internal token requirement. Silent bypass hides auth drift."
        )

    @pytest.mark.parametrize("env", ["dev", "test", "development", "local"])
    def test_dev_with_configured_token_rejects_wrong_token(self, env, monkeypatch):
        """Dev env with internal token configured must reject wrong token values."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "dev-internal-secret")
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        from fastapi import HTTPException

        from api.admin import require_internal_admin_gateway

        req = self._make_request(token_header="wrong-token")
        with pytest.raises(HTTPException) as exc_info:
            require_internal_admin_gateway(req)
        assert exc_info.value.status_code == 403

    @pytest.mark.parametrize("env", ["dev", "test", "development", "local"])
    def test_dev_with_configured_token_accepts_correct_token(self, env, monkeypatch):
        """Dev env with internal token configured must accept the correct token."""
        monkeypatch.setenv("FG_ENV", env)
        monkeypatch.delenv("FG_ADMIN_GATEWAY_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "dev-internal-secret")
        monkeypatch.delenv("FG_INTERNAL_TOKEN", raising=False)
        from api.admin import require_internal_admin_gateway

        req = self._make_request(token_header="dev-internal-secret")
        # Must not raise
        require_internal_admin_gateway(req)
