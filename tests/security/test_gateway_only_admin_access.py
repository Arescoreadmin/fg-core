"""
Task 2.2 — Enforce gateway-only access.

Regression tests proving:
A) Hosted profiles (prod/staging) reject direct /admin access without gateway token
B) Hosted profiles accept /admin access with valid gateway token
C) Non-hosted profiles do not enforce gateway token (dev/test convenience preserved)
D) require_internal_admin_gateway correctly classifies all hosted profiles
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
        """Gateway token must NOT be required in non-hosted profiles."""
        monkeypatch.setenv("FG_ENV", env)
        from api.admin import require_internal_admin_gateway

        req = self._make_request()
        # Must not raise — no enforcement in non-hosted profiles
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

        assert not is_production_env(), (
            f"FG_ENV={env!r} must NOT be a production env."
        )
