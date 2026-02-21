"""
Regression tests for FG-AUD-006.

FG-AUD-006: AuthGateMiddleware previously passed ALL unregistered routes through
without authentication (fail-open).  The gate now requires authentication even
for unregistered paths, so a misconfigured / lazily-loaded router cannot silently
bypass auth.

These tests prove:
  1. A request to an unregistered path without an API key receives 401.
  2. A request to an unregistered path with an invalid key receives 401.
  3. A request to a public path still bypasses auth (regression guard).
  4. The gate stamp reflects the correct gate value.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient

from api.middleware.auth_gate import AuthGateMiddleware, AuthGateConfig
from api.auth_scopes.definitions import AuthResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(*, require_status_auth=None):
    """Build a minimal Starlette app with only a /known route registered."""
    app = Starlette()
    app.state.auth_enabled = True

    @app.route("/known")
    async def known_route(request: Request):
        return PlainTextResponse("ok")

    if require_status_auth is None:
        def _noop(req): pass
        require_status_auth = _noop

    app.add_middleware(AuthGateMiddleware, require_status_auth=require_status_auth)
    return app


def _make_verify_always_valid(monkeypatch):
    """Monkeypatch verify_api_key_detailed to always return a valid result."""
    monkeypatch.setattr(
        "api.middleware.auth_gate.verify_api_key_detailed",
        lambda **kwargs: AuthResult(valid=True, reason="valid", tenant_id="t1"),
    )


def _make_verify_always_invalid(monkeypatch):
    monkeypatch.setattr(
        "api.middleware.auth_gate.verify_api_key_detailed",
        lambda **kwargs: AuthResult(valid=False, reason="key_not_found"),
    )


# ---------------------------------------------------------------------------
# FG-AUD-006 tests
# ---------------------------------------------------------------------------

class TestAuthGateFailClosed:
    """AuthGateMiddleware must be fail-closed for unregistered routes."""

    def test_unregistered_route_without_key_gets_401(self, monkeypatch):
        """An unregistered path with no API key must return 401 (not pass through)."""
        _make_verify_always_invalid(monkeypatch)
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/unregistered-path-that-does-not-exist")
        assert resp.status_code == 401, (
            "Unregistered route without API key must return 401, not pass through unauthenticated. "
            f"Got {resp.status_code}"
        )

    def test_unregistered_route_with_invalid_key_gets_401(self, monkeypatch):
        """An unregistered path with a bad API key must return 401."""
        _make_verify_always_invalid(monkeypatch)
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/unregistered-path", headers={"X-API-Key": "fg_bad_key"})
        assert resp.status_code == 401

    def test_unregistered_route_with_valid_key_passes_through(self, monkeypatch):
        """An unregistered path with a VALID API key proceeds (FastAPI returns 404)."""
        _make_verify_always_valid(monkeypatch)
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/unregistered-path", headers={"X-API-Key": "fg_valid_key"})
        # Auth gate should pass through with stamp "unmatched_authed"; FastAPI returns 404.
        assert resp.status_code == 404
        assert resp.headers.get("x-fg-gate") == "unmatched_authed"

    def test_public_path_bypasses_auth_gate(self, monkeypatch):
        """Public paths (e.g. /health) must still bypass authentication."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/health")
        # Gate should stamp 'public' regardless of key presence.
        assert resp.headers.get("x-fg-gate") == "public"

    def test_gate_stamp_unmatched_authed_set_correctly(self, monkeypatch):
        """Confirm gate header is 'unmatched_authed' for authenticated unregistered route."""
        _make_verify_always_valid(monkeypatch)
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/some/unknown/path", headers={"X-API-Key": "fg_valid_key"})
        gate = resp.headers.get("x-fg-gate", "")
        assert gate == "unmatched_authed", (
            f"Expected gate=unmatched_authed for authenticated unregistered route, got {gate!r}"
        )

    def test_old_failopen_gate_value_absent(self, monkeypatch):
        """The old 'unmatched' (fail-open) gate value must never appear in responses."""
        _make_verify_always_valid(monkeypatch)
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/totally/unknown", headers={"X-API-Key": "fg_valid_key"})
        gate = resp.headers.get("x-fg-gate", "")
        assert gate != "unmatched", (
            "Gate value 'unmatched' indicates fail-open auth bypass — must not appear. "
            f"Got gate={gate!r}"
        )
