"""Isolated customer-zero app — L14-CUSTOMER-ZERO-E2E-001.

Reuses the shared ``build_app`` fixture (per-test SQLite file, FG_ENV=test)
with the admin plane enabled and the tenant registry redirected into the
test's tmp directory.  Nothing here can reach a production database, send a
message, charge a billing account, or open a network connection.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.test_customer_zero_e2e import _northstar as N


class Platform:
    """Real routes, real authorities; personas are canonical role-bound keys."""

    def __init__(self, app: Any, platform_key: str) -> None:
        self.app = app
        self.platform_key = platform_key
        self.keys: dict[str, str] = {}
        self.credential_ids: dict[str, str] = {}

    def client(self, persona: str | None = None, **headers: str) -> TestClient:
        h = dict(headers)
        if persona is not None:
            h["X-API-Key"] = self.keys[persona]
        return TestClient(self.app, headers=h)

    def admin(self, tenant_id: str | None = None) -> TestClient:
        """Platform-admin client.  Unscoped (global key) only for tenant
        creation; tenant-scoped operations use a scoped admin credential so
        admin audit records carry actor and scope (FG-AUDIT-ADMIN-001)."""
        if tenant_id is None:
            return TestClient(self.app, headers={"X-API-Key": self.platform_key})
        from api.auth_scopes import mint_key

        key = mint_key("admin:read", "admin:write", tenant_id=tenant_id)
        return TestClient(self.app, headers={"X-API-Key": key})


@pytest.fixture()
def platform(build_app, monkeypatch, tmp_path):
    import tools.tenants.registry as registry

    monkeypatch.setattr(registry, "REGISTRY_PATH", tmp_path / "tenants.json")
    monkeypatch.setenv("FG_ADMIN_ENABLED", "1")
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", N.SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    return Platform(app, os.environ["FG_API_KEY"])
