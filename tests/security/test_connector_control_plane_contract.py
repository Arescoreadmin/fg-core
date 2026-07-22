"""Contract assertions: connector control plane revoke API behavioral guarantees.

Anchors the contract that the connector revoke endpoint is idempotent,
returns a stable response shape, and enforces admin:write authorization.
These invariants must hold regardless of whether canonical tenant_credentials
records exist (pre- and post-migration 0162).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from tests.test_auth import build_app


def _client() -> TestClient:
    app = build_app(auth_enabled=True)
    return TestClient(app)


def test_revoke_response_shape() -> None:
    """POST /admin/connectors/{id}/revoke returns {"ok": true}."""
    with _client() as client:
        key = mint_key("admin:write", ttl_seconds=3600, tenant_id="tenant-a")
        resp = client.post(
            "/admin/connectors/slack/revoke",
            headers={"x-api-key": key, "Idempotency-Key": "idem-contract-shape-1"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_revoke_is_idempotent() -> None:
    """Calling revoke twice on the same connector must not raise."""
    with _client() as client:
        key = mint_key("admin:write", ttl_seconds=3600, tenant_id="tenant-a")
        headers = {"x-api-key": key, "Idempotency-Key": "idem-contract-idemp-1"}
        r1 = client.post("/admin/connectors/slack/revoke", headers=headers)
        r2 = client.post("/admin/connectors/slack/revoke", headers=headers)
    assert r1.status_code == 200
    assert r1.json() == {"ok": True}
    assert r2.status_code == 200
    assert r2.json() == {"ok": True}


def test_revoke_requires_admin_write_scope() -> None:
    """Revoke must be rejected for API keys that lack admin:write."""
    with _client() as client:
        key = mint_key("admin:read", ttl_seconds=3600, tenant_id="tenant-a")
        resp = client.post(
            "/admin/connectors/slack/revoke",
            headers={"x-api-key": key},
        )
    assert resp.status_code in {401, 403}
