from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _defend_payload(tenant_id: str | None = None) -> dict:
    payload = {
        "event_type": "auth.bruteforce",
        "source": "unit-test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"src_ip": "1.2.3.4", "failed_auths": 6},
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    return payload


def test_tenant_mismatch_rejected_feed(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("feed:read", tenant_id="tenant-a")

    resp = client.get(
        "/feed/live?limit=1&tenant_id=tenant-b", headers={"X-API-Key": key}
    )

    assert resp.status_code == 403
    assert resp.status_code == 403
    assert resp.json()["detail"].lower() in {"forbidden", "tenant mismatch"}


def test_scoped_key_clamps_defend(build_app, monkeypatch):
    # Disable rate limiting to isolate tenant mismatch test
    monkeypatch.setenv("FG_RL_ENABLED", "0")
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("defend:write", tenant_id="tenant-a")

    resp = client.post(
        "/defend",
        headers={"X-API-Key": key},
        json=_defend_payload(tenant_id="tenant-b"),
    )

    assert resp.status_code == 403
    assert resp.status_code == 403
    assert resp.json()["detail"].lower() in {"forbidden", "tenant mismatch"}


@pytest.mark.parametrize("tenant_id", [None, ""])
def test_unscoped_key_denied_on_decisions_without_bound_tenant(build_app, tenant_id):
    """
    P0 Security Fix: Unscoped keys MUST provide tenant_id.

    Previously, unscoped keys would default to "unknown" tenant.
    After the 2026-01-31 security audit fix, tenant_id is required
    for all data access endpoints to prevent cross-tenant data exposure.
    """
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("decisions:read")  # Unscoped key

    decisions = client.get("/decisions?limit=1", headers={"X-API-Key": key})
    assert decisions.status_code == 400


def test_unscoped_key_with_explicit_tenant_denied(build_app):
    """
    Unscoped keys with explicit valid tenant_id should work.
    """
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("decisions:read")

    decisions = client.get(
        "/decisions?limit=1&tenant_id=test-tenant",
        headers={"X-API-Key": key},
    )
    assert decisions.status_code == 400
