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
    assert resp.json()["detail"] == "Tenant mismatch"


def test_scoped_key_clamps_defend(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("defend:write", tenant_id="tenant-a")

    resp = client.post(
        "/defend",
        headers={"X-API-Key": key},
        json=_defend_payload(tenant_id="tenant-b"),
    )

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Tenant mismatch"


@pytest.mark.parametrize("tenant_id", [None, ""])
def test_unscoped_key_defaults_unknown_tenant(build_app, tenant_id):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("defend:write")

    resp = client.post(
        "/defend",
        headers={"X-API-Key": key},
        json=_defend_payload(tenant_id=tenant_id),
    )

    assert resp.status_code == 200

    decisions = client.get("/decisions?limit=1", headers={"X-API-Key": key})
    assert decisions.status_code == 200
    items = decisions.json()["items"]
    assert items
    assert items[0]["tenant_id"] == "unknown"
