from datetime import datetime, timezone

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


def test_key_tenant_resolved_from_credential_on_decisions(build_app):
    """
    R4.11: All keys have a bound tenant_id (eliminating the NULL-tenant concept).
    A request without ?tenant_id= uses the key's bound tenant and succeeds.
    """
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("decisions:read", tenant_id="tenant-test")

    resp = client.get("/decisions?limit=1", headers={"X-API-Key": key})
    assert resp.status_code in {200, 404}


def test_cross_tenant_key_denied_on_decisions(build_app):
    """
    R4.11 cross-tenant isolation: a key bound to tenant-test cannot access
    a different tenant's decisions even with an explicit ?tenant_id= override.
    """
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("decisions:read", tenant_id="tenant-test")

    resp = client.get(
        "/decisions?limit=1&tenant_id=other-tenant",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 403
