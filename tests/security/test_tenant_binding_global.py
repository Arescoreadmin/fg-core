from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _insert_decision(db_path: str, tenant_id: str, event_id: str) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO decisions (
                tenant_id, source, event_id, event_type, threat_level,
                anomaly_score, ai_adversarial_score, pq_fallback, config_hash
            ) VALUES (?, 'test', ?, 'auth.bruteforce', 'low', 0.1, 0.1, 0, 'cfg')
            """,
            (tenant_id, event_id),
        )
        con.commit()
    finally:
        con.close()


@pytest.fixture
def client(build_app, fresh_db: str) -> TestClient:
    app = build_app(sqlite_path=fresh_db)
    return TestClient(app)


def test_auth_modes_for_representative_tenant_endpoints(client: TestClient):
    scoped_key = mint_key(
        "decisions:read",
        "ingest:write",
        "keys:admin",
        "admin:read",
        "forensics:verify",
        tenant_id="tenant-a",
    )

    cases = [
        ("GET", "/decisions?limit=1", None),
        (
            "POST",
            "/ingest",
            {
                "event_id": "evt-auth-mode",
                "event_type": "auth.bruteforce",
                "source": "agent",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {},
            },
        ),
        ("GET", "/keys", None),
        ("GET", "/admin/tenants/tenant-a/usage", None),
        ("GET", "/forensics/chain/verify?limit=5", None),
    ]

    for method, path, payload in cases:
        missing = client.request(method, path, json=payload)
        assert missing.status_code == 401
        gate_missing = missing.headers.get("x-fg-gate")
        if gate_missing and gate_missing != "public":
            assert gate_missing == "denied_missing_key"

        invalid = client.request(
            method, path, headers={"X-API-Key": "not-a-key"}, json=payload
        )
        assert invalid.status_code == 401
        gate_invalid = invalid.headers.get("x-fg-gate")
        if gate_invalid and gate_invalid != "public":
            assert gate_invalid == "denied_invalid_key"

        ok = client.request(
            method, path, headers={"X-API-Key": scoped_key}, json=payload
        )
        assert ok.status_code != 401, (method, path, ok.status_code, ok.text)


def test_cross_tenant_overrides_are_denied(client: TestClient, fresh_db: str):
    _insert_decision(fresh_db, tenant_id="tenant-a", event_id="evt-a")
    _insert_decision(fresh_db, tenant_id="tenant-b", event_id="evt-b")

    key_a = mint_key(
        "decisions:read",
        "ingest:write",
        "keys:admin",
        "admin:read",
        tenant_id="tenant-a",
    )

    decisions = client.get(
        "/decisions?tenant_id=tenant-b&limit=5",
        headers={"X-API-Key": key_a},
    )
    assert decisions.status_code == 403

    keys = client.get("/keys?tenant_id=tenant-b", headers={"X-API-Key": key_a})
    assert keys.status_code == 403

    ingest = client.post(
        "/ingest",
        headers={"X-API-Key": key_a},
        json={
            "tenant_id": "tenant-b",
            "event_id": "evt-cross",
            "event_type": "auth.bruteforce",
            "source": "agent",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {},
        },
    )
    assert ingest.status_code == 403

    admin = client.get(
        "/admin/tenants/tenant-b/usage",
        headers={"X-API-Key": key_a},
    )
    assert admin.status_code == 403


def test_prod_like_redaction_hides_tenant_enumeration(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_DB_URL", "postgresql://local/test")
    monkeypatch.setenv("FG_AUTH_DB_FAIL_OPEN", "0")
    key = mint_key("decisions:read", tenant_id="tenant-a")
    supplied = "tenant-b-secret"

    resp = client.get(
        f"/decisions?tenant_id={supplied}&limit=1",
        headers={"X-API-Key": key},
    )

    assert resp.status_code == 403
    body = resp.text.lower()
    for forbidden in (
        "known tenant",
        "unknown tenant",
        "tenant_id is required",
        supplied.lower(),
    ):
        assert forbidden not in body


def test_decisions_works_without_client_tenant_id_when_key_is_scoped(
    client: TestClient, fresh_db: str
):
    _insert_decision(fresh_db, tenant_id="tenant-a", event_id="evt-only-a")
    _insert_decision(fresh_db, tenant_id="tenant-b", event_id="evt-only-b")

    key = mint_key("decisions:read", tenant_id="tenant-a")
    resp = client.get("/decisions?limit=20", headers={"X-API-Key": key})

    assert resp.status_code == 200
    body = resp.json()
    tenants = {item.get("tenant_id") for item in body.get("items", [])}
    assert tenants <= {"tenant-a"}
