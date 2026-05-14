from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _auth_headers(raw_key: str) -> dict[str, str]:
    return {"X-API-Key": raw_key}


def _insert_security_event(
    db_path: str,
    *,
    tenant_id: str,
    event_type: str = "auth_success",
    severity: str = "info",
    request_id: str | None = None,
) -> None:
    import sqlite3
    from datetime import datetime, timezone

    created_at = datetime.now(timezone.utc).isoformat()
    entry_hash = str(uuid.uuid4())
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO security_audit_log
                (created_at, event_type, event_category, severity, tenant_id, request_id,
                 request_path, request_method, success, reason, chain_id, prev_hash, entry_hash)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                event_type,
                "security",
                severity,
                tenant_id,
                request_id,
                "/test/path",
                "GET",
                1,
                None,
                tenant_id or "global",
                "GENESIS",
                entry_hash,
            ),
        )
        con.commit()
    finally:
        con.close()


@pytest.fixture
def tenant_a_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def tenant_b_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def app(build_app, fresh_db: str):
    return build_app(sqlite_path=fresh_db)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def tenant_a_key(tenant_a_id: str, fresh_db: str) -> str:
    """Mint after fresh_db sets FG_SQLITE_PATH so the key lands in the test db."""
    try:
        return mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        return mint_key("ui:read", ttl_seconds=86400)


# ─── Tenant isolation: events ─────────────────────────────────────────────────

def test_events_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Tenant A cannot see tenant B events via /ui/forensics/events."""
    _insert_security_event(fresh_db, tenant_id=tenant_b_id, event_type="auth_failure")
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, event_type="auth_success")

    r = client.get("/ui/forensics/events", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert "events" in body
    for evt in body["events"]:
        assert evt.get("event_type") != "auth_failure", (
            f"Tenant A saw a tenant B event: {evt}"
        )


# ─── Tenant isolation: trace ──────────────────────────────────────────────────

def test_trace_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Tenant A cannot see tenant B events via /ui/forensics/trace/{request_id}."""
    shared_request_id = f"req-{uuid.uuid4().hex}"
    _insert_security_event(
        fresh_db,
        tenant_id=tenant_b_id,
        request_id=shared_request_id,
    )

    r = client.get(
        f"/ui/forensics/trace/{shared_request_id}",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["event_count"] == 0, (
        f"Tenant A saw tenant B trace events: {body}"
    )
    assert body["trace_available"] is False


# ─── Tenant isolation: export ─────────────────────────────────────────────────

def test_export_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Export for tenant A excludes tenant B events."""
    _insert_security_event(fresh_db, tenant_id=tenant_b_id, event_type="key_revoked")
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, event_type="key_created")

    r = client.get("/ui/forensics/events/export", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("export_safe") is True
    for evt in body.get("events", []):
        assert evt.get("event_type") != "key_revoked", (
            f"Tenant A export contained a tenant B event: {evt}"
        )


# ─── Auth required ────────────────────────────────────────────────────────────

def test_events_requires_auth(client: TestClient) -> None:
    """Unauthenticated request returns 401 or 403."""
    r = client.get("/ui/forensics/events")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


# ─── Scope check ─────────────────────────────────────────────────────────────

def test_events_wrong_scope_rejected(
    client: TestClient,
    tenant_a_id: str,
) -> None:
    """Wrong scope returns 401 or 403."""
    try:
        wrong_key = mint_key("forensics:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        wrong_key = mint_key("forensics:read", ttl_seconds=86400)

    r = client.get("/ui/forensics/events", headers=_auth_headers(wrong_key))
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


# ─── Pagination ───────────────────────────────────────────────────────────────

def test_pagination_limit_offset(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """limit and offset parameters work correctly."""
    for i in range(5):
        _insert_security_event(fresh_db, tenant_id=tenant_a_id, event_type="auth_success")

    r1 = client.get(
        "/ui/forensics/events?limit=2&offset=0",
        headers=_auth_headers(tenant_a_key),
    )
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert len(body1["events"]) == 2
    assert body1["total"] == 5
    assert body1["limit"] == 2
    assert body1["offset"] == 0

    r2 = client.get(
        "/ui/forensics/events?limit=2&offset=2",
        headers=_auth_headers(tenant_a_key),
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert len(body2["events"]) == 2
    assert body2["offset"] == 2


# ─── Filter: event_type ───────────────────────────────────────────────────────

def test_filter_event_type(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """event_type filter returns only matching events."""
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, event_type="auth_success")
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, event_type="key_created")

    r = client.get(
        "/ui/forensics/events?event_type=auth_success",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(e["event_type"] == "auth_success" for e in body["events"]), (
        f"Unexpected events: {body['events']}"
    )


# ─── Filter: severity ─────────────────────────────────────────────────────────

def test_filter_severity(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """severity filter returns only matching events."""
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, severity="info")
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, severity="critical")

    r = client.get(
        "/ui/forensics/events?severity=critical",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(e["severity"] == "critical" for e in body["events"]), (
        f"Unexpected events: {body['events']}"
    )


# ─── Invalid request_id validation ───────────────────────────────────────────

def test_trace_invalid_request_id_too_long(
    client: TestClient,
    tenant_a_key: str,
) -> None:
    """request_id exceeding 64 chars returns 422."""
    too_long = "x" * 65
    r = client.get(
        f"/ui/forensics/trace/{too_long}",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"
