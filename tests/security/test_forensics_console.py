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
    chain_id: str | None = None,
) -> None:
    """Insert a modern security event row.

    chain_id defaults to tenant_id (modern row semantics).
    Pass chain_id='global' explicitly to simulate a legacy-migrated row.
    """
    import sqlite3
    from datetime import datetime, timezone

    created_at = datetime.now(timezone.utc).isoformat()
    entry_hash = str(uuid.uuid4())
    effective_chain_id = chain_id if chain_id is not None else (tenant_id or "global")
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
                effective_chain_id,
                "GENESIS",
                entry_hash,
            ),
        )
        con.commit()
    finally:
        con.close()


def _insert_legacy_event(
    db_path: str,
    *,
    tenant_id: str,
    event_type: str = "legacy_event",
    severity: str = "info",
    request_id: str | None = None,
) -> None:
    """Insert a legacy-migrated event: tenant_id is correct, chain_id='global'."""
    _insert_security_event(
        db_path,
        tenant_id=tenant_id,
        event_type=event_type,
        severity=severity,
        request_id=request_id,
        chain_id="global",
    )


def _insert_global_system_event(
    db_path: str,
    *,
    event_type: str = "system_startup",
) -> None:
    """Insert a system-level event with no tenant: tenant_id=NULL, chain_id='global'."""
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
                "info",
                None,  # no tenant
                None,
                "/system",
                "GET",
                1,
                None,
                "global",  # chain_id='global', tenant_id=NULL
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
    assert body["event_count"] == 0, f"Tenant A saw tenant B trace events: {body}"
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
        _insert_security_event(
            fresh_db, tenant_id=tenant_a_id, event_type="auth_success"
        )

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


# ─── Legacy row visibility ────────────────────────────────────────────────────


def test_modern_rows_remain_tenant_scoped(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Modern chain-aware rows (chain_id == tenant_id) are scoped to the correct tenant."""
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, event_type="auth_success")
    _insert_security_event(fresh_db, tenant_id=tenant_b_id, event_type="auth_failure")

    r = client.get("/ui/forensics/events", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert body["events"][0]["event_type"] == "auth_success"


def test_legacy_rows_visible_to_correct_tenant(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Historical legacy rows (chain_id='global', real tenant_id) are returned for the owning tenant."""
    _insert_legacy_event(fresh_db, tenant_id=tenant_a_id, event_type="legacy_event")

    r = client.get("/ui/forensics/events", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] >= 1
    types = [e["event_type"] for e in body["events"]]
    assert "legacy_event" in types, f"Legacy event not returned: {body}"


def test_legacy_rows_invisible_cross_tenant(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Historical legacy rows for tenant B are never returned to tenant A."""
    _insert_legacy_event(fresh_db, tenant_id=tenant_b_id, event_type="legacy_b_event")

    r = client.get("/ui/forensics/events", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    for evt in body["events"]:
        assert evt["event_type"] != "legacy_b_event", (
            f"Tenant A saw tenant B legacy event: {evt}"
        )


def test_mixed_historical_and_modern_timeline(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Mixed legacy and modern rows for the same tenant both appear in the timeline."""
    _insert_security_event(fresh_db, tenant_id=tenant_a_id, event_type="modern_event")
    _insert_legacy_event(fresh_db, tenant_id=tenant_a_id, event_type="legacy_event")

    r = client.get("/ui/forensics/events", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2
    types = {e["event_type"] for e in body["events"]}
    assert "modern_event" in types
    assert "legacy_event" in types


def test_trace_includes_legacy_and_modern_rows(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Trace endpoint returns both legacy and modern rows for the same request_id."""
    rid = f"req-{uuid.uuid4().hex}"
    _insert_security_event(
        fresh_db, tenant_id=tenant_a_id, request_id=rid, event_type="modern_event"
    )
    _insert_legacy_event(
        fresh_db, tenant_id=tenant_a_id, request_id=rid, event_type="legacy_event"
    )

    r = client.get(
        f"/ui/forensics/trace/{rid}",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["event_count"] == 2
    assert body["trace_available"] is True
    types = {e["event_type"] for e in body["events"]}
    assert "modern_event" in types
    assert "legacy_event" in types


def test_export_includes_legacy_rows(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Export endpoint returns legacy rows for the owning tenant."""
    _insert_legacy_event(
        fresh_db, tenant_id=tenant_a_id, event_type="legacy_export_event"
    )

    r = client.get("/ui/forensics/events/export", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("export_safe") is True
    types = [e["event_type"] for e in body.get("events", [])]
    assert "legacy_export_event" in types, f"Legacy event missing from export: {body}"


def test_global_system_events_do_not_leak_to_tenants(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """System-level events (tenant_id=NULL, chain_id='global') are never returned to any tenant."""
    _insert_global_system_event(fresh_db, event_type="system_startup")

    r = client.get("/ui/forensics/events", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    for evt in body["events"]:
        assert evt["event_type"] != "system_startup", (
            f"System-level event leaked to tenant: {evt}"
        )


def test_pagination_count_with_mixed_rows(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """total count and pagination work correctly when rows include both legacy and modern entries."""
    for _ in range(3):
        _insert_security_event(
            fresh_db, tenant_id=tenant_a_id, event_type="modern_event"
        )
    for _ in range(2):
        _insert_legacy_event(fresh_db, tenant_id=tenant_a_id, event_type="legacy_event")

    r = client.get(
        "/ui/forensics/events?limit=3&offset=0",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 5
    assert len(body["events"]) == 3

    r2 = client.get(
        "/ui/forensics/events?limit=3&offset=3",
        headers=_auth_headers(tenant_a_key),
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert len(body2["events"]) == 2


def test_filters_apply_correctly_with_mixed_rows(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """event_type and severity filters work correctly across both legacy and modern row generations."""
    _insert_security_event(
        fresh_db, tenant_id=tenant_a_id, event_type="auth_success", severity="info"
    )
    _insert_legacy_event(
        fresh_db, tenant_id=tenant_a_id, event_type="auth_success", severity="critical"
    )
    _insert_security_event(
        fresh_db, tenant_id=tenant_a_id, event_type="key_created", severity="info"
    )

    r = client.get(
        "/ui/forensics/events?event_type=auth_success",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2
    assert all(e["event_type"] == "auth_success" for e in body["events"])

    r2 = client.get(
        "/ui/forensics/events?severity=critical",
        headers=_auth_headers(tenant_a_key),
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert body2["total"] == 1
    assert body2["events"][0]["severity"] == "critical"
