from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _auth_headers_from_key(raw_key: str) -> dict[str, str]:
    # FrostGate Core tests use X-API-Key style auth.
    return {"X-API-Key": raw_key}


def _insert_decision_record_sqlite(
    db_path: str, *, tenant_id: str, event_id: str
) -> None:
    """
    Insert a DecisionRecord row using sqlite directly.
    Avoids needing SQLAlchemy session fixtures.
    """
    import sqlite3

    created_at = _utcnow().isoformat()

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO decision_records
                (tenant_id, event_id, created_at, request_json, response_json, threat_level, chain_hash, prev_hash)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                event_id,
                created_at,
                '{"hello":"world"}',
                '{"ok":true}',
                "low",
                "abc",
                "def",
            ),
        )
        con.commit()
    finally:
        con.close()


@pytest.fixture(autouse=True)
def _enable_forensics(monkeypatch):
    # Turn on forensics by default for these tests
    monkeypatch.setenv("FG_FORENSICS_ENABLED", "1")
    yield


@pytest.fixture
def tenant_a_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def tenant_b_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def forensics_read_key(tenant_a_id: str) -> str:
    """
    Mint a key with the correct scope.
    Prefer tenant-bound key if supported by mint_key().
    """
    try:
        return mint_key("forensics:read", ttl_seconds=86400, tenant_id=tenant_a_id)  # type: ignore[arg-type]
    except TypeError:
        return mint_key("forensics:read", ttl_seconds=86400)


@pytest.fixture
def forensics_verify_key(tenant_a_id: str) -> str:
    try:
        return mint_key("forensics:verify", ttl_seconds=86400, tenant_id=tenant_a_id)  # type: ignore[arg-type]
    except TypeError:
        return mint_key("forensics:verify", ttl_seconds=86400)


@pytest.fixture
def app(build_app, fresh_db: str):
    """
    IMPORTANT: bind the FastAPI app to the same sqlite file that fresh_db inserts into.
    Otherwise the test writes to one DB file and the API reads from another.
    """
    return build_app(sqlite_path=fresh_db)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def tenant_b_event_id(fresh_db: str, tenant_b_id: str) -> str:
    event_id = f"evt-{uuid.uuid4().hex}"
    _insert_decision_record_sqlite(fresh_db, tenant_id=tenant_b_id, event_id=event_id)
    return event_id


def test_forensics_snapshot_cross_tenant_blocked(
    client: TestClient, forensics_read_key: str, tenant_b_event_id: str
):
    r = client.get(
        f"/forensics/snapshot/{tenant_b_event_id}",
        headers=_auth_headers_from_key(forensics_read_key),
    )
    assert r.status_code == 404, f"Expected 404, got {r.status_code}, body={r.text!r}"


def test_forensics_audit_trail_cross_tenant_blocked(
    client: TestClient, forensics_read_key: str, tenant_b_event_id: str
):
    r = client.get(
        f"/forensics/audit_trail/{tenant_b_event_id}",
        headers=_auth_headers_from_key(forensics_read_key),
    )
    assert r.status_code == 404, f"Expected 404, got {r.status_code}, body={r.text!r}"


def test_forensics_chain_verify_is_bound_to_auth_tenant(
    client: TestClient, forensics_verify_key: str, tenant_b_id: str
):
    # Route should NOT accept tenant_id from client input. Remove params entirely.
    r = client.get(
        "/forensics/chain/verify",
        params={"limit": 10},  # only allow non-tenant filtering controls
        headers=_auth_headers_from_key(forensics_verify_key),
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}, body={r.text!r}"

    # If response includes tenant_id, enforce it isn't attacker-supplied.
    try:
        body = r.json()
    except Exception:
        pytest.fail(f"Expected JSON response, got: {r.text!r}")

    if isinstance(body, dict) and "tenant_id" in body:
        assert body["tenant_id"] != tenant_b_id, (
            "Regression: verify_chain used client-supplied tenant_id"
        )


def test_forensics_disabled_returns_404(
    client: TestClient, monkeypatch, forensics_read_key: str, tenant_b_event_id: str
):
    monkeypatch.setenv("FG_FORENSICS_ENABLED", "0")

    r1 = client.get(
        f"/forensics/snapshot/{tenant_b_event_id}",
        headers=_auth_headers_from_key(forensics_read_key),
    )
    assert r1.status_code == 404

    r2 = client.get(
        f"/forensics/audit_trail/{tenant_b_event_id}",
        headers=_auth_headers_from_key(forensics_read_key),
    )
    assert r2.status_code == 404

    r3 = client.get(
        "/forensics/chain/verify",
        headers=_auth_headers_from_key(forensics_read_key),
    )
    assert r3.status_code == 404
