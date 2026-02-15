from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from api.auth_scopes import mint_key
from api.db import get_engine
from api.ingest import router as ingest_router


def _ensure_decisions_idempotency_index() -> None:
    engine = get_engine(sqlite_path=os.environ["FG_SQLITE_PATH"])
    session = sessionmaker(bind=engine, expire_on_commit=False, future=True)()
    try:
        session.execute(text("DELETE FROM decisions"))
        session.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS uq_decisions_tenant_event_id
                ON decisions(tenant_id, event_id)
                WHERE event_id IS NOT NULL
                """
            )
        )
        session.commit()
    finally:
        session.close()


def test_ingest_rejects_missing_event_id(build_app):
    app = build_app()
    app.include_router(ingest_router)
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-a")

    payload = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_type": "auth.bruteforce",
        "payload": {"failed_auths": 9, "src_ip": "203.0.113.12"},
    }

    resp = client.post(
        "/ingest",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-a",
        },
        json=payload,
    )
    assert resp.status_code == 400
    assert resp.json() == {
        "detail": {
            "error": {
                "code": "INGEST_EVENT_ID_REQUIRED",
                "message": "event_id is required",
            }
        }
    }


def test_ingest_rejects_invalid_event_id(build_app):
    app = build_app()
    app.include_router(ingest_router)
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-a")

    payload = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_id": "bad id with spaces",
        "event_type": "auth.bruteforce",
        "payload": {"failed_auths": 9, "src_ip": "203.0.113.12"},
    }

    resp = client.post(
        "/ingest",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-a",
        },
        json=payload,
    )
    assert resp.status_code == 400
    assert resp.json() == {
        "detail": {
            "error": {
                "code": "INGEST_EVENT_ID_INVALID",
                "message": "event_id contains invalid characters",
            }
        }
    }


def test_ingest_is_idempotent_for_same_tenant_and_event_id(build_app):
    app = build_app()
    _ensure_decisions_idempotency_index()
    app.include_router(ingest_router)
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-a")

    payload = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_id": "evt-fixed-001",
        "event_type": "auth.bruteforce",
        "payload": {"failed_auths": 9, "src_ip": "203.0.113.12"},
    }

    resp_1 = client.post(
        "/ingest",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-a",
        },
        json=payload,
    )
    assert resp_1.status_code == 200, resp_1.text
    assert resp_1.headers["Idempotent-Replay"] == "false"
    assert resp_1.headers["Idempotency-Key"] == "evt-fixed-001"

    resp_2 = client.post(
        "/ingest",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-a",
        },
        json=payload,
    )
    assert resp_2.status_code == 200, resp_2.text
    assert resp_2.json() == resp_1.json()
    assert resp_2.headers["Idempotent-Replay"] == "true"
    assert resp_2.headers["Idempotency-Key"] == "evt-fixed-001"

    engine = get_engine(sqlite_path=os.environ["FG_SQLITE_PATH"])
    session = sessionmaker(bind=engine, expire_on_commit=False, future=True)()
    try:
        row_count = session.execute(
            text(
                """
                SELECT COUNT(*)
                FROM decisions
                WHERE tenant_id = :tenant_id AND event_id = :event_id
                """
            ),
            {"tenant_id": "tenant-a", "event_id": "evt-fixed-001"},
        ).scalar_one()
        assert row_count == 1
    finally:
        session.close()


def test_ingest_same_event_id_allowed_for_different_tenants(build_app):
    app = build_app()
    _ensure_decisions_idempotency_index()
    app.include_router(ingest_router)
    client = TestClient(app)

    key_a = mint_key("ingest:write", tenant_id="tenant-a")
    key_b = mint_key("ingest:write", tenant_id="tenant-b")

    payload_a = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_id": "evt-shared",
        "event_type": "auth.bruteforce",
        "payload": {"failed_auths": 9, "src_ip": "203.0.113.12"},
    }
    payload_b = {
        "tenant_id": "tenant-b",
        "source": "unit-test",
        "event_id": "evt-shared",
        "event_type": "auth.bruteforce",
        "payload": {"failed_auths": 4, "src_ip": "203.0.113.13"},
    }

    resp_a = client.post(
        "/ingest",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key_a,
            "X-Tenant-Id": "tenant-a",
        },
        json=payload_a,
    )
    assert resp_a.status_code == 200, resp_a.text

    resp_b = client.post(
        "/ingest",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key_b,
            "X-Tenant-Id": "tenant-b",
        },
        json=payload_b,
    )
    assert resp_b.status_code == 200, resp_b.text

    engine = get_engine(sqlite_path=os.environ["FG_SQLITE_PATH"])
    session = sessionmaker(bind=engine, expire_on_commit=False, future=True)()
    try:
        row_count = session.execute(
            text(
                """
                SELECT COUNT(*)
                FROM decisions
                WHERE event_id = :event_id
                """
            ),
            {"event_id": "evt-shared"},
        ).scalar_one()
        assert row_count == 2
    finally:
        session.close()


def test_ingest_concurrent_same_event_id_is_single_row(build_app):
    app = build_app()
    _ensure_decisions_idempotency_index()
    app.include_router(ingest_router)
    key = mint_key("ingest:write", tenant_id="tenant-a")
    payload = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_id": "evt-concurrency-001",
        "event_type": "auth.bruteforce",
        "payload": {"failed_auths": 9, "src_ip": "203.0.113.12"},
    }

    engine = get_engine(sqlite_path=os.environ["FG_SQLITE_PATH"])

    def _send() -> tuple[int, dict, dict[str, str]]:
        with TestClient(app) as c:
            r = c.post(
                "/ingest",
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": key,
                    "X-Tenant-Id": "tenant-a",
                },
                json=payload,
            )
            return r.status_code, r.json(), dict(r.headers)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: _send(), range(8)))

    statuses = {status for status, _, _ in results}
    assert statuses == {200}

    bodies = [body for _, body, _ in results]
    assert all(body == bodies[0] for body in bodies)

    assert sum(h.get("idempotent-replay") == "false" for _, _, h in results) == 1
    assert sum(h.get("idempotent-replay") == "true" for _, _, h in results) == 7

    session = sessionmaker(bind=engine, expire_on_commit=False, future=True)()
    try:
        row_count = session.execute(
            text(
                """
                SELECT COUNT(*)
                FROM decisions
                WHERE tenant_id = :tenant_id AND event_id = :event_id
                """
            ),
            {"tenant_id": "tenant-a", "event_id": "evt-concurrency-001"},
        ).scalar_one()
        assert row_count == 1
    finally:
        session.close()
