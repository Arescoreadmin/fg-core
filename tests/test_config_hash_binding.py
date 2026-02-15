from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.config_versioning import create_config_version
from api.db import get_engine


def _create_config_hash(
    db: Session, tenant_id: str, payload: dict, set_active: bool = True
) -> str:
    v = create_config_version(
        db,
        tenant_id=tenant_id,
        config_payload=payload,
        created_by="test",
        set_active=set_active,
    )
    db.commit()
    return v.config_hash


def test_decision_includes_config_hash_on_ingest_and_read(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key("ingest:write", "decisions:read", tenant_id="tenant-bind")

    engine = get_engine()
    with Session(engine) as db:
        h = _create_config_hash(db, "tenant-bind", {"mode": "a"})

    payload = {
        "tenant_id": "tenant-bind",
        "source": "pytest",
        "event_id": "evt-bind-1",
        "event_type": "auth.test",
        "payload": {"x": 1},
    }

    r = client.post(
        "/ingest",
        json=payload,
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-bind"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["config_hash"] == h
    assert body["decision"]["config_hash"] == h

    rd = client.get(
        "/decisions", params={"tenant_id": "tenant-bind"}, headers={"X-API-Key": key}
    )
    assert rd.status_code == 200, rd.text
    assert rd.json()["items"][0]["config_hash"] == h


def test_atomic_config_selection_explicit_hash_beats_active_pointer_change(
    build_app, monkeypatch
):
    app = build_app()
    client = TestClient(app)
    key = mint_key("ingest:write", "decisions:read", tenant_id="tenant-atomic")

    engine = get_engine()
    with Session(engine) as db:
        hash_a = _create_config_hash(
            db, "tenant-atomic", {"version": "A"}, set_active=True
        )
        hash_b = _create_config_hash(
            db, "tenant-atomic", {"version": "B"}, set_active=True
        )

    from api import ingest as ingest_module

    orig_emit = ingest_module.emit_decision_evidence

    def _flip_active(db: Session, rec):
        db.execute(
            text(
                "UPDATE tenant_config_active SET active_config_hash = :h WHERE tenant_id = :t"
            ),
            {"h": hash_b, "t": "tenant-atomic"},
        )
        return orig_emit(db, rec)

    monkeypatch.setattr(ingest_module, "emit_decision_evidence", _flip_active)

    r = client.post(
        "/ingest",
        json={
            "tenant_id": "tenant-atomic",
            "source": "pytest",
            "event_id": "evt-atomic-1",
            "event_type": "auth.test",
            "payload": {},
        },
        headers={
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-atomic",
            "X-Config-Hash": hash_a,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["config_hash"] == hash_a


def test_unknown_config_hash_fails_closed(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-unknown-hash")

    r = client.post(
        "/ingest",
        json={
            "tenant_id": "tenant-unknown-hash",
            "source": "pytest",
            "event_id": "evt-unknown-1",
            "event_type": "auth.test",
            "payload": {},
        },
        headers={
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-unknown-hash",
            "X-Config-Hash": "deadbeef",
        },
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"]["code"] == "CONFIG_HASH_NOT_FOUND"


def test_unknown_config_hash_error_contract(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-err-contract")

    r = client.post(
        "/ingest",
        json={
            "tenant_id": "tenant-err-contract",
            "source": "pytest",
            "event_id": "evt-err-1",
            "event_type": "auth.test",
            "payload": {},
        },
        headers={
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-err-contract",
            "X-Config-Hash": "deadbeef",
        },
    )
    assert r.status_code == 400
    body = r.json()
    assert body == {
        "detail": {
            "error": {
                "code": "CONFIG_HASH_NOT_FOUND",
                "message": "requested config hash was not found",
                "details": {"config_hash": "deadbeef"},
            }
        }
    }


def test_active_config_missing_error_contract(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-missing-active")

    engine = get_engine()
    with Session(engine) as db:
        db.execute(
            text("DELETE FROM tenant_config_active WHERE tenant_id=:t"),
            {"t": "tenant-missing-active"},
        )
        db.commit()

    r = client.post(
        "/ingest",
        json={
            "tenant_id": "tenant-missing-active",
            "source": "pytest",
            "event_id": "evt-err-2",
            "event_type": "auth.test",
            "payload": {},
        },
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-missing-active"},
    )
    assert r.status_code == 503
    assert r.json() == {
        "detail": {
            "error": {
                "code": "CONFIG_ACTIVE_MISSING",
                "message": "active tenant config is missing",
            }
        }
    }


def test_cross_tenant_config_hash_isolation(build_app):
    app = build_app()
    client = TestClient(app)

    key1 = mint_key("ingest:write", tenant_id="tenant-one")
    key2 = mint_key("ingest:write", tenant_id="tenant-two")

    engine = get_engine()
    with Session(engine) as db:
        hash1 = _create_config_hash(db, "tenant-one", {"alpha": 1}, set_active=True)

    r = client.post(
        "/ingest",
        json={
            "tenant_id": "tenant-two",
            "source": "pytest",
            "event_id": "evt-cross-1",
            "event_type": "auth.test",
            "payload": {},
        },
        headers={
            "X-API-Key": key2,
            "X-Tenant-Id": "tenant-two",
            "X-Config-Hash": hash1,
        },
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"]["code"] == "CONFIG_HASH_NOT_FOUND"

    # sanity: owner tenant can use it
    ok = client.post(
        "/ingest",
        json={
            "tenant_id": "tenant-one",
            "source": "pytest",
            "event_id": "evt-cross-2",
            "event_type": "auth.test",
            "payload": {},
        },
        headers={
            "X-API-Key": key1,
            "X-Tenant-Id": "tenant-one",
            "X-Config-Hash": hash1,
        },
    )
    assert ok.status_code == 200, ok.text


def test_audit_record_links_decision_to_config_hash(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key(
        "ingest:write",
        "forensics:read",
        tenant_id="tenant-audit-link",
    )

    engine = get_engine()
    with Session(engine) as db:
        expected_hash = _create_config_hash(db, "tenant-audit-link", {"k": "v"})

    event_id = f"evt-audit-{uuid.uuid4().hex}"
    r = client.post(
        "/ingest",
        json={
            "tenant_id": "tenant-audit-link",
            "source": "pytest",
            "event_id": event_id,
            "event_type": "auth.test",
            "payload": {},
        },
        headers={
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-audit-link",
            "X-Config-Hash": expected_hash,
        },
    )
    assert r.status_code == 200, r.text

    with Session(engine) as db:
        dec_hash = db.execute(
            text(
                "SELECT config_hash FROM decisions WHERE tenant_id=:t AND event_id=:e"
            ),
            {"t": "tenant-audit-link", "e": event_id},
        ).scalar_one()

    audit_resp = client.get(
        f"/forensics/audit_trail/{event_id}",
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-audit-link"},
    )
    assert audit_resp.status_code == 200, audit_resp.text
    assert dec_hash == expected_hash
    assert audit_resp.json()["config_hash"] == dec_hash
