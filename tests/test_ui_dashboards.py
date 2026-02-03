from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import json

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import DecisionRecord


def _compute_chain_hash(prev_hash: str | None, payload: dict) -> str:
    import hashlib

    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(f"{prev_hash or ''}:{blob}".encode("utf-8")).hexdigest()


def _hash_payload(
    *,
    event_id: str,
    created_at: datetime,
    tenant_id: str,
    source: str,
    event_type: str,
    threat_level: str,
    rules_triggered: list[str],
) -> dict:
    created_at_iso = (
        created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return {
        "event_id": event_id,
        "created_at": created_at_iso,
        "tenant_id": tenant_id,
        "source": source,
        "event_type": event_type,
        "threat_level": threat_level,
        "rules_triggered": rules_triggered,
    }


def _seed_record(
    session: Session,
    tenant_id: str,
    event_id: str,
    created_at: datetime,
    prev_hash: str | None,
    tamper: bool = False,
) -> str:
    payload = _hash_payload(
        event_id=event_id,
        created_at=created_at,
        tenant_id=tenant_id,
        source="unit-test",
        event_type="auth.bruteforce",
        threat_level="low",
        rules_triggered=["rule-1"],
    )
    chain_hash = _compute_chain_hash(prev_hash, payload)
    if tamper:
        chain_hash = chain_hash[::-1]
    record = DecisionRecord(
        tenant_id=tenant_id,
        source="unit-test",
        event_id=event_id,
        event_type="auth.bruteforce",
        threat_level="low",
        anomaly_score=0.1,
        ai_adversarial_score=0.0,
        pq_fallback=False,
        rules_triggered_json=["rule-1"],
        decision_diff_json={"summary": "allow"},
        request_json={"event": "login"},
        response_json={"decision": "allow"},
        created_at=created_at,
        prev_hash=prev_hash,
        chain_hash=chain_hash,
    )
    session.add(record)
    return chain_hash


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def test_ui_dashboards_tenant_scoping(build_app, tmp_path):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key(
        "ui:read", "forensics:read", "controls:read", "audit:read", tenant_id="t1"
    )

    engine = get_engine()
    with Session(engine) as session:
        _seed_record(session, "t1", "evt-1", datetime.now(timezone.utc), None)
        _seed_record(session, "t2", "evt-2", datetime.now(timezone.utc), None)
        session.commit()

    ok = client.get("/ui/posture?tenant_id=t1", headers={"X-API-Key": key})
    assert ok.status_code == 200

    forbidden = client.get("/ui/posture?tenant_id=t2", headers={"X-API-Key": key})
    assert forbidden.status_code == 403

    list_ok = client.get("/ui/decisions?tenant_id=t1", headers={"X-API-Key": key})
    assert list_ok.status_code == 200

    list_forbidden = client.get(
        "/ui/decisions?tenant_id=t2", headers={"X-API-Key": key}
    )
    assert list_forbidden.status_code == 403

    decision_id = list_ok.json()["items"][0]["id"]
    detail_ok = client.get(
        f"/ui/decision/{decision_id}?tenant_id=t1", headers={"X-API-Key": key}
    )
    assert detail_ok.status_code == 200

    detail_forbidden = client.get(
        f"/ui/decision/{decision_id}?tenant_id=t2", headers={"X-API-Key": key}
    )
    assert detail_forbidden.status_code == 403

    chain_ok = client.get(
        "/ui/forensics/chain/verify?tenant_id=t1", headers={"X-API-Key": key}
    )
    assert chain_ok.status_code == 200

    chain_forbidden = client.get(
        "/ui/forensics/chain/verify?tenant_id=t2", headers={"X-API-Key": key}
    )
    assert chain_forbidden.status_code == 403

    controls_ok = client.get("/ui/controls?tenant_id=t1", headers={"X-API-Key": key})
    assert controls_ok.status_code == 200

    controls_forbidden = client.get(
        "/ui/controls?tenant_id=t2", headers={"X-API-Key": key}
    )
    assert controls_forbidden.status_code == 403

    csrf = client.get("/ui/csrf", headers={"X-API-Key": key})
    token = csrf.json()["csrf_token"]
    packet_forbidden = client.post(
        "/ui/audit/packet",
        headers={"X-API-Key": key, "X-CSRF-Token": token},
        json={"tenant_id": "t2"},
    )
    assert packet_forbidden.status_code == 403


def test_ui_scope_enforcement(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key(tenant_id="t1")

    resp = client.get("/ui/posture?tenant_id=t1", headers={"X-API-Key": key})
    assert resp.status_code == 403


def test_chain_verify_pass_fail(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("forensics:read", tenant_id="t1")

    now = datetime.now(timezone.utc)
    engine = get_engine()
    with Session(engine) as session:
        h1 = _seed_record(session, "t1", "evt-1", now, None)
        _seed_record(session, "t1", "evt-2", now + timedelta(seconds=10), h1)
        session.commit()

    ok = client.get(
        "/ui/forensics/chain/verify?tenant_id=t1", headers={"X-API-Key": key}
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "PASS"

    with Session(engine) as session:
        _seed_record(
            session, "t1", "evt-3", now + timedelta(seconds=20), "bad", tamper=True
        )
        session.commit()

    fail = client.get(
        "/ui/forensics/chain/verify?tenant_id=t1", headers={"X-API-Key": key}
    )
    assert fail.status_code == 200
    assert fail.json()["status"] == "FAIL"


def test_audit_packet_manifest(build_app, monkeypatch, tmp_path):
    audit_dir = tmp_path / "audit_packets"
    monkeypatch.setenv("FG_AUDIT_PACKET_DIR", str(audit_dir))

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("audit:read", "forensics:read", tenant_id="t1")

    engine = get_engine()
    with Session(engine) as session:
        _seed_record(session, "t1", "evt-1", datetime.now(timezone.utc), None)
        session.commit()

    csrf = client.get("/ui/csrf", headers={"X-API-Key": key})
    token = csrf.json()["csrf_token"]

    resp = client.post(
        "/ui/audit/packet",
        headers={"X-API-Key": key, "X-CSRF-Token": token},
        json={"tenant_id": "t1"},
    )
    assert resp.status_code == 200
    data = resp.json()
    packet_id = data["packet_id"]

    packet_path = audit_dir / packet_id
    manifest_path = packet_path / "manifest.json"
    assert manifest_path.exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = {item["name"]: item["sha256"] for item in manifest["files"]}
    assert "decisions.jsonl" in files
    assert "chain_verification.json" in files

    assert files["decisions.jsonl"] == _sha256_file(packet_path / "decisions.jsonl")
