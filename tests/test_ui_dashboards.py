from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import json

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import DecisionRecord
from api.ui_dashboards import ui_audit_packet_download


def _request_for_tenant(tenant_id: str):
    from starlette.requests import Request

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/ui/audit/packet/test/download",
            "headers": [],
        }
    )
    request.state.tenant_id = tenant_id
    return request


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

    ok = client.get("/ui/posture", headers={"X-API-Key": key})
    assert ok.status_code == 200

    forbidden = client.get("/ui/posture", headers={"X-API-Key": key})
    assert forbidden.status_code == 403

    list_ok = client.get("/ui/decisions", headers={"X-API-Key": key})
    assert list_ok.status_code == 200

    list_forbidden = client.get("/ui/decisions", headers={"X-API-Key": key})
    assert list_forbidden.status_code == 403

    decision_id = list_ok.json()["items"][0]["id"]
    detail_ok = client.get(f"/ui/decision/{decision_id}", headers={"X-API-Key": key})
    assert detail_ok.status_code == 200

    detail_forbidden = client.get(
        f"/ui/decision/{decision_id}", headers={"X-API-Key": key}
    )
    assert detail_forbidden.status_code == 403

    chain_ok = client.get("/ui/forensics/chain/verify", headers={"X-API-Key": key})
    assert chain_ok.status_code == 200

    chain_forbidden = client.get(
        "/ui/forensics/chain/verify", headers={"X-API-Key": key}
    )
    assert chain_forbidden.status_code == 403

    controls_ok = client.get("/ui/controls", headers={"X-API-Key": key})
    assert controls_ok.status_code == 200

    controls_forbidden = client.get("/ui/controls", headers={"X-API-Key": key})
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

    resp = client.get("/ui/posture", headers={"X-API-Key": key})
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

    ok = client.get("/ui/forensics/chain/verify", headers={"X-API-Key": key})
    assert ok.status_code == 200
    assert ok.json()["status"] == "PASS"

    with Session(engine) as session:
        _seed_record(
            session, "t1", "evt-3", now + timedelta(seconds=20), "bad", tamper=True
        )
        session.commit()

    fail = client.get("/ui/forensics/chain/verify", headers={"X-API-Key": key})
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


def _plant_outside_packet(tmp_path: Path) -> tuple[Path, Path]:
    """A packet-shaped dir outside the root whose token the caller knows."""
    audit_dir = tmp_path / "audit_packets"
    audit_dir.mkdir()  # the root must exist or the OS cannot resolve ".."
    (audit_dir / "a").mkdir()  # real intermediate dir for "a/../../outside"
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "token.txt").write_text("known-token", encoding="utf-8")
    (outside_dir / "metadata.json").write_text(
        json.dumps({"tenant_id": "tenant-a", "packet_id": "outside"}),
        encoding="utf-8",
    )
    (outside_dir / "audit_packet.zip").write_bytes(b"outside-root-data")
    (audit_dir / "escape-link").symlink_to(outside_dir, target_is_directory=True)
    return audit_dir, outside_dir


@pytest.mark.parametrize(
    "hostile",
    ["../outside", "ABS", "..", "escape-link", "./../outside", "a/../../outside"],
)
def test_audit_packet_download_rejects_path_traversal(monkeypatch, tmp_path, hostile):
    audit_dir, outside_dir = _plant_outside_packet(tmp_path)
    if hostile == "ABS":
        hostile = str(outside_dir)
    if hostile == "..":
        # Parent of the root holds a packet-shaped dir too.
        for name in ("token.txt", "metadata.json", "audit_packet.zip"):
            (tmp_path / name).write_bytes((outside_dir / name).read_bytes())
    monkeypatch.setenv("FG_AUDIT_PACKET_DIR", str(audit_dir))

    response = asyncio.run(
        ui_audit_packet_download(
            packet_id=hostile,
            request=_request_for_tenant("tenant-a"),
            tenant_id=None,
            token="known-token",
        )
    )

    assert response.status_code == 404
    assert json.loads(response.body) == {
        "detail": "Packet not found",
        "request_id": None,
    }


def test_audit_packet_download_serves_contained_packet(monkeypatch, tmp_path):
    audit_dir, outside_dir = _plant_outside_packet(tmp_path)
    inside = audit_dir / "packet-tenant-a-20261112000000"
    inside.mkdir()
    for name in ("token.txt", "metadata.json", "audit_packet.zip"):
        (inside / name).write_bytes((outside_dir / name).read_bytes())
    monkeypatch.setenv("FG_AUDIT_PACKET_DIR", str(audit_dir))

    response = asyncio.run(
        ui_audit_packet_download(
            packet_id=inside.name,
            request=_request_for_tenant("tenant-a"),
            tenant_id=None,
            token="known-token",
        )
    )

    assert response.status_code == 200
    assert Path(response.path) == inside.resolve() / "audit_packet.zip"


@pytest.mark.parametrize(
    "tenant", ["../x", "a/b", "a\\b", "/abs", "t.1", "t\x00", "t\n", "t:1"]
)
def test_packet_id_from_hostile_tenant_is_not_contained(monkeypatch, tmp_path, tenant):
    from api.ui_dashboards import _contained_packet_dir

    monkeypatch.setenv("FG_AUDIT_PACKET_DIR", str(tmp_path / "audit_packets"))
    assert _contained_packet_dir(f"packet-{tenant}-20261112000000") is None


def test_audit_packet_download_without_metadata_fails_closed(monkeypatch, tmp_path):
    audit_dir, outside_dir = _plant_outside_packet(tmp_path)
    inside = audit_dir / "packet-tenant-b-20261112000000"
    inside.mkdir()
    for name in ("token.txt", "audit_packet.zip"):  # no metadata.json
        (inside / name).write_bytes((outside_dir / name).read_bytes())
    monkeypatch.setenv("FG_AUDIT_PACKET_DIR", str(audit_dir))

    response = asyncio.run(
        ui_audit_packet_download(
            packet_id=inside.name,
            request=_request_for_tenant("tenant-a"),
            tenant_id=None,
            token="known-token",
        )
    )

    assert response.status_code == 404
