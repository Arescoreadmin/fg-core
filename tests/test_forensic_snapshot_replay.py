from fastapi.testclient import TestClient


def test_forensics_not_mounted_when_disabled(build_app):
    monkeypatch.delenv('FG_GOVERNANCE_ENABLED', raising=False)
    monkeypatch.delenv('FG_MISSION_ENVELOPE_ENABLED', raising=False)
    monkeypatch.delenv('FG_RING_ROUTER_ENABLED', raising=False)
    monkeypatch.delenv('FG_ROE_ENGINE_ENABLED', raising=False)
    monkeypatch.delenv('FG_FORENSICS_ENABLED', raising=False)
    app = build_app()
    client = TestClient(app)

    r = client.get("/forensics/snapshot/does-not-matter", headers={"X-API-Key": "supersecret"})
    assert r.status_code == 404

    r2 = client.get("/forensics/audit_trail/does-not-matter", headers={"X-API-Key": "supersecret"})
    assert r2.status_code == 404


def test_forensics_not_mounted_when_disabled(build_app, monkeypatch):
    monkeypatch.delenv('FG_GOVERNANCE_ENABLED', raising=False)
    monkeypatch.delenv('FG_MISSION_ENVELOPE_ENABLED', raising=False)
    monkeypatch.delenv('FG_RING_ROUTER_ENABLED', raising=False)
    monkeypatch.delenv('FG_ROE_ENGINE_ENABLED', raising=False)
    monkeypatch.delenv("FG_FORENSICS_ENABLED", raising=False)
    app = build_app()
    client = TestClient(app)

    r = client.get("/forensics/snapshot/does-not-matter", headers={"X-API-Key": "supersecret"})
    assert r.status_code == 404

    r2 = client.get("/forensics/audit_trail/does-not-matter", headers={"X-API-Key": "supersecret"})
    assert r2.status_code == 404


def test_forensic_snapshot_and_audit(build_app, monkeypatch):
    monkeypatch.setenv("FG_FORENSICS_ENABLED", "1")
    app = build_app()

    client = TestClient(app)
    headers = {"X-API-Key": "supersecret"}

    defend_resp = client.post(
        "/defend",
        headers=headers,
        json={
            "source": "unit-test",
            "tenant_id": "tenant-1",
            "event_type": "auth",
            "payload": {"event_type": "auth", "fail_count": 7, "source_ip": "10.0.0.1"},
        },
    )
    assert defend_resp.status_code == 200, defend_resp.text
    event_id = defend_resp.json()["event_id"]

    snapshot = client.get(f"/forensics/snapshot/{event_id}", headers=headers)
    assert snapshot.status_code == 200, snapshot.text
    snap_data = snapshot.json()
    assert snap_data["snapshot"]["event_id"] == event_id
    assert snap_data["decision_hash"]

    audit = client.get(f"/forensics/audit_trail/{event_id}", headers=headers)
    assert audit.status_code == 200, audit.text
    audit_data = audit.json()
    assert audit_data["event_id"] == event_id
    assert isinstance(audit_data.get("timeline"), list)

    # chain_hash/prev_hash are best-effort (schema may not have them)
    assert "chain_hash" in audit_data
    assert "prev_hash" in audit_data
