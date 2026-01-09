from fastapi.testclient import TestClient


def test_forensics_not_accessible_when_disabled(build_app, monkeypatch):
    monkeypatch.delenv("FG_GOVERNANCE_ENABLED", raising=False)
    monkeypatch.delenv("FG_MISSION_ENVELOPE_ENABLED", raising=False)
    monkeypatch.delenv("FG_RING_ROUTER_ENABLED", raising=False)
    monkeypatch.delenv("FG_ROE_ENGINE_ENABLED", raising=False)
    monkeypatch.delenv("FG_FORENSICS_ENABLED", raising=False)

    app = build_app()
    client = TestClient(app)

    r = client.get("/forensics/health")
    assert r.status_code in (401, 404, 405)
