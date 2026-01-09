import os

from fastapi.testclient import TestClient

from api.main import build_app


def test_auth_gate_accepts_cookie_when_header_missing(monkeypatch):
    # Force auth ON
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_API_KEY", "supersecret")

    # Use default cookie name unless overridden
    cookie_name = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")

    app = build_app(auth_enabled=True)
    client = TestClient(app)

    # Hit a protected endpoint WITHOUT header, ONLY cookie
    r = client.get("/stats", cookies={cookie_name: "supersecret"})

    assert r.status_code == 200, r.text
