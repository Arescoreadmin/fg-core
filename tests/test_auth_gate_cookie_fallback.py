import os

from fastapi.testclient import TestClient

from api.main import build_app


def test_auth_gate_accepts_cookie_when_header_missing(monkeypatch):
    # Force auth ON
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    api_key = os.environ["FG_API_KEY"]
    monkeypatch.setenv("FG_API_KEY", api_key)

    cookie_name = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")

    app = build_app(auth_enabled=True)

    with TestClient(app) as client:
        # Set cookie on the client (avoids httpx per-request cookies deprecation)
        client.cookies.set(cookie_name, api_key)

        # Hit a protected endpoint WITHOUT header, ONLY cookie
        r = client.get("/stats")

        assert r.status_code == 200, r.text
