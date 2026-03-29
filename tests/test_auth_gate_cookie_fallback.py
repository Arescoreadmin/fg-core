import os

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.main import build_app


def test_auth_gate_rejects_cookie_when_header_missing(monkeypatch):
    # Force auth ON
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    api_key = mint_key("stats:read", tenant_id="test-tenant")

    cookie_name = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")

    app = build_app(auth_enabled=True)

    with TestClient(app) as client:
        # Set cookie on the client (avoids httpx per-request cookies deprecation)
        client.cookies.set(cookie_name, api_key)

        # Hit a protected endpoint WITHOUT header, ONLY cookie
        r = client.get("/stats")

        assert r.status_code == 401, r.text

        # Header-based auth path remains valid (service-to-service model)
        r_ok = client.get("/stats", headers={"X-API-Key": api_key})
        assert r_ok.status_code == 200, r_ok.text


def test_legacy_ui_cookie_flow_still_works_in_non_hosted_profile(monkeypatch):
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    api_key = mint_key("ui:read", tenant_id="test-tenant")
    cookie_name = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")

    app = build_app(auth_enabled=True)

    with TestClient(app) as client:
        token_resp = client.get("/ui/token", headers={"X-API-Key": api_key})
        assert token_resp.status_code == 200, token_resp.text
        client.cookies.set(cookie_name, api_key)

        ui_resp = client.get("/ui/feed")
        assert ui_resp.status_code == 200, ui_resp.text
