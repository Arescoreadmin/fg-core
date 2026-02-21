import os

import pytest
from fastapi.testclient import TestClient
from api.db import reset_engine_cache
from api.main import build_app as _build_app


def build_app(auth_enabled: bool):
    """
    Rebuild the FastAPI app with desired auth_enabled.

    Steps:
      - Set/clear FG_API_KEY in env
      - Drop any cached `api.*` modules
      - Re-import api.config and api.main so `settings` sees the new env
    """
    # Control env (pin both knobs; FG_AUTH_ENABLED overrides FG_API_KEY in app logic)
    api_key = os.environ.get("FG_API_KEY", "")
    os.environ.pop("FG_API_KEY", None)
    os.environ.pop("FG_AUTH_ENABLED", None)
    os.environ["FG_AUTH_ENABLED"] = "1" if auth_enabled else "0"
    if auth_enabled:
        if not api_key:
            raise RuntimeError("FG_API_KEY must be set for test runs.")
        os.environ["FG_API_KEY"] = api_key

    # Keep app construction deterministic without purging global module state,
    # which can invalidate monkeypatch targets in other tests.
    reset_engine_cache()
    return _build_app(auth_enabled=auth_enabled)


@pytest.mark.parametrize("auth_enabled", [False, True])
def test_health_reflects_auth_enabled(auth_enabled: bool):
    app = build_app(auth_enabled)

    with TestClient(app) as client:
        resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "ok"
    assert data.get("env") == "test"
    assert data.get("auth_enabled") is auth_enabled


def test_status_requires_key_when_auth_enabled():
    app = build_app(auth_enabled=True)

    with TestClient(app) as client:
        resp = client.get("/status")

    assert resp.status_code == 401
    assert resp.json().get("detail") == "Invalid or missing API key"


def test_v1_status_accepts_valid_key_and_rejects_missing():
    app = build_app(auth_enabled=True)

    with TestClient(app) as client:
        # No key -> 401
        resp_no_key = client.get("/v1/status")
        assert resp_no_key.status_code == 401

        # With correct key -> 200
        resp_with_key = client.get(
            "/v1/status",
            headers={"x-api-key": os.environ["FG_API_KEY"]},
        )
        assert resp_with_key.status_code == 200
        data = resp_with_key.json()
        assert data.get("service") == "frostgate-core"
        assert data.get("env") == "test"
