from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware.resilience_guard import ResilienceGuardMiddleware


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(ResilienceGuardMiddleware)

    @app.post("/ai/infer")
    def infer() -> dict[str, str]:
        return {"ok": "yes"}

    return app


def test_backpressure_response_shape(monkeypatch):
    monkeypatch.setenv("FG_BACKPRESSURE_ENABLED", "1")
    monkeypatch.setenv("FG_DEGRADED_MODE", "0")
    client = TestClient(_app())
    resp = client.post("/ai/infer", headers={"X-Request-Id": "rid-1"}, json={"q": "x"})
    assert resp.status_code == 503
    body = resp.json()["detail"]
    assert body["error_code"] == "SERVICE_OVERLOADED_SHED"
    assert body["request_id"] == "rid-1"
    assert body["service_state"] in {"normal", "degraded"}
    assert body["retry_after_seconds"] == 5


def test_degraded_response_shape(monkeypatch):
    monkeypatch.setenv("FG_BACKPRESSURE_ENABLED", "0")
    monkeypatch.setenv("FG_DEGRADED_MODE", "1")
    client = TestClient(_app())
    resp = client.post("/ai/infer", json={"q": "x"})
    assert resp.status_code == 503
    body = resp.json()["detail"]
    assert body["error_code"] == "SERVICE_DEGRADED_READONLY"
    assert body["request_id"] == "unknown"
    assert body["service_state"] == "degraded"
    assert body["retry_after_seconds"] == 0
