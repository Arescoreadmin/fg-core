from __future__ import annotations

from fastapi.testclient import TestClient


def test_ui_ai_routes_require_auth(build_app):
    app = build_app()
    client = TestClient(app)

    exp = client.get("/ui/ai/experience")
    assert exp.status_code in {401, 403}

    chat = client.post("/ui/ai/chat", json={"message": "hello"})
    assert chat.status_code in {401, 403}
