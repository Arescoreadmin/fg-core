from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from api.middleware.exception_shield import FGExceptionShieldMiddleware


def _shielded_asgi_raiser(exc: Exception):
    async def app(scope, receive, send):
        raise exc

    return FGExceptionShieldMiddleware(app)


def _build_validation_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(FGExceptionShieldMiddleware)

    @app.post("/validate")
    async def validate(payload: dict[str, int]):
        return payload

    return app


def test_401_preserves_www_authenticate_header_and_request_id() -> None:
    app = _shielded_asgi_raiser(
        HTTPException(
            status_code=401,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    )
    client = TestClient(app)

    response = client.get("/unauthorized", headers={"X-Request-ID": "rid-401"})

    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"
    assert response.headers.get("X-Request-ID") == "rid-401"

    body = response.json()
    assert body["error_code"] == "E401_unauthorized"
    assert body["detail"] == "unauthorized"
    assert body["request_id"] == "rid-401"


def test_429_preserves_retry_after_header() -> None:
    app = _shielded_asgi_raiser(
        HTTPException(
            status_code=429,
            detail="rate limited",
            headers={"Retry-After": "5"},
        )
    )
    client = TestClient(app)

    response = client.get("/ratelimit")

    assert response.status_code == 429
    assert response.headers.get("Retry-After") == "5"
    body = response.json()
    assert body["error_code"] == "E429_rate_limited"
    assert body["detail"] == "rate limited"
    assert "request_id" not in body


def test_422_validation_error_is_not_rewritten() -> None:
    app = _build_validation_app()
    client = TestClient(app)

    response = client.post("/validate", json={"n": "not-an-int"})

    assert response.status_code == 422
    body = response.json()
    assert "detail" in body
    assert "error_code" not in body


def test_exception_group_with_http_exception_uses_first_http_exception() -> None:
    app = _shielded_asgi_raiser(
        ExceptionGroup(
            "eg",
            [
                HTTPException(status_code=403, detail="forbidden"),
                ValueError("x"),
            ],
        )
    )
    client = TestClient(app)

    response = client.get("/exception-group-http")

    assert response.status_code == 403
    body = response.json()
    assert body["error_code"] == "E403_forbidden"
    assert body["detail"] == "forbidden"


def test_exception_group_nested_http_exception_uses_first_nested_http_exception() -> (
    None
):
    app = _shielded_asgi_raiser(
        ExceptionGroup(
            "outer",
            [
                ValueError("a"),
                ExceptionGroup(
                    "inner",
                    [
                        ValueError("b"),
                        HTTPException(status_code=409, detail="conflict"),
                    ],
                ),
            ],
        )
    )
    client = TestClient(app)

    response = client.get("/exception-group-http-nested")

    assert response.status_code == 409
    body = response.json()
    assert body["error_code"] == "E409_conflict"
    assert body["detail"] == "conflict"


def test_exception_group_without_http_exception_is_reraised() -> None:
    app = _shielded_asgi_raiser(ExceptionGroup("eg", [ValueError("x")]))
    client = TestClient(app)

    with pytest.raises(ExceptionGroup):
        client.get("/exception-group-non-http")


@pytest.mark.anyio
async def test_response_started_safety_reraises_and_does_not_double_send() -> None:
    class StartedThenRaisesApp:
        async def __call__(self, scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"partial",
                    "more_body": False,
                }
            )
            raise HTTPException(status_code=418, detail="teapot")

    middleware = FGExceptionShieldMiddleware(StartedThenRaisesApp())
    sent_messages: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/partial",
        "raw_path": b"/partial",
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 123),
        "server": ("testserver", 80),
        "state": {},
    }

    with pytest.raises(HTTPException):
        await middleware(scope, receive, send)

    start_messages = [
        m for m in sent_messages if m.get("type") == "http.response.start"
    ]
    assert len(start_messages) == 1
    assert start_messages[0]["status"] == 200
