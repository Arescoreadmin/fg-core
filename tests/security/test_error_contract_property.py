from __future__ import annotations

from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import build_app


def test_http_exception_www_authenticate_header_preserved() -> None:
    app = build_app(auth_enabled=False)

    @app.get("/__test_auth_header")
    async def _test_auth_header() -> dict[str, str]:
        raise HTTPException(
            status_code=401,
            detail="x",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client = TestClient(app)
    response = client.get("/__test_auth_header")
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_http_exception_retry_after_header_preserved() -> None:
    app = build_app(auth_enabled=False)

    @app.get("/__test_retry_after")
    async def _test_retry_after() -> dict[str, str]:
        raise HTTPException(status_code=429, detail="x", headers={"Retry-After": "10"})

    client = TestClient(app)
    response = client.get("/__test_retry_after")
    assert response.status_code == 429
    assert response.headers.get("Retry-After") == "10"
