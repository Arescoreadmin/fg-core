from __future__ import annotations

import asyncio
import os
import time
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def dos_env() -> dict[str, str]:
    return {
        "FG_ENV": "dev",
        "FG_AUTH_ENABLED": "0",
        "FG_DOS_GUARD_ENABLED": "1",
        "FG_MAX_BODY_BYTES": "128",
        "FG_MAX_QUERY_BYTES": "32",
        "FG_MAX_PATH_BYTES": "64",
        "FG_MAX_HEADERS_COUNT": "8",
        "FG_MAX_HEADERS_BYTES": "512",
        "FG_MAX_HEADER_LINE_BYTES": "128",
        "FG_MULTIPART_MAX_BYTES": "256",
        "FG_MULTIPART_MAX_PARTS": "3",
        "FG_REQUEST_TIMEOUT_SEC": "1",
        "FG_MAX_CONCURRENT_REQUESTS": "4",
        "FG_RL_ENABLED": "0",
        "FG_ENFORCE_CONTENT_TYPE": "0",
    }


def _build_hardened_app(env: dict[str, str]):
    from api.main import build_app

    with patch.dict(os.environ, env, clear=False):
        with patch("api.main.get_shutdown_manager", None):
            return build_app(auth_enabled=False)


async def _request(app, method: str, path: str, **kwargs):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.request(method, path, **kwargs)
    await transport.aclose()
    return resp


@pytest.mark.asyncio
async def test_body_too_large_returns_413(dos_env):
    app = _build_hardened_app(dos_env)
    resp = await _request(app, "POST", "/defend", json={"payload": "x" * 4096})
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_too_many_headers_returns_431(dos_env):
    app = _build_hardened_app(dos_env)
    headers = {f"X-H{i}": "a" for i in range(12)}
    resp = await _request(app, "GET", "/health", headers=headers)
    assert resp.status_code == 431


@pytest.mark.asyncio
async def test_large_query_returns_414(dos_env):
    app = _build_hardened_app(dos_env)
    resp = await _request(app, "GET", "/health?" + ("a" * 128))
    assert resp.status_code == 414


@pytest.mark.asyncio
async def test_multipart_oversize_returns_413(dos_env):
    app = _build_hardened_app(dos_env)
    body = b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n" + (b"z" * 1024) + b"\r\n--abc--\r\n"
    headers = {"Content-Type": "multipart/form-data; boundary=abc"}
    resp = await _request(app, "POST", "/defend", content=body, headers=headers)
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_slow_body_times_out_without_hanging(dos_env):
    env = dict(dos_env)
    env["FG_REQUEST_TIMEOUT_SEC"] = "0.05"
    app = _build_hardened_app(env)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/defend",
        "raw_path": b"/defend",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    messages = [
        {"type": "http.request", "body": b"{", "more_body": True},
        {"type": "http.request", "body": b"}", "more_body": False},
    ]

    async def receive():
        if not messages:
            await asyncio.sleep(1)
            return {"type": "http.disconnect"}
        msg = messages.pop(0)
        if msg.get("more_body"):
            await asyncio.sleep(0.2)
        return msg

    sent = []

    async def send(message):
        sent.append(message)

    start = time.monotonic()
    await app(scope, receive, send)
    elapsed = time.monotonic() - start

    assert elapsed < 0.5
    assert next(m for m in sent if m["type"] == "http.response.start")["status"] == 408
