import os
import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key

API_KEY = os.environ.get("FG_API_KEY", "")
if not API_KEY:
    raise RuntimeError("FG_API_KEY must be set for test runs.")


@pytest.mark.contract
def test_ui_token_sets_cookie_with_header(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    r = c.get("/ui/token", headers={"x-api-key": API_KEY})
    assert r.status_code == 200
    assert "set-cookie" in {k.lower(): v for k, v in r.headers.items()}


@pytest.mark.contract
def test_ui_feed_without_cookie_is_401_not_500(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    r = c.get("/ui/feed")
    assert r.status_code == 401
    assert r.headers.get("x-fg-authgate")


@pytest.mark.contract
def test_ui_feed_with_cookie_is_200_html(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    r = c.get("/ui/token", headers={"x-api-key": API_KEY})
    assert r.status_code == 200
    r2 = c.get("/ui/feed")
    assert r2.status_code == 200
    assert "text/html" in r2.headers.get("content-type", "")


@pytest.mark.contract
def test_feed_stream_with_cookie_from_ui_token_is_200_sse(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    scoped_key = mint_key("ui:read", "feed:read", tenant_id="tenant-stream")
    token_resp = c.get("/ui/token", headers={"x-api-key": scoped_key})
    assert token_resp.status_code == 200

    with c.stream("GET", "/feed/stream") as stream_resp:
        assert stream_resp.status_code == 200
        assert "text/event-stream" in stream_resp.headers.get("content-type", "")
        assert stream_resp.headers.get("cache-control") == "no-cache"
        assert stream_resp.headers.get("connection") == "keep-alive"
        assert stream_resp.headers.get("x-accel-buffering") == "no"
        seen_ready = False
        seen_ok = False
        for line in stream_resp.iter_lines():
            if line == "event: ready":
                seen_ready = True
            if line == "data: ok":
                seen_ok = True
            if seen_ready and seen_ok:
                break
        assert seen_ready
        assert seen_ok


@pytest.mark.contract
def test_feed_stream_without_auth_is_401(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    r = c.get("/feed/stream")
    assert r.status_code == 401


@pytest.mark.contract
def test_ui_feed_and_feed_stream_share_cookie_auth_behavior(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)

    no_cookie_ui = c.get("/ui/feed")
    no_cookie_stream = c.get("/feed/stream")
    assert no_cookie_ui.status_code == 401
    assert no_cookie_stream.status_code == 401

    scoped_key = mint_key("ui:read", "feed:read", tenant_id="tenant-shared")
    token_resp = c.get("/ui/token", headers={"x-api-key": scoped_key})
    assert token_resp.status_code == 200

    with_cookie_ui = c.get("/ui/feed")
    assert with_cookie_ui.status_code == 200
    with c.stream("GET", "/feed/stream") as with_cookie_stream:
        assert with_cookie_stream.status_code == 200


@pytest.mark.contract
def test_ui_token_rejects_query_param_key(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    r = c.get("/ui/token", params={"api_key": API_KEY})
    assert r.status_code == 401
