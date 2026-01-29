import os
import pytest
from starlette.testclient import TestClient

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
def test_ui_token_rejects_query_param_key(build_app):
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    r = c.get("/ui/token", params={"api_key": API_KEY})
    assert r.status_code in {401, 403}
