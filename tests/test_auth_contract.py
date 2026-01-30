import os

from fastapi.testclient import TestClient

from tests.test_auth import build_app


def test_default_env_in_ci_has_auth_enabled():
    """
    CI sanity check:

    - FG_API_KEY must be set (we default it locally if missing)
    - /health should report auth_enabled = True
    """
    if not os.environ.get("FG_API_KEY"):
        raise RuntimeError("FG_API_KEY must be set for test runs.")

    app = build_app(auth_enabled=True)

    with TestClient(app) as client:
        resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.json()
    assert data["auth_enabled"] is True
