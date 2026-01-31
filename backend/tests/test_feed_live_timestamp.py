import os
from fastapi.testclient import TestClient

from api.db import reset_engine_cache
from api.main import build_app

API_KEY = os.environ.get("FG_API_KEY")
if not API_KEY:
    raise RuntimeError("FG_API_KEY must be set for test runs.")

TEST_TENANT = "test-tenant-timestamp"


def test_feed_live_includes_timestamp(tmp_path):
    # isolate env
    old = {k: os.environ.get(k) for k in ["FG_API_KEY", "FG_AUTH_ENABLED", "FG_SQLITE_PATH", "FG_DEV_EVENTS_ENABLED", "FG_RL_ENABLED"]}
    try:
        os.environ["FG_API_KEY"] = API_KEY
        os.environ["FG_AUTH_ENABLED"] = "1"
        os.environ["FG_SQLITE_PATH"] = str(tmp_path / "frostgate-test.db")
        os.environ["FG_DEV_EVENTS_ENABLED"] = "1"
        os.environ["FG_RL_ENABLED"] = "0"  # Disable rate limiter for test

        # Reset DB engine cache to use new SQLITE_PATH
        reset_engine_cache()

        app = build_app(auth_enabled=True)
        with TestClient(app) as client:
            # emit one synthetic event
            r = client.post(f"/dev/seed?tenant_id={TEST_TENANT}", headers={"x-api-key": API_KEY})
            assert r.status_code == 200, r.text

            r = client.get(f"/feed/live?limit=1&tenant_id={TEST_TENANT}", headers={"x-api-key": API_KEY})
            assert r.status_code == 200, r.text
            data = r.json()
            assert data.get("items"), f"empty items list from /feed/live: {data}"
            item = data["items"][0]

            ts = item.get("timestamp")
            assert ts, f"missing timestamp: {item}"
            assert "T" in ts, f"timestamp not iso-like: {ts}"
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
