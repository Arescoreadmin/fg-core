import os
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import reset_engine_cache
from api.main import build_app


TEST_TENANT = "test-tenant-diff"


def _post_auth(client: TestClient, attempts: int, api_key: str):
    r = client.post(
        "/defend",
        headers={"x-api-key": api_key},
        json={
            "event_type": "auth_attempt",
            "source": "pytest",
            "tenant_id": TEST_TENANT,
            "payload": {"source_ip": "1.2.3.4", "attempts": attempts},
        },
    )
    assert r.status_code == 200, f"/defend failed {r.status_code}: {r.text}"
    return r.json()


def test_decision_diff_is_persisted_and_surfaced(tmp_path):
    # Protect suite from env leakage
    keys = ["FG_API_KEY", "FG_AUTH_ENABLED", "FG_SQLITE_PATH", "FG_RL_ENABLED"]
    old = {k: os.environ.get(k) for k in keys}
    try:
        os.environ["FG_API_KEY"] = "ci-test-key-00000000000000000000000000000000"
        os.environ["FG_AUTH_ENABLED"] = "1"
        os.environ["FG_SQLITE_PATH"] = str(tmp_path / "frostgate-test.db")
        os.environ["FG_RL_ENABLED"] = "0"  # Disable rate limiter for test

        # Reset DB engine cache to use new SQLITE_PATH
        reset_engine_cache()

        app = build_app(auth_enabled=True)

        with TestClient(app) as client:
            defend_key = mint_key("defend:write", tenant_id=TEST_TENANT)
            decisions_key = mint_key("decisions:read", tenant_id=TEST_TENANT)
            # Two posts to create prior state + changed state
            _post_auth(client, 1, defend_key)
            _post_auth(client, 10, defend_key)

            r = client.get(
                "/decisions",
                params={"limit": 1},
                headers={"x-api-key": decisions_key},
            )
            assert r.status_code == 200, f"/decisions failed {r.status_code}: {r.text}"
            item = r.json()["items"][0]

            diff = item.get("decision_diff")
            assert diff is not None, f"missing decision_diff: item={item}"
            assert diff.get("summary"), f"missing diff.summary: diff={diff}"
            changes = diff.get("changes") or []
            assert len(changes) >= 1, f"diff.changes empty: diff={diff}"

            # Make sure it’s meaningful: threat/decision/score change
            # Make sure it’s meaningful: threat/decision/score change
            # changes may be ["field", ...] OR [{"field": "field", ...}, ...]
            fields = set()
            for c in changes:
                if isinstance(c, str):
                    fields.add(c)
                elif isinstance(c, dict):
                    # tolerate multiple schemas
                    f = c.get("field") or c.get("name") or c.get("key")
                    if f:
                        fields.add(str(f))

            assert {"threat_level", "decision", "score"} & fields, (
                f"diff not meaningful: fields={fields}, diff={diff}"
            )
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
