from __future__ import annotations

import os
from fastapi.testclient import TestClient

from api.main import app


def test_ai_query_unscoped_env_key_accepts_tenant_header() -> None:
    # Simulate local dev env key path
    os.environ["FG_API_KEY"] = "dev-test-key-1234567890abcdef"

    c = TestClient(app)
    r = c.post(
        "/ai/query",
        headers={
            "X-API-Key": os.environ["FG_API_KEY"],
            "X-Tenant-Id": "dev",
        },
        json={"prompt": "ping"},
    )

    # We don't assert 200 because downstream AI may be disabled/mocked;
    # we assert we did NOT fail with "tenant_id required for unscoped keys".
    assert r.status_code != 400
    assert "tenant_id required for unscoped keys" not in r.text
