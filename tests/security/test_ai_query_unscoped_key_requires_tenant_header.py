from __future__ import annotations

import importlib
import os

from fastapi.testclient import TestClient


def _fresh_app():
    # Ensure env is set BEFORE importing api.main
    os.environ["FG_API_KEY"] = "dev-test-key-1234567890abcdef"
    # Some builds cache config at import-time; reload the module to pick up env.
    import api.main as main

    importlib.reload(main)
    return main.app


def test_ai_query_unscoped_env_key_accepts_tenant_header() -> None:
    app = _fresh_app()
    c = TestClient(app)

    r = c.post(
        "/ai/query",
        headers={
            "X-API-Key": os.environ["FG_API_KEY"],
            "X-Tenant-Id": "dev",
        },
        json={"prompt": "ping"},
    )

    assert r.status_code != 400, r.text
    assert "tenant_id required for unscoped keys" not in r.text
