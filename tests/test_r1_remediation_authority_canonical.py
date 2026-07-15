"""R-1: Remediation authority declared canonical; legacy /remediation/* deprecated.

Acceptance criteria:
  R1-1  All /remediation/* routes in the OpenAPI spec have deprecated: true
  R1-2  /remediation-authority/* routes in the OpenAPI spec do NOT have deprecated: true
  R1-3  Legacy /remediation/* routes still respond (not removed) — backward compat
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "r1_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=False)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# R1-1: All /remediation/* routes are marked deprecated in OpenAPI
# ---------------------------------------------------------------------------


def test_r1_1_legacy_remediation_routes_deprecated(client: TestClient) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()
    paths = spec.get("paths", {})

    legacy_paths = [p for p in paths if p.startswith("/remediation/")]
    assert legacy_paths, "No /remediation/* paths found in OpenAPI spec"

    not_deprecated = []
    for path, path_item in paths.items():
        if not path.startswith("/remediation/"):
            continue
        for method, operation in path_item.items():
            if method == "parameters":
                continue
            if not operation.get("deprecated", False):
                not_deprecated.append(f"{method.upper()} {path}")

    assert not_deprecated == [], (
        f"Legacy routes missing deprecated=True: {not_deprecated}"
    )


# ---------------------------------------------------------------------------
# R1-2: /remediation-authority/* routes are NOT deprecated
# ---------------------------------------------------------------------------


def test_r1_2_canonical_remediation_authority_not_deprecated(
    client: TestClient,
) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()
    paths = spec.get("paths", {})

    authority_paths = [p for p in paths if p.startswith("/remediation-authority/")]
    assert authority_paths, "No /remediation-authority/* paths found in OpenAPI spec"

    wrongly_deprecated = []
    for path, path_item in paths.items():
        if not path.startswith("/remediation-authority/"):
            continue
        for method, operation in path_item.items():
            if method == "parameters":
                continue
            if operation.get("deprecated", False):
                wrongly_deprecated.append(f"{method.upper()} {path}")

    assert wrongly_deprecated == [], (
        f"Canonical routes incorrectly marked deprecated: {wrongly_deprecated}"
    )


# ---------------------------------------------------------------------------
# R1-3: Legacy /remediation/* routes still respond (not removed)
# ---------------------------------------------------------------------------


def test_r1_3_legacy_routes_still_respond(client: TestClient) -> None:
    # GET /remediation/tasks — legacy list endpoint; expect 200 or auth error (401/403),
    # NOT 404 (which would mean the route was removed).
    resp = client.get("/remediation/tasks")
    assert resp.status_code != 404, (
        "Legacy GET /remediation/tasks returned 404 — route was removed prematurely"
    )
