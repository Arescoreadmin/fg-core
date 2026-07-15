"""P-1: Provisioning to portal activation is deterministic.

Acceptance criteria:
  P1-1  complete_workflow without client_id/engagement_id → portal_grant null (backward compat)
  P1-2  complete_workflow with both → portal_grant non-null, raw_secret present
  P1-3  raw_secret from P1-2 authenticates successfully via POST /portal/authenticate
         — client can reach the portal with no additional operator action
  P1-4  Only one field provided (partial) → no grant issued, portal_grant null
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest
from fastapi.testclient import TestClient

_TENANT = "tenant-p1-provisioning"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "p1_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key(
        "control-plane:read",
        "control-plane:admin",
        "governance:read",
        tenant_id=_TENANT,
    )
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


def _provision(client: TestClient, slug_suffix: str) -> str:
    """Create org → start workflow → return provisioning_id."""
    org = client.post(
        "/control-plane/provisioning/organizations",
        json={
            "org_name": f"P-1 Test Org {slug_suffix}",
            "slug": f"p1-test-{slug_suffix}",
        },
    )
    assert org.status_code == 201, org.text
    org_id = org.json()["organization_id"]

    wf = client.post(
        f"/control-plane/provisioning/organizations/{org_id}/provision",
        json={},
    )
    assert wf.status_code == 201, wf.text
    return wf.json()["provisioning_id"]


# ---------------------------------------------------------------------------
# P1-1: backward compat — no grant fields → portal_grant null
# ---------------------------------------------------------------------------


def test_P1_1_complete_without_grant_fields_returns_null_portal_grant(
    client: TestClient,
):
    prov_id = _provision(client, "compat")

    resp = client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={"validation_results": {}},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workflow_state"] == "completed"
    assert body["portal_grant"] is None


# ---------------------------------------------------------------------------
# P1-4: partial fields only → no grant issued
# ---------------------------------------------------------------------------


def test_P1_4_partial_fields_no_grant_issued(client: TestClient):
    prov_id = _provision(client, "partial")

    resp = client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={"validation_results": {}, "client_id": "Acme Corp"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["portal_grant"] is None


# ---------------------------------------------------------------------------
# P1-2: both fields → portal_grant non-null with raw_secret
# ---------------------------------------------------------------------------


def test_P1_2_complete_with_grant_fields_returns_portal_grant(client: TestClient):
    prov_id = _provision(client, "full")

    resp = client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={
            "validation_results": {},
            "client_id": "Acme Corp",
            "engagement_id": "eng-p1-full",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workflow_state"] == "completed"
    pg = body["portal_grant"]
    assert pg is not None
    assert pg["grant_id"]
    assert pg["raw_secret"]
    assert pg["client_id"] == "Acme Corp"
    assert pg["engagement_id"] == "eng-p1-full"
    assert pg["expires_at"]


# ---------------------------------------------------------------------------
# P1-3: raw_secret from auto-grant authenticates → client reaches portal
# ---------------------------------------------------------------------------


def test_P1_3_raw_secret_authenticates_portal_session(client: TestClient):
    prov_id = _provision(client, "auth")

    complete_resp = client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={
            "validation_results": {},
            "client_id": "Globex Inc",
            "engagement_id": "eng-p1-auth",
        },
    )
    assert complete_resp.status_code == 200, complete_resp.text
    raw_secret = complete_resp.json()["portal_grant"]["raw_secret"]
    assert raw_secret

    auth_resp = client.post(
        "/portal/authenticate",
        json={"secret": raw_secret},
    )
    assert auth_resp.status_code == 200, auth_resp.text
    auth_body = auth_resp.json()
    assert auth_body["session_id"]
    assert auth_body["client_id"] == "Globex Inc"
    assert "eng-p1-auth" in auth_body["engagement_ids"]
