"""P-1: Provisioning to portal activation is deterministic.

Acceptance criteria:
  P1-1  complete_workflow without client_id/engagement_id → portal_grant null (backward compat)
  P1-2  complete_workflow with both → portal_grant non-null, raw_secret present
  P1-3  raw_secret from P1-2 authenticates successfully via POST /portal/authenticate
         — client can reach the portal with no additional operator action
  P1-4  Only one field provided (partial) → no grant issued, portal_grant null

SQLite transaction-atomicity regression tests (fix/portal-provisioning-sqlite-transaction-atomicity):
  P1-A  completion with client_id + engagement_id succeeds on SQLite (no lock error)
  P1-B  returned raw_secret authenticates successfully (canonical path)
  P1-C  credential rows are created in tenant_credentials
  P1-D  credential_slot and tenant_credential are part of the same transaction
  P1-E  if credential issuance raises, provisioning completion does NOT commit partially
  P1-F  portal grant audit does not persist on failed issuance
  P1-G  standalone CredentialAuthority callers (conn=None path) still work
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


# ---------------------------------------------------------------------------
# P1-A  SQLite lock regression — complete with grant must not raise
#        OperationalError: database is locked
# ---------------------------------------------------------------------------


def test_P1_A_sqlite_no_lock_error_on_grant_issuance(client: TestClient):
    """P1-A: complete_workflow + portal grant issuance must not raise SQLite lock."""
    prov_id = _provision(client, "sqlite-a")
    resp = client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={
            "validation_results": {},
            "client_id": "LockTest Client",
            "engagement_id": "eng-p1-sqlite-a",
        },
    )
    # Must succeed — previously raised 500 with OperationalError: database is locked
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workflow_state"] == "completed"
    assert body["portal_grant"] is not None
    assert body["portal_grant"]["raw_secret"]


# ---------------------------------------------------------------------------
# P1-B  raw_secret from auto-grant authenticates via canonical credential path
# ---------------------------------------------------------------------------


def test_P1_B_raw_secret_authenticates_canonical_path(client: TestClient):
    """P1-B: raw_secret authenticates via canonical tenant_credentials lookup."""
    prov_id = _provision(client, "sqlite-b")
    complete_resp = client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={
            "validation_results": {},
            "client_id": "CanonClient",
            "engagement_id": "eng-p1-sqlite-b",
        },
    )
    assert complete_resp.status_code == 200, complete_resp.text
    raw_secret = complete_resp.json()["portal_grant"]["raw_secret"]

    auth_resp = client.post(
        "/portal/authenticate",
        json={"secret": raw_secret},
    )
    assert auth_resp.status_code == 200, auth_resp.text
    body = auth_resp.json()
    assert body["session_id"]
    assert body["client_id"] == "CanonClient"


# ---------------------------------------------------------------------------
# P1-C  credential rows are written to tenant_credentials (canonical table)
# ---------------------------------------------------------------------------


def test_P1_C_credential_row_in_tenant_credentials(tmp_path, monkeypatch):
    """P1-C: after grant issuance, tenant_credentials has an active portal_access row."""
    from api.auth_scopes import mint_key
    from api.db import get_engine, reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "p1c_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper-c")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    tenant = "tenant-p1c"
    key = mint_key("control-plane:read", "control-plane:admin", tenant_id=tenant)
    http = TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})

    prov_id = _provision(http, "cred-c")
    resp = http.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={
            "validation_results": {},
            "client_id": "AuditClient",
            "engagement_id": "eng-p1c",
        },
    )
    assert resp.status_code == 200, resp.text
    grant_id = resp.json()["portal_grant"]["grant_id"]

    # Query tenant_credentials directly via the engine.
    from sqlalchemy import text

    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT credential_id, status, credential_type "
                "FROM tenant_credentials "
                "WHERE credential_id = :cid"
            ),
            {"cid": grant_id},
        ).fetchone()

    assert row is not None, "no row in tenant_credentials for grant_id"
    assert row[1] == "active"
    assert row[2] == "portal_access"


# ---------------------------------------------------------------------------
# P1-D  credential_slot and tenant_credential are in the same transaction —
#        both rows commit atomically or neither does
# ---------------------------------------------------------------------------


def test_P1_D_slot_and_credential_same_transaction(tmp_path, monkeypatch):
    """P1-D: credential_slots and tenant_credentials rows commit together."""
    from api.auth_scopes import mint_key
    from api.db import get_engine, reset_engine_cache
    from api.main import build_app
    from sqlalchemy import text

    db_path = tmp_path / "p1d_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper-d")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    tenant = "tenant-p1d"
    key = mint_key("control-plane:read", "control-plane:admin", tenant_id=tenant)
    http = TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})

    prov_id = _provision(http, "slot-d")
    resp = http.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={
            "validation_results": {},
            "client_id": "SlotClient",
            "engagement_id": "eng-p1d",
        },
    )
    assert resp.status_code == 200, resp.text
    grant_id = resp.json()["portal_grant"]["grant_id"]

    engine = get_engine()
    with engine.connect() as conn:
        cred_row = conn.execute(
            text(
                "SELECT credential_slot FROM tenant_credentials WHERE credential_id = :cid"
            ),
            {"cid": grant_id},
        ).fetchone()
        assert cred_row is not None
        slot = cred_row[0]

        slot_row = conn.execute(
            text(
                "SELECT current_generation FROM credential_slots "
                "WHERE credential_slot = :slot AND credential_type = 'portal_access'"
            ),
            {"slot": slot},
        ).fetchone()
        assert slot_row is not None, (
            "no credential_slots row — slot and credential not co-committed"
        )
        assert slot_row[0] == 1, f"expected generation=1, got {slot_row[0]}"


# ---------------------------------------------------------------------------
# P1-E  if credential issuance raises, provisioning completion does NOT commit
# ---------------------------------------------------------------------------


def test_P1_E_atomicity_on_issuance_failure(tmp_path, monkeypatch):
    """P1-E: provisioning state is NOT committed when credential issuance raises."""
    import unittest.mock

    from api.auth_scopes import mint_key
    from api.db import get_engine, reset_engine_cache
    from api.main import build_app
    from sqlalchemy import text

    db_path = tmp_path / "p1e_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper-e")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    tenant = "tenant-p1e"
    key = mint_key("control-plane:read", "control-plane:admin", tenant_id=tenant)
    http = TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})

    prov_id = _provision(http, "atomic-e")

    # Patch issue_credential to raise after the provisioning store flushes
    # (simulates a downstream write failure).
    with unittest.mock.patch(
        "api.credential_authority.issue_credential",
        side_effect=RuntimeError("simulated issuance failure"),
    ):
        resp = http.post(
            f"/control-plane/provisioning/workflows/{prov_id}/complete",
            json={
                "validation_results": {},
                "client_id": "AtomicClient",
                "engagement_id": "eng-p1e",
            },
        )
    # Must not return 200 (partial success) — any non-200 is acceptable here.
    assert resp.status_code != 200, (
        f"expected non-200 after issuance failure, got {resp.status_code}"
    )

    # Verify the workflow was NOT committed as completed.
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT workflow_state FROM provisioning_workflows "
                "WHERE provisioning_id = :pid"
            ),
            {"pid": prov_id},
        ).fetchone()
    # Row should still be in a non-completed state.
    assert row is not None
    assert row[0] != "completed", (
        f"workflow was committed as completed despite issuance failure: {row[0]}"
    )


# ---------------------------------------------------------------------------
# P1-F  portal grant audit does not persist on failed issuance
# ---------------------------------------------------------------------------


def test_P1_F_audit_not_persisted_on_issuance_failure(tmp_path, monkeypatch):
    """P1-F: portal_grant_audit_events are rolled back when issuance fails."""
    import unittest.mock

    from api.auth_scopes import mint_key
    from api.db import get_engine, reset_engine_cache
    from api.main import build_app
    from sqlalchemy import text

    db_path = tmp_path / "p1f_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper-f")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    tenant = "tenant-p1f"
    key = mint_key("control-plane:read", "control-plane:admin", tenant_id=tenant)
    http = TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})

    prov_id = _provision(http, "audit-f")

    with unittest.mock.patch(
        "api.credential_authority.issue_credential",
        side_effect=RuntimeError("simulated issuance failure"),
    ):
        resp = http.post(
            f"/control-plane/provisioning/workflows/{prov_id}/complete",
            json={
                "validation_results": {},
                "client_id": "AuditFailClient",
                "engagement_id": "eng-p1f",
            },
        )
    assert resp.status_code != 200

    # Portal grant audit events should not be present.
    engine = get_engine()
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT COUNT(*) FROM portal_grant_audit_events "
                "WHERE tenant_id = :tid AND engagement_id = :eid"
            ),
            {"tid": tenant, "eid": "eng-p1f"},
        ).fetchone()
    assert rows is not None
    assert rows[0] == 0, (
        f"expected 0 portal_grant_audit_events after rollback, found {rows[0]}"
    )


# ---------------------------------------------------------------------------
# P1-G  standalone CredentialAuthority callers (conn=None default path)
# ---------------------------------------------------------------------------


def test_P1_G_standalone_credential_authority_conn_none(tmp_path, monkeypatch):
    """P1-G: issue_credential with conn=None (default) works as before."""
    from api.db import (
        ensure_tenant_canonical_row,
        get_engine,
        init_db,
        reset_engine_cache,
    )

    db_path = tmp_path / "p1g_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper-g")
    reset_engine_cache()

    init_db(sqlite_path=str(db_path))

    tenant = "tenant-p1g-standalone"
    ensure_tenant_canonical_row(str(db_path), tenant)

    import api.credential_authority as ca

    engine = get_engine()
    # conn=None is the default — this must work exactly as before.
    result = ca.issue_credential(
        engine,
        tenant_id=tenant,
        credential_type="portal_access",
        credential_slot="standalone-slot-g1",
        scopes=["credential:use"],
        metadata={"client_id": "standalone-client", "engagement_id": "eng-g"},
        expires_in_seconds=86400,
        actor_id="test-actor",
        # conn not passed → uses engine.begin() internally
    )
    assert result.plaintext_secret is not None
    assert result.record.status == "active"
    assert result.record.credential_type == "portal_access"
