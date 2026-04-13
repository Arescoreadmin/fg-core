"""
Regression tests for POST /audit/cycle/run (Task 9.2).

Covers:
- Happy path: cycle runs, session_id returned, record persisted, retrievable via GET /audit/sessions
- Persisted state: AuditLedgerRecord rows exist after success
- Retrieval: GET /audit/sessions returns the session for the correct tenant
- Unauthorized: no API key → 401
- Wrong scope: key without audit:write → 403
- Unbound tenant: key without tenant binding → 400
- Missing prerequisite: tenant not in registry → 422
- Invalid cycle_kind: unknown value → 422
- Cross-tenant isolation: tenant-b cannot see tenant-a's sessions
- Tamper detection: tampered chain → 409

All assertions are deterministic. No flaky timing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine, init_db, reset_engine_cache
from api.db_models import AuditLedgerRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AUDIT_HMAC_KEY = "test-cycle-key-test-cycle-key-tc"
_AUDIT_HMAC_KEY_ID = "ak-cycle"


def _registry_path(tmp_path: Path) -> Path:
    return tmp_path / "tenants.json"


def _seed_tenant(registry_path: Path, tenant_id: str) -> None:
    import json

    if registry_path.exists():
        data = json.loads(registry_path.read_text())
    else:
        data = {}
    data[tenant_id] = {
        "name": tenant_id,
        "api_key": "dummy-key",
        "status": "active",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    registry_path.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def cycle_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Isolated DB + registry for cycle-run tests.
    Returns (client, write_key_a, write_key_b, registry_path).
    """
    db_path = tmp_path / "cycle_run.db"
    reg_path = _registry_path(tmp_path)

    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_API_KEY", "")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_CURRENT", _AUDIT_HMAC_KEY)
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", _AUDIT_HMAC_KEY_ID)
    monkeypatch.setenv("FG_TENANT_REGISTRY_PATH", str(reg_path))
    # REGISTRY_PATH is a module-level constant resolved at import time; patch the symbol
    import tools.tenants.registry as _reg_mod

    monkeypatch.setattr(_reg_mod, "REGISTRY_PATH", reg_path)

    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    from api.main import build_app

    client = TestClient(build_app(auth_enabled=True), raise_server_exceptions=False)

    write_key_a = mint_key("audit:write,audit:read", ttl_seconds=3600, tenant_id="tenant-a")
    write_key_b = mint_key("audit:write,audit:read", ttl_seconds=3600, tenant_id="tenant-b")

    return client, write_key_a, write_key_b, reg_path


@pytest.fixture()
def cycle_env_with_tenant(cycle_env):
    """cycle_env with tenant-a seeded in registry."""
    client, write_key_a, write_key_b, reg_path = cycle_env
    _seed_tenant(reg_path, "tenant-a")
    return client, write_key_a, write_key_b, reg_path


# ---------------------------------------------------------------------------
# Phase 1A: Happy-path end-to-end
# ---------------------------------------------------------------------------


def test_audit_cycle_run_happy_path(cycle_env_with_tenant, monkeypatch):
    """POST /audit/cycle/run succeeds for tenant with registry entry."""
    client, write_key_a, _, _ = cycle_env_with_tenant

    monkeypatch.setattr(
        "services.audit_engine.engine.AuditEngine._invariants",
        lambda self: [
            __import__(
                "services.audit_engine.engine", fromlist=["InvariantResult"]
            ).InvariantResult("test-inv", "pass", "ok")
        ],
    )

    resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": write_key_a},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "session_id" in body
    assert body["cycle_kind"] == "light"
    assert body["tenant_id"] == "tenant-a"
    assert len(body["session_id"]) == 36  # UUID


def test_audit_cycle_run_persists_ledger_records(cycle_env_with_tenant, monkeypatch):
    """Successful run creates AuditLedgerRecord rows tagged with the tenant."""
    client, write_key_a, _, _ = cycle_env_with_tenant

    monkeypatch.setattr(
        "services.audit_engine.engine.AuditEngine._invariants",
        lambda self: [
            __import__(
                "services.audit_engine.engine", fromlist=["InvariantResult"]
            ).InvariantResult("inv-persist", "pass", "ok")
        ],
    )

    resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": write_key_a},
    )
    assert resp.status_code == 200
    session_id = resp.json()["session_id"]

    engine = get_engine()
    with Session(engine) as session:
        rows = (
            session.query(AuditLedgerRecord)
            .filter(
                AuditLedgerRecord.session_id == session_id,
                AuditLedgerRecord.tenant_id == "tenant-a",
            )
            .all()
        )
    assert len(rows) >= 1
    assert all(r.tenant_id == "tenant-a" for r in rows)
    assert all(r.cycle_kind == "light" for r in rows)


def test_audit_cycle_run_retrievable_via_sessions(cycle_env_with_tenant, monkeypatch):
    """GET /audit/sessions returns the session created by POST /audit/cycle/run."""
    client, write_key_a, _, _ = cycle_env_with_tenant

    monkeypatch.setattr(
        "services.audit_engine.engine.AuditEngine._invariants",
        lambda self: [
            __import__(
                "services.audit_engine.engine", fromlist=["InvariantResult"]
            ).InvariantResult("inv-retrieve", "pass", "ok")
        ],
    )

    run_resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": write_key_a},
    )
    assert run_resp.status_code == 200
    session_id = run_resp.json()["session_id"]

    read_key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")
    list_resp = client.get(
        "/audit/sessions",
        headers={"X-API-Key": read_key_a},
    )
    assert list_resp.status_code == 200
    sessions = list_resp.json()["sessions"]
    session_ids = [s["session_id"] for s in sessions]
    assert session_id in session_ids


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


def test_audit_cycle_run_no_key_rejected(cycle_env_with_tenant):
    """No API key → 401."""
    client, _, _, _ = cycle_env_with_tenant
    resp = client.post("/audit/cycle/run", json={"cycle_kind": "light"})
    assert resp.status_code in (401, 403)


def test_audit_cycle_run_wrong_scope_rejected(cycle_env_with_tenant):
    """Key with read-only scope cannot trigger a cycle."""
    client, _, _, _ = cycle_env_with_tenant
    read_only_key = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")
    resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": read_only_key},
    )
    assert resp.status_code == 403


def test_audit_cycle_run_unbound_tenant_rejected(cycle_env_with_tenant):
    """Key without tenant binding → 400."""
    client, _, _, _ = cycle_env_with_tenant
    unbound_key = mint_key("audit:write", ttl_seconds=3600, tenant_id=None)
    resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": unbound_key},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Precondition enforcement
# ---------------------------------------------------------------------------


def test_audit_cycle_run_tenant_not_in_registry_fails(cycle_env):
    """Tenant not in registry → 422 TENANT_NOT_FOUND."""
    client, write_key_a, _, _ = cycle_env
    # tenant-a NOT seeded in registry
    resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": write_key_a},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "TENANT_NOT_FOUND"


def test_audit_cycle_run_invalid_cycle_kind_fails(cycle_env_with_tenant):
    """Unknown cycle_kind → 422 INVALID_CYCLE_KIND."""
    client, write_key_a, _, _ = cycle_env_with_tenant
    resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "ultra"},
        headers={"X-API-Key": write_key_a},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "INVALID_CYCLE_KIND"


def test_audit_cycle_run_extra_fields_rejected(cycle_env_with_tenant):
    """Extra fields in request body → 422 (extra=forbid)."""
    client, write_key_a, _, _ = cycle_env_with_tenant
    resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light", "unknown_field": "bad"},
        headers={"X-API-Key": write_key_a},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Cross-tenant isolation
# ---------------------------------------------------------------------------


def test_audit_cycle_run_cross_tenant_sessions_invisible(
    cycle_env_with_tenant, monkeypatch
):
    """
    tenant-b cannot see tenant-a's sessions via GET /audit/sessions.
    Sessions are strictly filtered by bound tenant_id.
    """
    client, write_key_a, write_key_b, reg_path = cycle_env_with_tenant
    # Also seed tenant-b so it can run its own cycles
    _seed_tenant(reg_path, "tenant-b")

    monkeypatch.setattr(
        "services.audit_engine.engine.AuditEngine._invariants",
        lambda self: [
            __import__(
                "services.audit_engine.engine", fromlist=["InvariantResult"]
            ).InvariantResult("inv-iso", "pass", "ok")
        ],
    )

    # tenant-a runs a cycle
    run_resp = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": write_key_a},
    )
    assert run_resp.status_code == 200
    tenant_a_session = run_resp.json()["session_id"]

    # tenant-b lists sessions — must not see tenant-a's session
    read_key_b = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-b")
    list_resp = client.get(
        "/audit/sessions",
        headers={"X-API-Key": read_key_b},
    )
    assert list_resp.status_code == 200
    session_ids = [s["session_id"] for s in list_resp.json()["sessions"]]
    assert tenant_a_session not in session_ids


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_audit_cycle_run_tampered_chain_returns_409(
    cycle_env_with_tenant, monkeypatch
):
    """
    If the audit chain is tampered, run_cycle raises AuditTamperDetected → 409.
    """
    from sqlalchemy import text

    client, write_key_a, _, _ = cycle_env_with_tenant

    monkeypatch.setattr(
        "services.audit_engine.engine.AuditEngine._invariants",
        lambda self: [
            __import__(
                "services.audit_engine.engine", fromlist=["InvariantResult"]
            ).InvariantResult("inv-tamper", "pass", "ok")
        ],
    )

    # First cycle — seeds the chain
    first = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": write_key_a},
    )
    assert first.status_code == 200

    # Inject a tampered row to break chain integrity
    db_engine = get_engine()
    with Session(db_engine) as s:
        s.execute(
            text(
                "INSERT INTO audit_ledger("
                "session_id,cycle_kind,timestamp_utc,invariant_id,decision,"
                "config_hash,policy_hash,git_commit,runtime_version,host_id,"
                "tenant_id,sha256_engine_code_hash,sha256_self_hash,"
                "previous_record_hash,signature,details_json"
                ") VALUES ("
                "'tampered-session','light','2025-01-01T00:00:00Z',"
                "'tampered','pass','a','b','c','d','tenant-a','tenant-a',"
                "'e','f','g','h','{}'"
                ")"
            )
        )
        s.commit()

    # Second cycle must fail with 409
    second = client.post(
        "/audit/cycle/run",
        json={"cycle_kind": "light"},
        headers={"X-API-Key": write_key_a},
    )
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "AUDIT_TAMPER_DETECTED"
