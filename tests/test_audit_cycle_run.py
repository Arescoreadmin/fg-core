"""
Regression tests for the audit cycle run flow:
  POST /audit/cycle/run  — trigger
  GET  /audit/sessions   — retrieval

Covers: happy path, tenant isolation, precondition failures, tamper detection,
auth guards, blank-tenant safety, and cross-tenant retrieval denial.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from api.audit import CycleRunRequest, audit_sessions, run_audit_cycle
from api.auth_scopes import require_bound_tenant
from api.db import get_engine, init_db, reset_engine_cache
from services.audit_engine.engine import (
    AuditEngine,
    AuditIntegrityError,
    InvariantResult,
)

_HMAC_KEY = "test-cycle-key-test-cycle-key-te"
_HMAC_KEY_ID = "ak-cycle-test"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_cycle.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_CURRENT", _HMAC_KEY)
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", _HMAC_KEY_ID)
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return db_path


@pytest.fixture()
def audit_eng(isolated_db, monkeypatch):
    eng = AuditEngine()
    monkeypatch.setattr(
        eng,
        "_invariants",
        lambda: [
            InvariantResult("soc-invariants", "pass", "ok"),
            InvariantResult("route-inventory", "pass", "ok"),
        ],
    )
    return eng


def _bound_request(tenant_id: str) -> object:
    """Minimal request stub accepted by require_bound_tenant and audit_admin_action."""
    return SimpleNamespace(
        state=SimpleNamespace(
            tenant_id=tenant_id,
            tenant_is_key_bound=True,
            auth=SimpleNamespace(
                key_prefix="test-key-prefix",
                scopes={"audit:write"},
            ),
            request_id="test-req-cycle-001",
        ),
        app=SimpleNamespace(openapi=lambda: {"openapi": "3.1.0"}),
        headers={},
        client=None,
        method="POST",
        url=SimpleNamespace(path="/audit/cycle/run"),
    )


def _unbound_request() -> object:
    """Request where tenant_is_key_bound is False."""
    return SimpleNamespace(
        state=SimpleNamespace(tenant_id=None, tenant_is_key_bound=False),
    )


# ---------------------------------------------------------------------------
# 1. Happy-path end-to-end flow
# ---------------------------------------------------------------------------


def test_run_cycle_returns_session_id(audit_eng, monkeypatch):
    monkeypatch.setattr("api.audit.AuditEngine", lambda: audit_eng)
    result = run_audit_cycle(
        CycleRunRequest(cycle_kind="light"), _bound_request("tenant-a")
    )
    assert "session_id" in result
    assert result["cycle_kind"] == "light"
    assert len(result["session_id"]) == 36  # UUID format


def test_run_cycle_persists_records(audit_eng, monkeypatch):
    monkeypatch.setattr("api.audit.AuditEngine", lambda: audit_eng)
    result = run_audit_cycle(
        CycleRunRequest(cycle_kind="light"), _bound_request("tenant-a")
    )
    session_id = result["session_id"]
    from api.db_models import AuditLedgerRecord

    with Session(get_engine()) as s:
        rows = (
            s.query(AuditLedgerRecord)
            .filter(AuditLedgerRecord.session_id == session_id)
            .all()
        )
    assert len(rows) >= 1
    assert all(r.tenant_id == "tenant-a" for r in rows)


def test_run_cycle_then_sessions_retrieval(audit_eng, monkeypatch):
    """POST /audit/cycle/run followed by GET /audit/sessions returns that session."""
    monkeypatch.setattr("api.audit.AuditEngine", lambda: audit_eng)
    run_result = run_audit_cycle(
        CycleRunRequest(cycle_kind="light"), _bound_request("tenant-a")
    )
    session_id = run_result["session_id"]

    sessions_result = audit_sessions(_bound_request("tenant-a"))
    session_ids = [s["session_id"] for s in sessions_result["sessions"]]
    assert session_id in session_ids


def test_sessions_retrieval_contains_correct_cycle_kind(audit_eng, monkeypatch):
    monkeypatch.setattr("api.audit.AuditEngine", lambda: audit_eng)
    run_result = run_audit_cycle(
        CycleRunRequest(cycle_kind="light"), _bound_request("tenant-a")
    )
    session_id = run_result["session_id"]

    sessions_result = audit_sessions(_bound_request("tenant-a"))
    matched = [s for s in sessions_result["sessions"] if s["session_id"] == session_id]
    assert len(matched) == 1
    assert matched[0]["cycle_kind"] == "light"
    assert matched[0]["records"] >= 1


def test_run_cycle_full_kind(audit_eng, monkeypatch):
    monkeypatch.setattr("api.audit.AuditEngine", lambda: audit_eng)
    result = run_audit_cycle(
        CycleRunRequest(cycle_kind="full"), _bound_request("tenant-a")
    )
    assert result["cycle_kind"] == "full"


# ---------------------------------------------------------------------------
# 2. Preconditions: cycle_kind validation
# ---------------------------------------------------------------------------


def test_invalid_cycle_kind_rejected_by_model():
    with pytest.raises(Exception) as exc:
        CycleRunRequest(cycle_kind="deep_sweep")
    assert "cycle_kind" in str(exc.value).lower() or "value" in str(exc.value).lower()


def test_extra_request_fields_rejected_by_model():
    with pytest.raises(Exception) as exc:
        CycleRunRequest(cycle_kind="light", unknown_field="bad")
    assert exc.value is not None


# ---------------------------------------------------------------------------
# 3. Tenant context safety at engine service boundary
# ---------------------------------------------------------------------------


def test_engine_blank_tenant_raises_explicit_error(isolated_db, monkeypatch):
    """Blank tenant_id cannot silently fall back when explicitly provided."""
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    with pytest.raises(AuditIntegrityError) as exc:
        eng.run_cycle("light", tenant_id="")
    assert exc.value.code == "AUDIT_TENANT_REQUIRED"


def test_engine_whitespace_tenant_raises_explicit_error(isolated_db, monkeypatch):
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    with pytest.raises(AuditIntegrityError) as exc:
        eng.run_cycle("light", tenant_id="   ")
    assert exc.value.code == "AUDIT_TENANT_REQUIRED"


def test_engine_none_tenant_uses_env_fallback(isolated_db, monkeypatch):
    """Legacy non-API callers (None tenant_id) still fall back to env."""
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "env-tenant")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    session_id = eng.run_cycle("light", tenant_id=None)
    assert session_id is not None
    from api.db_models import AuditLedgerRecord

    with Session(get_engine()) as s:
        rows = (
            s.query(AuditLedgerRecord)
            .filter(AuditLedgerRecord.session_id == session_id)
            .all()
        )
    assert all(r.tenant_id == "env-tenant" for r in rows)


def test_api_provided_tenant_overrides_env(isolated_db, monkeypatch):
    """API-provided tenant_id must NOT fall back to env tenant."""
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "env-tenant")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    session_id = eng.run_cycle("light", tenant_id="api-tenant")
    from api.db_models import AuditLedgerRecord

    with Session(get_engine()) as s:
        rows = (
            s.query(AuditLedgerRecord)
            .filter(AuditLedgerRecord.session_id == session_id)
            .all()
        )
    assert all(r.tenant_id == "api-tenant" for r in rows)
    assert not any(r.tenant_id == "env-tenant" for r in rows)


# ---------------------------------------------------------------------------
# 4. Tampered chain → explicit 409
# ---------------------------------------------------------------------------


def test_tampered_chain_returns_409(isolated_db, monkeypatch):
    from sqlalchemy import text as sa_text

    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    eng.run_cycle("light", tenant_id="tenant-a")

    # inject a tampered row to break chain integrity
    with Session(get_engine()) as s:
        s.execute(
            sa_text(
                "INSERT INTO audit_ledger("
                "session_id,cycle_kind,timestamp_utc,invariant_id,decision,"
                "config_hash,policy_hash,git_commit,runtime_version,host_id,"
                "tenant_id,sha256_engine_code_hash,sha256_self_hash,"
                "previous_record_hash,signature,details_json) "
                "VALUES ('tamper','light','2026-01-01T00:00:00Z','x','pass',"
                "'a','b','c','d','tenant-a','tenant-a','e','f','g','h','{}')"
            )
        )
        s.commit()

    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)
    with pytest.raises(HTTPException) as exc:
        run_audit_cycle(CycleRunRequest(cycle_kind="light"), _bound_request("tenant-a"))
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "AUDIT_CHAIN_TAMPERED"


# ---------------------------------------------------------------------------
# 5. Auth guard: unbound tenant rejected
# ---------------------------------------------------------------------------


def test_unbound_tenant_rejected_by_guard():
    with pytest.raises(HTTPException) as exc:
        require_bound_tenant(_unbound_request())
    assert exc.value.status_code == 400


def test_bound_tenant_accepted_by_guard():
    result = require_bound_tenant(_bound_request("tenant-x"))
    assert result == "tenant-x"


# ---------------------------------------------------------------------------
# 6. Cross-tenant isolation on execution and retrieval
# ---------------------------------------------------------------------------


def test_cross_tenant_execution_isolation(isolated_db, monkeypatch):
    """Cycle run for tenant-a must not write records tagged for tenant-b."""
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    session_id = eng.run_cycle("light", tenant_id="tenant-a")

    from api.db_models import AuditLedgerRecord

    with Session(get_engine()) as s:
        b_rows = (
            s.query(AuditLedgerRecord)
            .filter(
                AuditLedgerRecord.session_id == session_id,
                AuditLedgerRecord.tenant_id == "tenant-b",
            )
            .all()
        )
    assert b_rows == []


def test_cross_tenant_retrieval_denied_on_sessions(isolated_db, monkeypatch):
    """GET /audit/sessions for tenant-b returns empty when only tenant-a has records."""
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    eng.run_cycle("light", tenant_id="tenant-a")

    result = audit_sessions(_bound_request("tenant-b"))
    assert result["sessions"] == []


def test_sessions_returns_only_own_tenant_records(isolated_db, monkeypatch):
    """GET /audit/sessions for tenant-a does not expose tenant-b sessions."""
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    sid_a = eng.run_cycle("light", tenant_id="tenant-a")
    sid_b = eng.run_cycle("light", tenant_id="tenant-b")

    result_a = audit_sessions(_bound_request("tenant-a"))
    session_ids_a = [s["session_id"] for s in result_a["sessions"]]
    assert sid_a in session_ids_a
    assert sid_b not in session_ids_a

    result_b = audit_sessions(_bound_request("tenant-b"))
    session_ids_b = [s["session_id"] for s in result_b["sessions"]]
    assert sid_b in session_ids_b
    assert sid_a not in session_ids_b


# ---------------------------------------------------------------------------
# 7. Retrieval truthfulness
# ---------------------------------------------------------------------------


def test_sessions_empty_before_any_run(isolated_db):
    result = audit_sessions(_bound_request("tenant-a"))
    assert result["sessions"] == []


def test_sessions_records_count_matches_invariants(isolated_db, monkeypatch):
    eng = AuditEngine()
    invariants = [
        InvariantResult("inv-1", "pass", "ok"),
        InvariantResult("inv-2", "pass", "ok"),
        InvariantResult("inv-3", "fail", "issue"),
    ]
    monkeypatch.setattr(eng, "_invariants", lambda: invariants)
    session_id = eng.run_cycle("light", tenant_id="tenant-a")

    result = audit_sessions(_bound_request("tenant-a"))
    matched = [s for s in result["sessions"] if s["session_id"] == session_id]
    assert len(matched) == 1
    assert matched[0]["records"] == len(invariants)


# ---------------------------------------------------------------------------
# 8. Revoked-tenant denial
# ---------------------------------------------------------------------------


def _patch_registry(monkeypatch, registry_dict: dict) -> None:
    """Patch tools.tenants.registry.load_registry to return a fixed dict."""
    import tools.tenants.registry as _reg_mod
    from tools.tenants.registry import TenantRecord

    def _fake_load():
        out = {}
        for tid, payload in registry_dict.items():
            out[tid] = TenantRecord.from_dict({"tenant_id": tid, **payload})
        return out

    monkeypatch.setattr(_reg_mod, "load_registry", _fake_load)


def _make_revoked_registry(monkeypatch, tenant_id: str) -> None:
    """Patch registry so tenant_id appears revoked."""
    _patch_registry(
        monkeypatch,
        {
            tenant_id: {
                "api_key": "test-key-revoked",
                "status": "revoked",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
            }
        },
    )


def _make_active_registry(monkeypatch, tenant_id: str) -> None:
    """Patch registry so tenant_id appears active."""
    _patch_registry(
        monkeypatch,
        {
            tenant_id: {
                "api_key": "test-key-active",
                "status": "active",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
            }
        },
    )


def test_revoked_tenant_denied_on_cycle_run(isolated_db, monkeypatch):
    """Revoked tenant in registry must not be able to trigger a cycle run."""
    _make_revoked_registry(monkeypatch, "tenant-revoked")
    monkeypatch.setattr(
        "api.audit.AuditEngine",
        lambda: _make_mocked_engine(isolated_db, monkeypatch),
    )
    with pytest.raises(HTTPException) as exc:
        run_audit_cycle(
            CycleRunRequest(cycle_kind="light"), _bound_request("tenant-revoked")
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "TENANT_REVOKED"


def _make_mocked_engine(isolated_db, monkeypatch):
    """Helper: return an AuditEngine with _invariants stubbed."""
    eng = AuditEngine()
    eng._invariants = lambda: [InvariantResult("inv-1", "pass", "ok")]  # type: ignore[method-assign]
    return eng


def test_revoked_tenant_creates_no_ledger_state(isolated_db, monkeypatch):
    """Revoked tenant denial must occur before any persistence."""
    _make_revoked_registry(monkeypatch, "tenant-revoked")
    monkeypatch.setattr(
        "api.audit.AuditEngine",
        lambda: _make_mocked_engine(isolated_db, monkeypatch),
    )
    try:
        run_audit_cycle(
            CycleRunRequest(cycle_kind="light"), _bound_request("tenant-revoked")
        )
    except HTTPException:
        pass

    from api.db_models import AuditLedgerRecord

    with Session(get_engine()) as s:
        rows = (
            s.query(AuditLedgerRecord)
            .filter(AuditLedgerRecord.tenant_id == "tenant-revoked")
            .all()
        )
    assert rows == []


def test_active_tenant_in_registry_allowed(isolated_db, monkeypatch):
    """Active tenant in registry can still run cycle successfully."""
    _make_active_registry(monkeypatch, "tenant-active")
    eng = _make_mocked_engine(isolated_db, monkeypatch)
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)
    result = run_audit_cycle(
        CycleRunRequest(cycle_kind="light"), _bound_request("tenant-active")
    )
    assert "session_id" in result
    assert result["cycle_kind"] == "light"


def test_tenant_not_in_registry_allowed(isolated_db, monkeypatch):
    """Tenant absent from registry (no revocation recorded) is allowed through."""
    _patch_registry(monkeypatch, {})  # empty registry
    eng = _make_mocked_engine(isolated_db, monkeypatch)
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)
    result = run_audit_cycle(
        CycleRunRequest(cycle_kind="light"), _bound_request("tenant-unknown")
    )
    assert "session_id" in result


# ---------------------------------------------------------------------------
# 9. Fail-closed registry exception (Fix B)
# ---------------------------------------------------------------------------


def test_registry_exception_returns_503(isolated_db, monkeypatch):
    """Registry errors must not be swallowed; they must yield 503 TENANT_STATE_UNAVAILABLE."""
    import tools.tenants.registry as _reg_mod

    def _boom():
        raise OSError("registry disk read failure")

    monkeypatch.setattr(_reg_mod, "load_registry", _boom)
    eng = _make_mocked_engine(isolated_db, monkeypatch)
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    with pytest.raises(HTTPException) as exc:
        run_audit_cycle(CycleRunRequest(cycle_kind="light"), _bound_request("tenant-a"))
    assert exc.value.status_code == 503
    assert exc.value.detail["code"] == "TENANT_STATE_UNAVAILABLE"


def test_registry_exception_creates_no_ledger_state(isolated_db, monkeypatch):
    """On registry I/O error, no AuditLedgerRecord rows are written."""
    import tools.tenants.registry as _reg_mod

    def _boom():
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(_reg_mod, "load_registry", _boom)
    eng = _make_mocked_engine(isolated_db, monkeypatch)
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    try:
        run_audit_cycle(CycleRunRequest(cycle_kind="light"), _bound_request("tenant-a"))
    except HTTPException:
        pass

    from api.db_models import AuditLedgerRecord

    with Session(get_engine()) as s:
        rows = (
            s.query(AuditLedgerRecord)
            .filter(AuditLedgerRecord.tenant_id == "tenant-a")
            .all()
        )
    assert rows == []


# ---------------------------------------------------------------------------
# 10. Literal type schema validation (Fix A)
# ---------------------------------------------------------------------------


def test_invalid_cycle_kind_rejected_at_schema_level():
    """Literal type must reject invalid values with a schema validation error."""
    with pytest.raises(Exception) as exc:
        CycleRunRequest(cycle_kind="extreme_sweep")
    err = str(exc.value).lower()
    # Pydantic Literal validation names the field and the allowed values
    assert "cycle_kind" in err or "light" in err or "full" in err


def test_valid_cycle_kinds_accepted():
    """Both allowed literal values must parse without error."""
    req_light = CycleRunRequest(cycle_kind="light")
    req_full = CycleRunRequest(cycle_kind="full")
    assert req_light.cycle_kind == "light"
    assert req_full.cycle_kind == "full"


def test_default_cycle_kind_is_light():
    """Default cycle_kind must be 'light'."""
    req = CycleRunRequest()
    assert req.cycle_kind == "light"
