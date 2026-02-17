from __future__ import annotations

import pytest
from fastapi import HTTPException

from api.audit import ReproduceRequest, audit_reproduce
from api.db import init_db, reset_engine_cache
from services.audit_engine.engine import InvariantResult


@pytest.fixture
def isolated_audit_env(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "audit_exam_api.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))


def test_reproduce_mismatch_returns_non_200(monkeypatch, isolated_audit_env):
    from services.audit_engine.engine import AuditEngine

    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "api-audit-key-api-audit-key-api-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-api")
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng,
        "_invariants",
        lambda: [InvariantResult("soc-invariants", "pass", "ok")],
    )
    sid = eng.run_cycle("light")
    monkeypatch.setattr(
        eng,
        "_invariants",
        lambda: [InvariantResult("soc-invariants", "fail", "changed")],
    )
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    with pytest.raises(HTTPException) as exc:
        audit_reproduce(ReproduceRequest(session_id=sid))
    assert exc.value.status_code == 409


def test_export_chain_failure_returns_non_200(monkeypatch, isolated_audit_env):
    from services.audit_engine.engine import AuditEngine

    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "api-audit-key-api-audit-key-api-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-api")
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("soc-invariants", "pass", "ok")]
    )
    _ = eng.run_cycle("light")
    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "different-key-different-key-diff-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-new")
    monkeypatch.delenv("FG_AUDIT_HMAC_KEY_PREV", raising=False)
    monkeypatch.delenv("FG_AUDIT_HMAC_KEY_ID_PREV", raising=False)
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    with pytest.raises(HTTPException) as exc:
        from api.audit import audit_export
        from types import SimpleNamespace

        class DummyReq:
            state = SimpleNamespace(tenant_id="tenant-a", tenant_is_key_bound=True)
            app = SimpleNamespace(openapi=lambda: {"openapi": "3.1.0"})

        audit_export(DummyReq(), "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "AUDIT_CHAIN_BROKEN"
