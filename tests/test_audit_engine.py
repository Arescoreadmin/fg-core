from __future__ import annotations


import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.db import init_db, reset_engine_cache
from services.audit_engine.engine import (
    AuditEngine,
    AuditTamperDetected,
    InvariantResult,
)


@pytest.fixture
def audit_engine(tmp_path, monkeypatch) -> AuditEngine:
    db_path = tmp_path / "audit.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_CURRENT", "unit-test-key-unit-test-key-unit!!")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak1")
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    eng = AuditEngine()
    monkeypatch.setattr(
        eng,
        "_invariants",
        lambda: [
            InvariantResult("soc-invariants", "pass", "ok"),
            InvariantResult("security-regression-gates", "pass", "ok"),
        ],
    )
    return eng


def test_append_only_enforced(audit_engine: AuditEngine) -> None:
    audit_engine.run_cycle("light")
    with Session(audit_engine.engine) as session:
        with pytest.raises(SQLAlchemyError):
            session.execute(text("UPDATE audit_ledger SET decision='fail' WHERE id=1"))
            session.commit()


def test_hash_chain_integrity_detects_injected_row(audit_engine: AuditEngine) -> None:
    audit_engine.run_cycle("light")
    with Session(audit_engine.engine) as session:
        assert audit_engine.verify_chain_integrity(session)
        session.execute(
            text(
                "INSERT INTO audit_ledger(session_id,cycle_kind,timestamp_utc,invariant_id,decision,config_hash,policy_hash,git_commit,runtime_version,host_id,tenant_id,sha256_engine_code_hash,sha256_self_hash,previous_record_hash,signature,details_json) VALUES ('x','light','2026-01-01T00:00:00Z','tampered','pass','a','b','c','d','tenant-a','tenant-a','e','f','g','h','{}')"
            )
        )
        session.commit()
    with Session(audit_engine.engine) as session:
        assert not audit_engine.verify_chain_integrity(session)


def test_tamper_detection_fail_closed(audit_engine: AuditEngine) -> None:
    audit_engine.run_cycle("light")
    with Session(audit_engine.engine) as session:
        session.execute(
            text(
                "INSERT INTO audit_ledger(session_id,cycle_kind,timestamp_utc,invariant_id,decision,config_hash,policy_hash,git_commit,runtime_version,host_id,tenant_id,sha256_engine_code_hash,sha256_self_hash,previous_record_hash,signature,details_json) VALUES ('x','light','2026-01-01T00:00:00Z','tampered','pass','a','b','c','d','tenant-a','tenant-a','e','f','g','h','{}')"
            )
        )
        session.commit()
    with pytest.raises(AuditTamperDetected):
        audit_engine.run_cycle("light")


def test_reproducibility_mismatch_detected(audit_engine: AuditEngine, monkeypatch) -> None:
    sid = audit_engine.run_cycle("light")
    monkeypatch.setattr(
        audit_engine,
        "_invariants",
        lambda: [InvariantResult("soc-invariants", "fail", "changed")],
    )
    result = audit_engine.reproduce_session(sid)
    assert not result["ok"]
    assert result["reason"] == "reproducibility_mismatch"
    assert result["critical_alert"] is True


def test_deterministic_export(audit_engine: AuditEngine) -> None:
    audit_engine.run_cycle("light")
    first = audit_engine.export_bundle(
        start="1970-01-01T00:00:00Z",
        end="9999-12-31T23:59:59Z",
        app_openapi={"openapi": "3.1.0"},
        tenant_id="tenant-a",
    )
    second = audit_engine.export_bundle(
        start="1970-01-01T00:00:00Z",
        end="9999-12-31T23:59:59Z",
        app_openapi={"openapi": "3.1.0"},
        tenant_id="tenant-a",
    )
    assert first["manifest"]["bundle_sha256"] == second["manifest"]["bundle_sha256"]


def test_exam_export_is_deterministic(audit_engine: AuditEngine) -> None:
    import hashlib
    from pathlib import Path

    audit_engine.run_cycle("light")
    exam_id = audit_engine.create_exam(
        tenant_id="tenant-a",
        name="semi-annual",
        window_start="1970-01-01T00:00:00Z",
        window_end="9999-12-31T23:59:59Z",
    )
    a = audit_engine.export_exam_bundle(exam_id, app_openapi={"openapi": "3.1.0"})
    first_bytes = Path(a["archive_path"]).read_bytes()
    b = audit_engine.export_exam_bundle(exam_id, app_openapi={"openapi": "3.1.0"})
    second_bytes = Path(b["archive_path"]).read_bytes()
    assert hashlib.sha256(first_bytes).hexdigest() == hashlib.sha256(second_bytes).hexdigest()


def test_exam_reproduce(audit_engine: AuditEngine) -> None:
    sid = audit_engine.run_cycle("light")
    assert sid
    exam_id = audit_engine.create_exam(
        tenant_id="tenant-a",
        name="semi-annual",
        window_start="1970-01-01T00:00:00Z",
        window_end="9999-12-31T23:59:59Z",
    )
    result = audit_engine.reproduce_exam(exam_id)
    assert result["ok"] is True
    assert set(result["hashes"]) == {"expected", "actual"}


def test_key_rotation_old_record_verifiable(audit_engine: AuditEngine, monkeypatch) -> None:
    audit_engine.run_cycle("light")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_CURRENT", "new-key-new-key-new-key-new-key-0000")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak2")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_PREV", "unit-test-key-unit-test-key-unit!!")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_PREV", "ak1")
    with Session(audit_engine.engine) as session:
        assert audit_engine.verify_chain_integrity(session)




def test_unknown_key_id_fails_chain_verification(audit_engine: AuditEngine, monkeypatch) -> None:
    audit_engine.run_cycle("light")
    monkeypatch.delenv("FG_AUDIT_HMAC_KEY_PREV", raising=False)
    monkeypatch.delenv("FG_AUDIT_HMAC_KEY_ID_PREV", raising=False)
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_CURRENT", "another-audit-key-another-audit-key-0000")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak9")
    with Session(audit_engine.engine) as session:
        assert not audit_engine.verify_chain_integrity(session)
