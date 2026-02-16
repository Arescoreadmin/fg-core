from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from api.db_models import AuditChainCheckpoint, AuditExport, ConfigVersion
from services.audit_engine.engine import (
    append_audit_record,
    deterministic_export_bundle,
    export_evidence_bundle,
    reproduce_audit_session,
    verify_audit_chain,
)


def _setup_db(tmp_path, monkeypatch):
    db_path = tmp_path / "audit.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUDIT_HMAC_KEYS", "k-active,k-previous")
    monkeypatch.setenv("FG_AUDIT_CHECKPOINT_INTERVAL", "3")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return get_engine(sqlite_path=str(db_path))


def test_hash_chain_integrity_and_checkpoint(tmp_path, monkeypatch):
    engine = _setup_db(tmp_path, monkeypatch)
    with Session(engine) as db:
        for i in range(7):
            append_audit_record(db, tenant_id="t1", invariant_id=f"inv-{i}", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        result = verify_audit_chain(db, tenant_id="t1")
        assert result["ok"] is True
        assert db.query(AuditChainCheckpoint).filter(AuditChainCheckpoint.tenant_id == "t1").count() >= 2


def test_tamper_detection_within_checkpoint_segment(tmp_path, monkeypatch):
    engine = _setup_db(tmp_path, monkeypatch)
    with Session(engine) as db:
        for i in range(5):
            append_audit_record(db, tenant_id="t1", invariant_id=f"inv-{i}", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.execute(
            text("INSERT INTO audit_ledger(tenant_id,timestamp_utc,invariant_id,decision,config_hash,policy_hash,git_commit,runtime_version,host_id,sha256_self_hash,previous_record_hash,signature) VALUES ('t1','2026-01-01T00:00:00Z','tampered','pass',:cfg,:pol,'x','x','x',:self_hash,'broken-prev','deadbeef')"),
            {"cfg": "a" * 64, "pol": "b" * 64, "self_hash": "c" * 64},
        )
        db.commit()
        result = verify_audit_chain(db, tenant_id="t1")
        assert result["ok"] is False


def test_append_only_enforcement(tmp_path, monkeypatch):
    engine = _setup_db(tmp_path, monkeypatch)
    with Session(engine) as db:
        rec = append_audit_record(db, tenant_id="t1", invariant_id="soc-invariants", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        with pytest.raises(DBAPIError):
            db.execute(text("DELETE FROM audit_ledger WHERE id=:id"), {"id": rec.id})
            db.commit()


def test_deterministic_export_hash_and_bytes_equality(tmp_path, monkeypatch):
    engine = _setup_db(tmp_path, monkeypatch)
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="soc-invariants", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.add(
            ConfigVersion(
                tenant_id="t1",
                config_hash="c" * 64,
                created_by="test",
                config_json={"b": [2, 1], "a": 1},
                config_json_canonical='{"a":1,"b":[2,1]}',
            )
        )
        db.commit()

        end = datetime.now(tz=UTC)
        start = end - timedelta(days=1)
        first = deterministic_export_bundle(db, tenant_id="t1", start=start, end=end)
        second = deterministic_export_bundle(db, tenant_id="t1", start=start, end=end)
        assert first["manifest"]["bundle_sha256"] == second["manifest"]["bundle_sha256"]
        assert first["manifest"]["root_hash"] == second["manifest"]["root_hash"]


def test_evidence_metadata_and_no_churn(tmp_path, monkeypatch):
    engine = _setup_db(tmp_path, monkeypatch)
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="soc-invariants", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        now = datetime.now(tz=UTC)
        one = export_evidence_bundle(db, tenant_id="t1", start=now - timedelta(days=1), end=now, purpose="audit", triggered_by="u1", retention_class="regulated")
        two = export_evidence_bundle(db, tenant_id="t1", start=now - timedelta(days=1), end=now, purpose="audit", triggered_by="u1", retention_class="regulated")
        assert one["manifest"]["bundle_sha256"] == two["manifest"]["bundle_sha256"]
        assert one["manifest"]["range_end_inclusive"] is True
        assert two["deduplicated"] is True
        row = db.query(AuditExport).filter(AuditExport.tenant_id == "t1").first()
        assert row is not None
        assert row.export_range_end_inclusive is True


def test_reproducibility_mismatch(tmp_path, monkeypatch):
    engine = _setup_db(tmp_path, monkeypatch)
    with Session(engine) as db:
        rec = append_audit_record(db, tenant_id="t1", invariant_id="config-hash-validation", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        result = reproduce_audit_session(db, tenant_id="t1", session_id=rec.id)
        assert result["verification_result"] == "fail"
        assert result["deterministic_hash_comparison"] == "mismatch"
