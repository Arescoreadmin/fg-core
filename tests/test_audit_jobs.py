from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from api.db_models import AuditLedgerRecord
from services.audit_engine import append_audit_record, cancel_export_job, enqueue_export_job, run_export_job


def _setup(tmp_path, monkeypatch):
    db_path = tmp_path / "jobs.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return get_engine(sqlite_path=str(db_path))


def test_export_job_queue_idempotent_and_resumable(tmp_path, monkeypatch):
    engine = _setup(tmp_path, monkeypatch)
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="inv", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        now = datetime.now(tz=UTC)
        a = enqueue_export_job(
            db,
            tenant_id="t1",
            start=now - timedelta(days=1),
            end=now,
            purpose="audit",
            retention_class="regulated",
            triggered_by="tester",
            signing_kid="kid-1",
        )
        b = enqueue_export_job(
            db,
            tenant_id="t1",
            start=now - timedelta(days=1),
            end=now,
            purpose="audit",
            retention_class="regulated",
            triggered_by="tester",
            signing_kid="kid-1",
        )
        assert a.job_id == b.job_id
        done = run_export_job(db, tenant_id="t1", job_id=a.job_id, worker_id="w1")
        assert done.status == "succeeded"
        assert done.attempts >= 1
        again = run_export_job(db, tenant_id="t1", job_id=a.job_id, worker_id="w2")
        assert again.status == "succeeded"


def test_export_job_can_be_cancelled_and_not_executed(tmp_path, monkeypatch):
    engine = _setup(tmp_path, monkeypatch)
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="inv", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        now = datetime.now(tz=UTC)
        job = enqueue_export_job(
            db,
            tenant_id="t1",
            start=now - timedelta(days=1),
            end=now,
            purpose="audit",
            retention_class="regulated",
            triggered_by="tester",
            signing_kid="kid-1",
        )
        cancelled = cancel_export_job(db, tenant_id="t1", job_id=job.job_id, cancelled_by="auditor")
        assert cancelled.status == "cancelled"
        assert cancelled.last_error_code == "AUDIT_EXPORT_JOB_CANCELLED"
        assert int(cancelled.job_event_seq) == 1
        rerun = run_export_job(db, tenant_id="t1", job_id=job.job_id, worker_id="w1")
        assert rerun.status == "cancelled"
        assert rerun.last_error_code == "AUDIT_EXPORT_JOB_CANCELLED"
        assert int(rerun.job_event_seq) == 1
        ledger_row = db.query(AuditLedgerRecord).filter(AuditLedgerRecord.tenant_id == "t1", AuditLedgerRecord.invariant_id.like(f"audit-export-job-cancel:{job.job_id}:%")).one()
        assert ledger_row.decision == "pass"



def test_cancel_export_job_terminal_state_conflict(tmp_path, monkeypatch):
    engine = _setup(tmp_path, monkeypatch)
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="inv", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        now = datetime.now(tz=UTC)
        job = enqueue_export_job(
            db,
            tenant_id="t1",
            start=now - timedelta(days=1),
            end=now,
            purpose="audit",
            retention_class="regulated",
            triggered_by="tester",
            signing_kid="kid-1",
        )
        done = run_export_job(db, tenant_id="t1", job_id=job.job_id, worker_id="w1")
        assert done.status == "succeeded"
        assert int(done.job_event_seq) >= 1

        with pytest.raises(RuntimeError, match="AUDIT_EXPORT_JOB_TERMINAL_STATE"):
            cancel_export_job(db, tenant_id="t1", job_id=job.job_id, cancelled_by="auditor")



def test_cancel_idempotent_under_race_like_conditions(tmp_path, monkeypatch):
    engine = _setup(tmp_path, monkeypatch)
    now = datetime.now(tz=UTC)
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="inv", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        job = enqueue_export_job(
            db,
            tenant_id="t1",
            start=now - timedelta(days=1),
            end=now,
            purpose="audit",
            retention_class="regulated",
            triggered_by="tester",
        )
        db.commit()
        job_id = job.job_id

    with Session(engine) as db1, Session(engine) as db2:
        c1 = cancel_export_job(db1, tenant_id="t1", job_id=job_id, cancelled_by="actor-1", reason_code="OPERATOR_ERROR", ticket_id="OPS-21")
        c2 = cancel_export_job(db2, tenant_id="t1", job_id=job_id, cancelled_by="actor-2", reason_code="OPERATOR_ERROR", ticket_id="OPS-22")
        assert c1.status == "cancelled"
        assert c2.status == "cancelled"



def test_terminal_state_db_guard(tmp_path, monkeypatch):
    engine = _setup(tmp_path, monkeypatch)
    now = datetime.now(tz=UTC)
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="inv", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        job = enqueue_export_job(
            db,
            tenant_id="t1",
            start=now - timedelta(days=1),
            end=now,
            purpose="audit",
            retention_class="regulated",
            triggered_by="tester",
        )
        db.commit()
        cancel_export_job(db, tenant_id="t1", job_id=job.job_id, cancelled_by="actor", reason_code="OPERATOR_ERROR", ticket_id="OPS-31")

        with pytest.raises(DBAPIError):
            db.execute(text("UPDATE audit_export_jobs SET status='running' WHERE job_id=:job_id"), {"job_id": job.job_id})
            db.commit()

