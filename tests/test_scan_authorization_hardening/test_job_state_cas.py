"""DurableJobService compare-and-swap transitions against a real SQLite ORM session.

A cancel_requested / cancelled / terminal job can never be revived to running or
overwritten by a late completion or failure.  L14-SCAN-AUTH-HARDENING-001.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FG_ENV", "test")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.db_models_field_assessment import FaScanJob
from services.field_assessment.durable_job_service import DurableJobService


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    FaScanJob.__table__.create(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _job(db, status, scanner_type="web_headers", attempts=0):
    j = FaScanJob(
        id=f"job-{status}-{scanner_type}",
        tenant_id="t1",
        engagement_id="e1",
        verified_target_ids="[]",
        scanner_type=scanner_type,
        status=status,
        attempt_count=attempts,
        max_retries=3,
        actor="a",
        created_at="2026-11-08T00:00:00Z",
    )
    db.add(j)
    db.commit()
    return j.id


def _status(db, jid):
    db.expire_all()
    return db.get(FaScanJob, jid).status


svc = DurableJobService()


class TestMarkRunning:
    def test_queued_to_running(self, db):
        jid = _job(db, "queued")
        assert svc.mark_running(db, job_id=jid) is True
        assert _status(db, jid) == "running"

    @pytest.mark.parametrize(
        "status",
        [
            "cancel_requested",
            "cancelled",
            "complete",
            "failed",
            "dead_letter",
            "running",
        ],
    )
    def test_non_queued_never_restarted(self, db, status):
        jid = _job(db, status)
        assert svc.mark_running(db, job_id=jid) is False
        assert _status(db, jid) == status


class TestMarkComplete:
    def test_running_to_complete(self, db):
        jid = _job(db, "running")
        assert svc.mark_complete(db, job_id=jid, scan_result_id="sr") is True
        assert _status(db, jid) == "complete"

    @pytest.mark.parametrize(
        "status", ["cancel_requested", "cancelled", "queued", "failed", "dead_letter"]
    )
    def test_late_completion_never_overwrites(self, db, status):
        jid = _job(db, status)
        assert svc.mark_complete(db, job_id=jid, scan_result_id="sr") is False
        assert _status(db, jid) == status

    def test_completed_scan_cannot_be_overwritten(self, db):
        jid = _job(db, "complete")
        assert svc.mark_complete(db, job_id=jid, scan_result_id="other") is False
        db.expire_all()
        assert db.get(FaScanJob, jid).scan_result_id is None


class TestMarkFailed:
    @pytest.mark.parametrize(
        "status", ["cancel_requested", "cancelled", "complete", "dead_letter"]
    )
    def test_failure_never_overwrites_cancel_or_terminal(self, db, status):
        jid = _job(db, status)
        assert svc.mark_failed(db, job_id=jid, failure_reason="boom") is False
        assert _status(db, jid) == status

    def test_running_retryable_goes_failed(self, db):
        jid = _job(db, "running")
        assert svc.mark_failed(db, job_id=jid, failure_reason="boom") is True
        assert _status(db, jid) == "failed"

    def test_running_non_retryable_goes_dead_letter(self, db):
        jid = _job(db, "running", scanner_type="microsoft_graph")
        assert svc.mark_failed(db, job_id=jid, failure_reason="boom") is True
        assert _status(db, jid) == "dead_letter"

    def test_missing_job(self, db):
        assert svc.mark_failed(db, job_id="nope", failure_reason="x") is False
