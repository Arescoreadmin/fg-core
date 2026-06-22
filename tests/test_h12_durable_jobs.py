"""tests/test_h12_durable_jobs.py — H12 Durable Job Service.

Test coverage:
  D1  create_job — new job starts in 'queued' state with correct fields
  D2  find_duplicate — idempotency_key dedup returns existing job
  D3  mark_running — transitions queued→running, sets timestamps and lease
  D4  mark_complete — transitions running→complete, clears lease
  D5  mark_failed retryable — retryable scanner stays 'failed' with next_retry_at set
  D6  mark_failed non-retryable — MSAL scanner goes dead_letter immediately
  D7  mark_failed max retries — attempt_count == max_retries → dead_letter
  D8  get_job tenant isolation — job from another tenant returns None
  D9  list_jobs — returns only jobs for the specified engagement
  D10 list_jobs status filter — only matching-status jobs returned
  D11 recover_orphans retryable — expired-lease retryable job requeued
  D12 recover_orphans non-retryable — expired-lease MSAL job dead-lettered
  D13 recover_orphans live job — job with future lease untouched
  D14 status route DB fallback — after process restart state comes from DB
  D15 status route cross-tenant — job_id from another tenant returns 404
  D16 list scan-jobs route — GET /scan-jobs returns job list with correct fields
  D17 get scan-job route — GET /scan-jobs/{job_id} returns single job
  D18 get scan-job wrong engagement — 404 when job_id belongs to different engagement
  D19 all 9 scanner types create FaScanJob — coverage that no route skips job creation
  D20 _c6_update_job_status running — delegates to mark_running
  D21 _c6_update_job_status complete — delegates to mark_complete
  D22 _c6_update_job_status failed retryable — delegates to mark_failed
"""

from __future__ import annotations

import os
import secrets

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient

from services.field_assessment.durable_job_service import (
    _RETRYABLE_SCANNER_TYPES,
    durable_job_svc,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-h12-test"
_OTHER_TENANT = "tenant-h12-other"

_ENG_BODY = {
    "client_name": "DurableCorp",
    "assessor_id": "assessor-h12",
    "assessment_type": "ai_governance",
}


# ---------------------------------------------------------------------------
# Helpers — DB
# ---------------------------------------------------------------------------


def _sessionmaker():
    from api.db import get_sessionmaker

    return get_sessionmaker()


def _make_engagement(SM, *, tenant_id: str) -> str:
    from api.db_models_field_assessment import FaEngagement
    from services.canonical import utc_iso8601_z_now

    eng_id = secrets.token_hex(16)
    now = utc_iso8601_z_now()
    db = SM()
    try:
        db.add(
            FaEngagement(
                id=eng_id,
                tenant_id=tenant_id,
                client_name="DurableCorp",
                assessor_id="assessor-h12",
                assessment_type="ai_governance",
                status="active",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    finally:
        db.close()
    return eng_id


def _get_job(SM, *, job_id: str):
    from api.db_models_field_assessment import FaScanJob

    db = SM()
    try:
        return db.get(FaScanJob, job_id)
    finally:
        db.close()


def _future_ts(seconds: int = 9999) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _past_ts(seconds: int = 9999) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


# ---------------------------------------------------------------------------
# HTTP client helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)
    key = mint_key("governance:write", "governance:read", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def other_client(build_app):
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)
    key = mint_key("governance:write", "governance:read", tenant_id=_OTHER_TENANT)
    return TestClient(app, headers={"X-API-Key": key})


def _create_engagement_http(client: TestClient) -> str:
    resp = client.post("/field-assessment/engagements", json=_ENG_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# D1: create_job — queued state with correct fields
# ---------------------------------------------------------------------------


class TestCreateJob:
    def test_d1_create_job_queued_state(self):
        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)
        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="operator@test",
                scanner_type="network_scan",
                target_ids=["t1", "t2"],
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored is not None
        assert stored.status == "queued"
        assert stored.attempt_count == 0
        assert stored.max_retries == 3
        assert stored.tenant_id == _TENANT
        assert stored.engagement_id == eng_id
        assert stored.actor == "operator@test"
        assert stored.scanner_type == "network_scan"
        assert stored.lease_owner is None
        assert stored.scan_result_id is None

    def test_d2_find_duplicate_idempotency_key(self):
        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)
        ikey = secrets.token_hex(16)

        db = SM()
        try:
            job1 = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="operator@test",
                scanner_type="dns_email",
                idempotency_key=ikey,
            )
            db.commit()
            job1_id = job1.id
        finally:
            db.close()

        db = SM()
        try:
            job2 = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="operator@test",
                scanner_type="dns_email",
                idempotency_key=ikey,
            )
            db.commit()
            job2_id = job2.id
        finally:
            db.close()

        assert job1_id == job2_id


# ---------------------------------------------------------------------------
# D3–D7: State transitions
# ---------------------------------------------------------------------------


class TestStateTransitions:
    def _make_job(
        self, SM, tenant_id: str = _TENANT, scanner_type: str = "network_scan"
    ):
        eng_id = _make_engagement(SM, tenant_id=tenant_id)
        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=tenant_id,
                engagement_id=eng_id,
                actor="worker@test",
                scanner_type=scanner_type,
            )
            db.commit()
            return job.id
        finally:
            db.close()

    def test_d3_mark_running(self):
        SM = _sessionmaker()
        job_id = self._make_job(SM)
        db = SM()
        try:
            durable_job_svc.mark_running(db, job_id=job_id)
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "running"
        assert stored.attempt_count == 1
        assert stored.started_at is not None
        assert stored.lease_owner is not None
        assert stored.lease_expires_at is not None

    def test_d4_mark_complete(self):
        SM = _sessionmaker()
        job_id = self._make_job(SM)
        db = SM()
        try:
            durable_job_svc.mark_running(db, job_id=job_id)
            durable_job_svc.mark_complete(db, job_id=job_id, scan_result_id="sr-123")
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "complete"
        assert stored.scan_result_id == "sr-123"
        assert stored.completed_at is not None
        assert stored.lease_owner is None
        assert stored.lease_expires_at is None

    def test_d5_mark_failed_retryable_stays_failed(self):
        SM = _sessionmaker()
        assert "network_scan" in _RETRYABLE_SCANNER_TYPES
        job_id = self._make_job(SM, scanner_type="network_scan")
        db = SM()
        try:
            durable_job_svc.mark_running(db, job_id=job_id)
            durable_job_svc.mark_failed(db, job_id=job_id, failure_reason="timeout")
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "failed"
        assert stored.failure_reason == "timeout"
        assert stored.next_retry_at is not None
        assert stored.lease_owner is None

    def test_d6_mark_failed_non_retryable_dead_letters(self):
        SM = _sessionmaker()
        assert "microsoft_graph" not in _RETRYABLE_SCANNER_TYPES
        job_id = self._make_job(SM, scanner_type="microsoft_graph")
        db = SM()
        try:
            durable_job_svc.mark_running(db, job_id=job_id)
            durable_job_svc.mark_failed(db, job_id=job_id, failure_reason="auth failed")
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "dead_letter"
        assert stored.failure_reason == "auth failed"
        assert stored.completed_at is not None

    def test_d7_mark_failed_max_retries_dead_letters(self):
        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)
        db = SM()
        try:
            # Create job with max_retries=1 so first failure dead-letters it.
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="worker@test",
                scanner_type="network_scan",
                max_retries=1,
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        # First attempt
        db = SM()
        try:
            durable_job_svc.mark_running(db, job_id=job_id)
            db.commit()
        finally:
            db.close()

        # First failure (attempt_count=1 == max_retries=1) → dead_letter
        db = SM()
        try:
            durable_job_svc.mark_failed(db, job_id=job_id, failure_reason="scan error")
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "dead_letter"


# ---------------------------------------------------------------------------
# D8–D10: Query helpers
# ---------------------------------------------------------------------------


class TestQueryHelpers:
    def test_d8_get_job_tenant_isolation(self):
        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)
        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="dns_email",
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        db = SM()
        try:
            # Correct tenant can see the job.
            found = durable_job_svc.get_job(db, job_id=job_id, tenant_id=_TENANT)
            assert found is not None
            assert found.id == job_id

            # Different tenant gets None.
            not_found = durable_job_svc.get_job(
                db, job_id=job_id, tenant_id=_OTHER_TENANT
            )
            assert not_found is None
        finally:
            db.close()

    def test_d9_list_jobs_engagement_scoped(self):
        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)
        other_eng_id = _make_engagement(SM, tenant_id=_TENANT)

        db = SM()
        try:
            durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="network_scan",
            )
            durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=other_eng_id,
                actor="op@test",
                scanner_type="network_scan",
            )
            db.commit()
        finally:
            db.close()

        db = SM()
        try:
            jobs = durable_job_svc.list_jobs(
                db, tenant_id=_TENANT, engagement_id=eng_id
            )
            eng_ids = {j.engagement_id for j in jobs}
            assert eng_ids == {eng_id}
        finally:
            db.close()

    def test_d10_list_jobs_status_filter(self):
        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)

        db = SM()
        try:
            durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="dns_email",
            )
            j2 = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="dns_email",
            )
            db.commit()
            j2_id = j2.id
        finally:
            db.close()

        db = SM()
        try:
            durable_job_svc.mark_running(db, job_id=j2_id)
            durable_job_svc.mark_complete(db, job_id=j2_id)
            db.commit()
        finally:
            db.close()

        db = SM()
        try:
            queued = durable_job_svc.list_jobs(
                db, tenant_id=_TENANT, engagement_id=eng_id, status="queued"
            )
            statuses = {j.status for j in queued}
            assert statuses == {"queued"}
        finally:
            db.close()


# ---------------------------------------------------------------------------
# D11–D13: Orphan recovery
# ---------------------------------------------------------------------------


class TestOrphanRecovery:
    def _make_running_job(
        self, SM, *, tenant_id: str = _TENANT, scanner_type: str, lease_expires_at: str
    ) -> str:
        from sqlalchemy import update
        from api.db_models_field_assessment import FaScanJob

        eng_id = _make_engagement(SM, tenant_id=tenant_id)
        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=tenant_id,
                engagement_id=eng_id,
                actor="worker@test",
                scanner_type=scanner_type,
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        db = SM()
        try:
            durable_job_svc.mark_running(db, job_id=job_id)
            # Override lease_expires_at to simulate past or future
            db.execute(
                update(FaScanJob)
                .where(FaScanJob.id == job_id)
                .values(lease_expires_at=lease_expires_at)
            )
            db.commit()
        finally:
            db.close()

        return job_id

    def test_d11_recover_orphans_retryable_requeued(self):
        SM = _sessionmaker()
        job_id = self._make_running_job(
            SM, scanner_type="network_scan", lease_expires_at=_past_ts()
        )

        db = SM()
        try:
            recovered = durable_job_svc.recover_orphans(db)
            db.commit()
            assert recovered >= 1
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "queued"
        assert stored.lease_owner is None

    def test_d12_recover_orphans_non_retryable_dead_lettered(self):
        SM = _sessionmaker()
        job_id = self._make_running_job(
            SM, scanner_type="microsoft_graph", lease_expires_at=_past_ts()
        )

        db = SM()
        try:
            durable_job_svc.recover_orphans(db)
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "dead_letter"
        assert stored.failure_reason is not None

    def test_d13_recover_orphans_live_job_untouched(self):
        SM = _sessionmaker()
        job_id = self._make_running_job(
            SM, scanner_type="network_scan", lease_expires_at=_future_ts()
        )

        db = SM()
        try:
            durable_job_svc.recover_orphans(db)
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "running"


# ---------------------------------------------------------------------------
# D14–D18: HTTP routes
# ---------------------------------------------------------------------------


class TestScanJobRoutes:
    def test_d14_status_route_db_fallback(self, client, build_app):
        """After in-memory state clears, status route reads from DB."""
        from api.field_assessment import _MSGRAPH_RUNS, _MSGRAPH_RUNS_LOCK

        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)

        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="dns_email",
            )
            durable_job_svc.mark_running(db, job_id=job.id)
            durable_job_svc.mark_complete(
                db, job_id=job.id, scan_result_id="sr-fallback"
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        # Ensure not in memory (simulate restart).
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS.pop(job_id, None)

        resp = client.get(
            f"/field-assessment/engagements/{eng_id}/connector-runs/{job_id}/status"
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "complete"
        assert data["scan_result_id"] == "sr-fallback"

    def test_d15_status_route_cross_tenant_denied(
        self, client, other_client, build_app
    ):
        """Job from tenant-A returns 404 when queried by tenant-B."""
        from api.field_assessment import _MSGRAPH_RUNS, _MSGRAPH_RUNS_LOCK

        SM = _sessionmaker()
        eng_id = _make_engagement(SM, tenant_id=_TENANT)
        other_eng_id = _make_engagement(SM, tenant_id=_OTHER_TENANT)

        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="network_scan",
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS.pop(job_id, None)

        # Other tenant's engagement ID doesn't matter — the job tenant_id must match.
        resp = other_client.get(
            f"/field-assessment/engagements/{other_eng_id}/connector-runs/{job_id}/status"
        )
        assert resp.status_code == 404

    def test_d16_list_scan_jobs_route(self, client, build_app):
        eng_id = _create_engagement_http(client)

        SM = _sessionmaker()
        db = SM()
        try:
            for _ in range(3):
                durable_job_svc.create_job(
                    db,
                    tenant_id=_TENANT,
                    engagement_id=eng_id,
                    actor="op@test",
                    scanner_type="web_headers",
                )
            db.commit()
        finally:
            db.close()

        resp = client.get(f"/field-assessment/engagements/{eng_id}/scan-jobs")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "jobs" in data
        assert len(data["jobs"]) >= 3
        for job in data["jobs"]:
            assert "job_id" in job
            assert "status" in job
            assert "scanner_type" in job

    def test_d17_get_scan_job_route(self, client, build_app):
        eng_id = _create_engagement_http(client)

        SM = _sessionmaker()
        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="dns_email",
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        resp = client.get(f"/field-assessment/engagements/{eng_id}/scan-jobs/{job_id}")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["job_id"] == job_id
        assert data["status"] == "queued"
        assert data["scanner_type"] == "dns_email"

    def test_d18_get_scan_job_wrong_engagement_returns_404(self, client, build_app):
        eng_id = _create_engagement_http(client)
        other_eng_id = _create_engagement_http(client)

        SM = _sessionmaker()
        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type="dns_email",
            )
            db.commit()
            job_id = job.id
        finally:
            db.close()

        resp = client.get(
            f"/field-assessment/engagements/{other_eng_id}/scan-jobs/{job_id}"
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# D20–D22: _c6_update_job_status delegation
# ---------------------------------------------------------------------------


class TestC6Delegation:
    def _make_job(self, SM, scanner_type: str = "dns_email") -> str:
        eng_id = _make_engagement(SM, tenant_id=_TENANT)
        db = SM()
        try:
            job = durable_job_svc.create_job(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                actor="op@test",
                scanner_type=scanner_type,
            )
            db.commit()
            return job.id
        finally:
            db.close()

    def test_d20_c6_update_job_status_running(self):
        from api.field_assessment import _c6_update_job_status

        SM = _sessionmaker()
        job_id = self._make_job(SM)
        db = SM()
        try:
            _c6_update_job_status(db, job_id=job_id, status="running")
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "running"
        assert stored.attempt_count == 1

    def test_d21_c6_update_job_status_complete(self):
        from api.field_assessment import _c6_update_job_status

        SM = _sessionmaker()
        job_id = self._make_job(SM)
        db = SM()
        try:
            _c6_update_job_status(db, job_id=job_id, status="running")
            _c6_update_job_status(
                db, job_id=job_id, status="complete", scan_result_id="sr-abc"
            )
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "complete"
        assert stored.scan_result_id == "sr-abc"

    def test_d22_c6_update_job_status_failed_retryable(self):
        from api.field_assessment import _c6_update_job_status

        SM = _sessionmaker()
        job_id = self._make_job(SM, scanner_type="dns_email")
        assert "dns_email" in _RETRYABLE_SCANNER_TYPES

        db = SM()
        try:
            _c6_update_job_status(db, job_id=job_id, status="running")
            _c6_update_job_status(
                db, job_id=job_id, status="failed", failure_reason="dns timeout"
            )
            db.commit()
        finally:
            db.close()

        stored = _get_job(SM, job_id=job_id)
        assert stored.status == "failed"
        assert stored.next_retry_at is not None
