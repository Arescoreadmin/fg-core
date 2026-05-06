"""
tests/test_report_hardening.py — Report generation load-hardening tests.

Covers:
- Bounded concurrency semaphore caps running jobs to FG_REPORT_MAX_CONCURRENT_JOBS
- Jobs waiting for capacity stay in QUEUED state until a slot is free
- Terminal state (succeeded/failed) is not overwritten by concurrent paths
- Timeout still fails with stable REPORT_GENERATION_TIMEOUT reason
- Exception path still fails with stable REPORT_GENERATION_FAILED reason
- Both failure paths emit audit events
- Success path emits audit event
- Queue depth helper reflects queued/running/max_concurrent
- Load harness still records metrics correctly after hardening
- Tenant isolation preserved under concurrent jobs
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers (duplicated minimally from test_report_jobs.py to keep tests self-contained)
# ---------------------------------------------------------------------------


def _make_report_record(
    report_id: str,
    tenant_id: str = "tenant-A",
    assessment_id: str = "assessment-1",
    status: str = "pending",
) -> MagicMock:
    r = MagicMock()
    r.id = report_id
    r.tenant_id = tenant_id
    r.assessment_id = assessment_id
    r.status = status
    r.prompt_type = "executive"
    r.error_message = None
    r.completed_at = None
    return r


def _make_assessment_record(
    assessment_id: str, tenant_id: str = "tenant-A"
) -> MagicMock:
    a = MagicMock()
    a.id = assessment_id
    a.tenant_id = tenant_id
    a.org_profile_id = 42
    a.overall_score = 72.5
    a.risk_band = "medium"
    a.profile_type = "smb_growth"
    a.scores = {}
    return a


def _make_prompt_record() -> MagicMock:
    p = MagicMock()
    p.user_prompt_template = "Generate a report for {{org_name}}"
    p.system_prompt = "You are a report generator."
    return p


def _make_org_record() -> MagicMock:
    org = MagicMock()
    org.org_name = "Acme Corp"
    org.industry = "tech"
    return org


def _mock_get_sessionmaker(fake_db: MagicMock):
    return lambda: fake_db


class _MockAuditor:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def log_event(self, event: Any) -> None:
        self.events.append(event)

    @property
    def reasons(self) -> list[str]:
        return [e.reason for e in self.events]

    @property
    def all_details(self) -> list[dict]:
        return [e.details.copy() for e in self.events]

    def details_for(self, reason: str) -> list[dict]:
        return [e.details.copy() for e in self.events if e.reason == reason]


# ---------------------------------------------------------------------------
# Semaphore / concurrency helpers
# ---------------------------------------------------------------------------


class TestSemaphoreHelpers:
    def setup_method(self):
        import api.reports_engine as engine_mod

        engine_mod._reset_semaphore()

    def test_get_max_concurrent_jobs_default(self) -> None:
        from api.reports_engine import _get_max_concurrent_jobs

        # Ensure env var is unset for this test
        env = {
            k: v for k, v in os.environ.items() if k != "FG_REPORT_MAX_CONCURRENT_JOBS"
        }
        with patch.dict(os.environ, env, clear=True):
            import api.reports_engine as engine_mod

            engine_mod._reset_semaphore()
            assert _get_max_concurrent_jobs() == 4

    def test_get_max_concurrent_jobs_from_env(self) -> None:
        from api.reports_engine import _get_max_concurrent_jobs

        with patch.dict(os.environ, {"FG_REPORT_MAX_CONCURRENT_JOBS": "7"}):
            import api.reports_engine as engine_mod

            engine_mod._reset_semaphore()
            assert _get_max_concurrent_jobs() == 7

    def test_get_max_concurrent_jobs_clamps_to_minimum_1(self) -> None:
        from api.reports_engine import _get_max_concurrent_jobs

        with patch.dict(os.environ, {"FG_REPORT_MAX_CONCURRENT_JOBS": "0"}):
            import api.reports_engine as engine_mod

            engine_mod._reset_semaphore()
            assert _get_max_concurrent_jobs() == 1

    def test_get_max_concurrent_jobs_invalid_value_falls_back(self) -> None:
        from api.reports_engine import _get_max_concurrent_jobs

        with patch.dict(os.environ, {"FG_REPORT_MAX_CONCURRENT_JOBS": "bad"}):
            import api.reports_engine as engine_mod

            engine_mod._reset_semaphore()
            assert _get_max_concurrent_jobs() == 4

    def test_get_semaphore_returns_semaphore(self) -> None:
        from api.reports_engine import _get_semaphore

        sem = _get_semaphore()
        assert isinstance(sem, asyncio.Semaphore)

    def test_get_semaphore_is_idempotent(self) -> None:
        from api.reports_engine import _get_semaphore

        sem1 = _get_semaphore()
        sem2 = _get_semaphore()
        assert sem1 is sem2

    def test_reset_semaphore_forces_fresh_creation(self) -> None:
        import api.reports_engine as engine_mod

        sem1 = engine_mod._get_semaphore()
        engine_mod._reset_semaphore()
        sem2 = engine_mod._get_semaphore()
        assert sem1 is not sem2


# ---------------------------------------------------------------------------
# Bounded concurrency — asyncio-level tests
# ---------------------------------------------------------------------------


class TestReportConcurrencyLimiter:
    def setup_method(self):
        import api.reports_engine as engine_mod

        engine_mod._reset_semaphore()

    def test_report_concurrency_limiter_caps_running_jobs(self) -> None:
        """At most FG_REPORT_MAX_CONCURRENT_JOBS generators run simultaneously."""
        max_concurrent = 2
        concurrency_seen: list[int] = []
        running_now = 0

        async def _fake_generator() -> None:
            nonlocal running_now
            running_now += 1
            concurrency_seen.append(running_now)
            await asyncio.sleep(0)  # yield to let other tasks start
            running_now -= 1

        async def _run() -> None:
            import api.reports_engine as engine_mod

            with patch.dict(
                os.environ, {"FG_REPORT_MAX_CONCURRENT_JOBS": str(max_concurrent)}
            ):
                engine_mod._reset_semaphore()
                sem = engine_mod._get_semaphore()

                async def _bounded():
                    async with sem:
                        await _fake_generator()

                tasks = [asyncio.create_task(_bounded()) for _ in range(6)]
                await asyncio.gather(*tasks)

        asyncio.run(_run())
        assert max(concurrency_seen) <= max_concurrent, (
            f"Max observed concurrency {max(concurrency_seen)} exceeded limit {max_concurrent}"
        )

    def test_report_jobs_wait_queued_until_capacity_available(self) -> None:
        """Jobs that cannot immediately acquire the semaphore wait (do not error)."""
        completion_order: list[int] = []

        async def _run() -> None:
            import api.reports_engine as engine_mod

            with patch.dict(os.environ, {"FG_REPORT_MAX_CONCURRENT_JOBS": "1"}):
                engine_mod._reset_semaphore()
                sem = engine_mod._get_semaphore()

                async def _job(idx: int) -> None:
                    async with sem:
                        await asyncio.sleep(0.001)
                        completion_order.append(idx)

                await asyncio.gather(*[asyncio.create_task(_job(i)) for i in range(4)])

        asyncio.run(_run())
        # All 4 jobs completed (none was dropped)
        assert sorted(completion_order) == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# Terminal-state protection
# ---------------------------------------------------------------------------


class TestTerminalStateProtection:
    def test_handle_timeout_does_not_overwrite_complete_status(self) -> None:
        """_handle_timeout skips overwrite when report already has 'complete' status."""
        import api.reports_engine as engine_mod

        report = _make_report_record("r-t-001", status="complete")
        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = report

        auditor = _MockAuditor()

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
        ):
            engine_mod._handle_timeout("r-t-001")

        # Status must remain 'complete'
        assert report.status == "complete"
        # No audit event should have been emitted for this overwrite attempt
        assert "report_job_failed" not in auditor.reasons

    def test_handle_timeout_does_not_overwrite_failed_status(self) -> None:
        """_handle_timeout skips overwrite when report already has 'failed' status."""
        import api.reports_engine as engine_mod

        report = _make_report_record("r-t-002", status="failed")
        report.error_message = "REPORT_GENERATION_FAILED"
        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = report

        auditor = _MockAuditor()

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
        ):
            engine_mod._handle_timeout("r-t-002")

        assert report.status == "failed"
        assert report.error_message == "REPORT_GENERATION_FAILED"
        assert "report_job_failed" not in auditor.reasons

    def test_report_terminal_state_not_overwritten(self) -> None:
        """_do_generate_report returns early if report is already in terminal state."""
        import api.reports_engine as engine_mod

        report = _make_report_record("r-t-003", status="complete")
        auditor = _MockAuditor()
        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = report

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
        ):
            engine_mod._do_generate_report("r-t-003")

        # Status must remain 'complete', not be overwritten to 'generating'
        assert report.status == "complete"
        # No started/failed events
        assert "report_job_started" not in auditor.reasons

    def test_exception_handler_does_not_overwrite_already_failed(self) -> None:
        """The exception path in _do_generate_report skips overwrite if already failed."""
        import api.reports_engine as engine_mod

        # Simulate report that is initially 'pending', then exception fires,
        # but by the time the handler re-fetches it's already 'failed'.
        report_initial = _make_report_record("r-t-004", status="pending")
        report_already_failed = _make_report_record("r-t-004", status="failed")
        report_already_failed.error_message = "prior-failure"
        assessment = _make_assessment_record("assessment-1")
        org = _make_org_record()
        prompt = _make_prompt_record()

        auditor = _MockAuditor()
        fake_db = MagicMock()
        # First call returns pending report; subsequent calls simulate re-fetch
        fake_db.query.return_value.filter.return_value.first.side_effect = [
            report_initial,
            assessment,
            org,
            prompt,
            report_already_failed,  # re-fetch in exception handler
        ]

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
            patch(
                "services.ai.dispatch.call_provider",
                side_effect=RuntimeError("provider gone"),
            ),
        ):
            engine_mod._do_generate_report("r-t-004")

        # The already-failed report must not have its error_message overwritten
        assert report_already_failed.error_message == "prior-failure"


# ---------------------------------------------------------------------------
# Audit events emitted under hardening
# ---------------------------------------------------------------------------


class TestAuditEventsUnderHardening:
    def test_report_job_failure_still_emits_audit_event(self) -> None:
        """Exception path still emits report_job_failed audit event after hardening."""
        import api.reports_engine as engine_mod
        from services.ai.providers.base import ProviderCallError

        report = _make_report_record("r-a-001")
        assessment = _make_assessment_record("assessment-1")
        org = _make_org_record()
        prompt = _make_prompt_record()
        auditor = _MockAuditor()

        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.side_effect = [
            report,
            assessment,
            org,
            prompt,
            report,
        ]

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
            patch(
                "services.ai.dispatch.call_provider",
                side_effect=ProviderCallError("PROVIDER_ERROR", "down"),
            ),
        ):
            engine_mod._do_generate_report("r-a-001")

        assert "report_job_failed" in auditor.reasons

    def test_report_job_success_still_emits_audit_event(self) -> None:
        """Success path still emits report_job_succeeded audit event after hardening."""
        import api.reports_engine as engine_mod

        report = _make_report_record("r-a-002")
        assessment = _make_assessment_record("assessment-1")
        org = _make_org_record()
        prompt = _make_prompt_record()
        auditor = _MockAuditor()

        mock_resp = MagicMock()
        mock_resp.text = '{"executive_summary": "hardened"}'

        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.side_effect = [
            report,
            assessment,
            org,
            prompt,
        ]

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
            patch("services.ai.dispatch.call_provider", return_value=mock_resp),
        ):
            engine_mod._do_generate_report("r-a-002")

        assert "report_job_succeeded" in auditor.reasons

    def test_report_job_timeout_still_fails_with_stable_reason(self) -> None:
        """Timeout path still produces REPORT_GENERATION_TIMEOUT reason code."""
        import api.reports_engine as engine_mod
        from api.report_jobs import REPORT_GENERATION_TIMEOUT

        report = _make_report_record("r-a-003")
        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = report
        auditor = _MockAuditor()

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
        ):
            engine_mod._handle_timeout("r-a-003")

        assert report.status == "failed"
        assert report.error_message == REPORT_GENERATION_TIMEOUT
        failed = auditor.details_for("report_job_failed")
        assert len(failed) == 1
        assert failed[0]["reason_code"] == REPORT_GENERATION_TIMEOUT

    def test_report_job_exception_still_fails_with_stable_reason(self) -> None:
        """Exception path still produces REPORT_GENERATION_FAILED reason code."""
        import api.reports_engine as engine_mod
        from api.report_jobs import REPORT_GENERATION_FAILED
        from services.ai.providers.base import ProviderCallError

        report = _make_report_record("r-a-004")
        assessment = _make_assessment_record("assessment-1")
        org = _make_org_record()
        prompt = _make_prompt_record()
        auditor = _MockAuditor()

        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.side_effect = [
            report,
            assessment,
            org,
            prompt,
            report,
        ]

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
            patch(
                "services.ai.dispatch.call_provider",
                side_effect=ProviderCallError("PROVIDER_ERROR", "down"),
            ),
        ):
            engine_mod._do_generate_report("r-a-004")

        failed = auditor.details_for("report_job_failed")
        assert len(failed) >= 1
        assert failed[0]["reason_code"] == REPORT_GENERATION_FAILED


# ---------------------------------------------------------------------------
# Queue depth visibility
# ---------------------------------------------------------------------------


class TestReportQueueDepth:
    def setup_method(self):
        import api.reports_engine as engine_mod

        engine_mod._reset_semaphore()

    def test_report_queue_depth_reflects_max_concurrent(self) -> None:
        from api.reports_engine import get_report_queue_status

        with patch.dict(os.environ, {"FG_REPORT_MAX_CONCURRENT_JOBS": "3"}):
            import api.reports_engine as engine_mod

            engine_mod._reset_semaphore()
            status = get_report_queue_status()
            assert status["max_concurrent"] == 3

    def test_report_queue_depth_reflects_queued_and_running_jobs(self) -> None:
        """Available slots decrease as jobs acquire the semaphore."""

        async def _run() -> None:
            import api.reports_engine as engine_mod

            with patch.dict(os.environ, {"FG_REPORT_MAX_CONCURRENT_JOBS": "2"}):
                engine_mod._reset_semaphore()
                sem = engine_mod._get_semaphore()

                # Acquire one slot manually
                await sem.acquire()
                status = engine_mod.get_report_queue_status()
                assert status["running"] == 1
                assert status["available"] == 1

                # Acquire second slot
                await sem.acquire()
                status = engine_mod.get_report_queue_status()
                assert status["running"] == 2
                assert status["available"] == 0

                sem.release()
                sem.release()

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# Load harness still works after hardening
# ---------------------------------------------------------------------------


class TestReportLoadHarnessAfterHardening:
    def test_report_load_harness_still_records_metrics_after_hardening(self) -> None:
        """The load harness still produces valid metrics after hardening changes."""
        from tools.load.report_generation_load import run_load_test, LoadMetrics

        async def _instant(job_id: str, tenant_id: str) -> None:
            pass

        metrics = asyncio.run(
            run_load_test(
                total_jobs=10,
                concurrency=3,
                generator=_instant,
            )
        )
        assert isinstance(metrics, LoadMetrics)
        assert metrics.total_jobs == 10
        assert metrics.succeeded_count == 10
        assert metrics.failed_count == 0
        assert metrics.timeout_count == 0
        assert len(metrics.completion_latencies_ms) == 10

    def test_report_load_harness_failure_metrics_accurate_after_hardening(self) -> None:
        """Failure counts remain accurate after hardening."""
        from tools.load.report_generation_load import run_load_test
        from api.report_jobs import REPORT_GENERATION_FAILED

        async def _failing(job_id: str, tenant_id: str) -> None:
            raise RuntimeError(REPORT_GENERATION_FAILED)

        metrics = asyncio.run(
            run_load_test(
                total_jobs=5,
                concurrency=2,
                generator=_failing,
            )
        )
        assert metrics.failed_count == 5
        assert metrics.succeeded_count == 0


# ---------------------------------------------------------------------------
# Tenant isolation preserved under concurrent jobs
# ---------------------------------------------------------------------------


class TestReportTenantIsolationUnderConcurrency:
    def test_report_tenant_isolation_preserved_under_concurrent_jobs(self) -> None:
        """Each job's tenant_id is preserved independently under concurrent load."""
        tenant_map: dict[str, str] = {}

        async def _capture_tenant(job_id: str, tenant_id: str) -> None:
            tenant_map[job_id] = tenant_id

        async def _run() -> None:
            from tools.load.report_generation_load import run_load_test

            await run_load_test(
                total_jobs=8,
                concurrency=4,
                tenant_id="isolated-tenant-X",
                generator=_capture_tenant,
            )

        asyncio.run(_run())
        assert len(tenant_map) == 8
        assert all(v == "isolated-tenant-X" for v in tenant_map.values()), (
            f"Tenant IDs leaked: {set(tenant_map.values())}"
        )

    def test_report_job_status_enforces_tenant_isolation_after_hardening(self) -> None:
        """Tenant isolation on GET /reports/{id} is preserved post-hardening."""
        from fastapi import HTTPException
        import api.reports_engine as engine_mod

        report = _make_report_record("r-iso-h1", tenant_id="tenant-A")
        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = report

        fake_request = MagicMock()
        fake_request.state.tenant_id = "tenant-B"

        with pytest.raises(HTTPException) as exc_info:
            engine_mod.get_report(
                report_id="r-iso-h1",
                request=fake_request,
                db=fake_db,
            )
        assert exc_info.value.status_code == 404
