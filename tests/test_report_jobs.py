"""
tests/test_report_jobs.py — Report generation hardening tests.

Covers:
- ReportJobState enum and stable reason codes
- Job lifecycle state transitions (queued -> running -> succeeded/failed)
- Timeout causes REPORT_GENERATION_TIMEOUT reason code
- Audit events emitted for each lifecycle phase
- Tenant isolation enforced on job read path
- Sensitive payloads never appear in audit metadata
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report_record(
    report_id: str,
    tenant_id: str = "tenant-A",
    assessment_id: str = "assessment-1",
    status: str = "pending",
) -> MagicMock:
    """Return a minimal mock ReportRecord."""
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
    a.overall_score = 72.5  # float so f"{x:.1f}" works
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
    """Return a factory that, when called, returns fake_db."""
    return lambda: fake_db


class _MockAuditor:
    """Capture emitted AuditEvents for inspection."""

    def __init__(self) -> None:
        self.events: list[MagicMock] = []

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
# ReportJobState / reason code constants
# ---------------------------------------------------------------------------


class TestReportJobStateEnum:
    def test_state_values_are_strings(self) -> None:
        from api.report_jobs import ReportJobState

        assert ReportJobState.QUEUED == "queued"
        assert ReportJobState.RUNNING == "running"
        assert ReportJobState.SUCCEEDED == "succeeded"
        assert ReportJobState.FAILED == "failed"

    def test_state_is_str_subclass(self) -> None:
        from api.report_jobs import ReportJobState

        for state in ReportJobState:
            assert isinstance(state, str)

    def test_reason_codes_are_stable_strings(self) -> None:
        from api.report_jobs import REPORT_GENERATION_FAILED, REPORT_GENERATION_TIMEOUT

        assert REPORT_GENERATION_TIMEOUT == "REPORT_GENERATION_TIMEOUT"
        assert REPORT_GENERATION_FAILED == "REPORT_GENERATION_FAILED"

    def test_reason_codes_are_distinct(self) -> None:
        from api.report_jobs import REPORT_GENERATION_FAILED, REPORT_GENERATION_TIMEOUT

        assert REPORT_GENERATION_TIMEOUT != REPORT_GENERATION_FAILED


# ---------------------------------------------------------------------------
# _emit_report_event — audit metadata safety
# ---------------------------------------------------------------------------


class TestEmitReportEvent:
    def test_report_audit_metadata_does_not_include_sensitive_payload(self) -> None:
        from api.report_jobs import ReportJobState
        import api.reports_engine as engine_mod

        auditor = _MockAuditor()

        with patch.object(engine_mod, "get_auditor", return_value=auditor):
            engine_mod._emit_report_event(
                "report_job_queued",
                "tenant-test",
                "report-abc",
                "assessment-xyz",
                state=ReportJobState.QUEUED,
            )

        assert len(auditor.events) == 1
        d = auditor.all_details[0]
        for forbidden_key in (
            "content",
            "prompt",
            "user_prompt",
            "system_prompt",
            "raw_text",
            "model_output",
            "phi",
            "answers",
        ):
            assert forbidden_key not in d, (
                f"Sensitive key '{forbidden_key}' found in audit metadata"
            )

    def test_emit_includes_report_id_and_state(self) -> None:
        from api.report_jobs import ReportJobState
        import api.reports_engine as engine_mod

        auditor = _MockAuditor()

        with patch.object(engine_mod, "get_auditor", return_value=auditor):
            engine_mod._emit_report_event(
                "report_job_queued",
                "tenant-test",
                "report-abc",
                "assessment-xyz",
                state=ReportJobState.QUEUED,
            )

        d = auditor.all_details[0]
        assert d["report_id"] == "report-abc"
        assert d["assessment_id"] == "assessment-xyz"
        assert d["job_state"] == "queued"

    def test_emit_failed_includes_reason_code(self) -> None:
        from api.report_jobs import REPORT_GENERATION_FAILED, ReportJobState
        import api.reports_engine as engine_mod

        auditor = _MockAuditor()

        with patch.object(engine_mod, "get_auditor", return_value=auditor):
            engine_mod._emit_report_event(
                "report_job_failed",
                "tenant-test",
                "report-abc",
                "assessment-xyz",
                state=ReportJobState.FAILED,
                reason_code=REPORT_GENERATION_FAILED,
            )

        assert auditor.all_details[0]["reason_code"] == REPORT_GENERATION_FAILED

    def test_emit_succeeded_includes_duration_ms(self) -> None:
        from api.report_jobs import ReportJobState
        import api.reports_engine as engine_mod

        auditor = _MockAuditor()

        with patch.object(engine_mod, "get_auditor", return_value=auditor):
            engine_mod._emit_report_event(
                "report_job_succeeded",
                "tenant-test",
                "report-abc",
                "assessment-xyz",
                state=ReportJobState.SUCCEEDED,
                duration_ms=1234,
            )

        assert auditor.all_details[0]["duration_ms"] == 1234

    def test_emit_does_not_raise_on_auditor_failure(self) -> None:
        """Audit failure must never abort the calling thread."""
        from api.report_jobs import ReportJobState
        import api.reports_engine as engine_mod

        class _FailingAuditor:
            def log_event(self, event: Any) -> None:
                raise RuntimeError("db down")

        with patch.object(engine_mod, "get_auditor", return_value=_FailingAuditor()):
            # Must not raise
            engine_mod._emit_report_event(
                "report_job_queued",
                "tenant-test",
                "report-abc",
                None,
                state=ReportJobState.QUEUED,
            )


# ---------------------------------------------------------------------------
# _do_generate_report — success path
# ---------------------------------------------------------------------------


class TestDoGenerateReportSuccess:
    """_do_generate_report: queued -> running -> succeeded path."""

    def _run_success(self, report_id: str, tenant_id: str = "tenant-A"):
        import api.reports_engine as engine_mod

        report = _make_report_record(report_id, tenant_id=tenant_id)
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
        ]

        mock_resp = MagicMock()
        mock_resp.text = '{"executive_summary": "ok"}'

        with (
            patch.object(
                engine_mod,
                "get_sessionmaker",
                return_value=_mock_get_sessionmaker(fake_db),
            ),
            patch.object(engine_mod, "get_auditor", return_value=auditor),
            patch(
                "services.ai.dispatch.call_provider",
                return_value=mock_resp,
            ),
        ):
            engine_mod._do_generate_report(report_id)

        return auditor, report

    def test_report_job_starts_and_succeeds(self) -> None:
        from api.report_jobs import ReportJobState

        auditor, _ = self._run_success("r-001")
        assert ReportJobState.RUNNING.value in [
            d["job_state"] for d in auditor.all_details
        ]
        assert ReportJobState.SUCCEEDED.value in [
            d["job_state"] for d in auditor.all_details
        ]

    def test_report_job_emits_started_event(self) -> None:
        auditor, _ = self._run_success("r-002")
        assert "report_job_started" in auditor.reasons

    def test_report_job_emits_succeeded_event(self) -> None:
        auditor, _ = self._run_success("r-003")
        assert "report_job_succeeded" in auditor.reasons

    def test_report_job_preserves_tenant_id(self) -> None:
        auditor, _ = self._run_success("r-004", tenant_id="tenant-XYZ")
        # Every emitted event carries the correct tenant_id
        for event in auditor.events:
            assert event.tenant_id == "tenant-XYZ"


# ---------------------------------------------------------------------------
# _do_generate_report — failure path
# ---------------------------------------------------------------------------


class TestDoGenerateReportFailure:
    """_do_generate_report: queued -> running -> failed path."""

    def _run_failure(self, report_id: str):
        import api.reports_engine as engine_mod
        from services.ai.providers.base import ProviderCallError

        report = _make_report_record(report_id)
        assessment = _make_assessment_record("assessment-1")
        org = _make_org_record()
        prompt = _make_prompt_record()

        auditor = _MockAuditor()

        fake_db = MagicMock()
        # Extra return value for the error handler re-fetch of the report
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
                side_effect=ProviderCallError("PROVIDER_ERROR", "provider down"),
            ),
        ):
            engine_mod._do_generate_report(report_id)

        return auditor, report

    def test_report_job_fails_on_exception(self) -> None:
        from api.report_jobs import ReportJobState

        auditor, report = self._run_failure("r-010")
        assert "report_job_failed" in auditor.reasons
        failed_details = auditor.details_for("report_job_failed")
        assert len(failed_details) >= 1
        assert failed_details[0]["job_state"] == ReportJobState.FAILED.value

    def test_report_job_emits_failed_event(self) -> None:
        auditor, _ = self._run_failure("r-011")
        assert "report_job_failed" in auditor.reasons

    def test_report_job_failure_reason_is_stable(self) -> None:
        """Reason code for non-timeout failure is REPORT_GENERATION_FAILED constant."""
        from api.report_jobs import REPORT_GENERATION_FAILED

        auditor, _ = self._run_failure("r-012")
        failed_details = auditor.details_for("report_job_failed")
        assert len(failed_details) >= 1
        assert failed_details[0]["reason_code"] == REPORT_GENERATION_FAILED


# ---------------------------------------------------------------------------
# _handle_timeout — timeout reason code and audit
# ---------------------------------------------------------------------------


class TestHandleTimeout:
    def test_report_job_fails_on_timeout(self) -> None:
        """_handle_timeout marks report failed with REPORT_GENERATION_TIMEOUT."""
        import api.reports_engine as engine_mod
        from api.report_jobs import REPORT_GENERATION_TIMEOUT

        report = _make_report_record("r-020")
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
            engine_mod._handle_timeout("r-020")

        assert report.status == "failed"
        assert report.error_message == REPORT_GENERATION_TIMEOUT

    def test_timeout_emits_failed_event_with_timeout_reason(self) -> None:
        import api.reports_engine as engine_mod
        from api.report_jobs import REPORT_GENERATION_TIMEOUT

        report = _make_report_record("r-021")
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
            engine_mod._handle_timeout("r-021")

        assert any(
            d.get("reason_code") == REPORT_GENERATION_TIMEOUT
            for d in auditor.all_details
        )

    def test_generate_report_async_triggers_timeout_handler(self) -> None:
        """_generate_report_async calls _handle_timeout when wait_for raises TimeoutError."""
        import api.reports_engine as engine_mod

        async def _test() -> None:
            with (
                patch.object(engine_mod, "_handle_timeout") as mock_timeout,
                patch(
                    "asyncio.wait_for",
                    side_effect=asyncio.TimeoutError,
                ),
            ):
                await engine_mod._generate_report_async("r-030")
                mock_timeout.assert_called_once_with("r-030")

        asyncio.run(_test())


# ---------------------------------------------------------------------------
# Tenant isolation on GET /reports/{id}
# ---------------------------------------------------------------------------


class TestReportJobTenantIsolation:
    """get_report must return 404 for wrong-tenant requests."""

    def test_report_job_status_enforces_tenant_isolation(self) -> None:
        """A caller from tenant-B cannot read a report owned by tenant-A."""
        import pytest
        from fastapi import HTTPException
        import api.reports_engine as engine_mod

        report = _make_report_record("r-iso-1", tenant_id="tenant-A")
        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = report

        fake_request = MagicMock()
        fake_request.state.tenant_id = "tenant-B"

        with pytest.raises(HTTPException) as exc_info:
            engine_mod.get_report(
                report_id="r-iso-1",
                request=fake_request,
                db=fake_db,
            )
        assert exc_info.value.status_code == 404

    def test_correct_tenant_can_read_own_report(self) -> None:
        """A caller with matching tenant_id can read the report."""
        import api.reports_engine as engine_mod

        report = _make_report_record("r-iso-2", tenant_id="tenant-A")
        assessment = _make_assessment_record("assessment-1")

        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.side_effect = [
            report,
            assessment,
        ]

        fake_request = MagicMock()
        fake_request.state.tenant_id = "tenant-A"

        result = engine_mod.get_report(
            report_id="r-iso-2",
            request=fake_request,
            db=fake_db,
        )
        assert result["id"] == "r-iso-2"

    def test_no_tenant_in_request_state_does_not_block(self) -> None:
        """If caller has no tenant_id in state, isolation check is skipped."""
        import api.reports_engine as engine_mod

        report = _make_report_record("r-iso-3", tenant_id="tenant-A")
        assessment = _make_assessment_record("assessment-1")

        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.side_effect = [
            report,
            assessment,
        ]

        # state has no tenant_id attribute at all
        fake_request = MagicMock(spec=[])
        fake_request.state = MagicMock(spec=[])

        result = engine_mod.get_report(
            report_id="r-iso-3",
            request=fake_request,
            db=fake_db,
        )
        assert result["id"] == "r-iso-3"


# ---------------------------------------------------------------------------
# generate_report endpoint — enqueues job and emits queued event
# ---------------------------------------------------------------------------


class TestGenerateReportEndpoint:
    def _run_generate(self, report_id: str = "r-new", tenant_id: str = "tenant-A"):
        import api.reports_engine as engine_mod

        assessment = _make_assessment_record("assessment-1", tenant_id=tenant_id)
        assessment.status = "scored"
        report_record = _make_report_record(report_id, tenant_id=tenant_id)

        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = assessment

        auditor = _MockAuditor()
        fake_bg = MagicMock()
        fake_request = MagicMock()
        fake_request.state.tenant_id = tenant_id

        with (
            patch.object(engine_mod, "get_auditor", return_value=auditor),
            patch.object(engine_mod, "ReportRecord", return_value=report_record),
        ):
            from api.reports_engine import GenerateReportRequest

            body = GenerateReportRequest(
                assessment_id="assessment-1", prompt_type="executive"
            )
            result = engine_mod.generate_report(
                body=body,
                background_tasks=fake_bg,
                request=fake_request,
                db=fake_db,
            )

        return result, auditor, fake_bg

    def test_report_generation_request_enqueues_job(self) -> None:
        result, auditor, fake_bg = self._run_generate()
        assert result.status == "pending"
        assert result.report_id is not None
        fake_bg.add_task.assert_called_once()

    def test_report_job_emits_queued_event(self) -> None:
        _, auditor, _ = self._run_generate()
        assert "report_job_queued" in auditor.reasons

    def test_queued_event_has_correct_job_state(self) -> None:
        from api.report_jobs import ReportJobState

        _, auditor, _ = self._run_generate()
        queued = auditor.details_for("report_job_queued")
        assert len(queued) == 1
        assert queued[0]["job_state"] == ReportJobState.QUEUED.value

    def test_report_job_queued_metadata_no_sensitive_fields(self) -> None:
        """Queued event metadata must not include sensitive payload."""
        _, auditor, _ = self._run_generate()
        for d in auditor.details_for("report_job_queued"):
            for forbidden in (
                "content",
                "prompt",
                "user_prompt",
                "system_prompt",
                "phi",
            ):
                assert forbidden not in d, (
                    f"Sensitive key '{forbidden}' in queued event"
                )
