"""L14-SCAN-SAFETY-001 — scan cancellation state machine adversarial tests.

Tests the cancellation service layer against mock DB sessions.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

from services.field_assessment.scan_authorization import (
    ScanAuthorizationError,
    cancel_scan,
    confirm_scan_cancelled,
)


_TENANT = "tenant-cancel-test"
_ENG = "cccccccc-cccc-cccc-cccc-cccccccccccc"
_JOB_ID = "job-cancel-001"


def _make_cancel_db(
    *,
    update_returns=None,
    existing_status: str | None = None,
) -> MagicMock:
    """Build mock DB for cancel_scan tests.

    update_returns: tuple from the UPDATE RETURNING, or None if no row updated.
    existing_status: status from the SELECT fallback query, or None if not found.
    """
    db = MagicMock()

    update_result = MagicMock()
    update_result.fetchone.return_value = update_returns

    select_result = MagicMock()
    if existing_status is not None:
        select_result.fetchone.return_value = (_JOB_ID, existing_status)
    else:
        select_result.fetchone.return_value = None

    db.execute.side_effect = [update_result, select_result]
    return db


def _make_confirm_db(
    *,
    update_returns=None,
    existing_status: str | None = None,
) -> MagicMock:
    db = MagicMock()

    update_result = MagicMock()
    update_result.fetchone.return_value = update_returns

    select_result = MagicMock()
    if existing_status is not None:
        select_result.fetchone.return_value = (existing_status,)
    else:
        select_result.fetchone.return_value = None

    db.execute.side_effect = [update_result, select_result]
    return db


class TestCancelScan:
    def test_cancel_queued_job_transitions_to_cancel_requested(self):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        db = _make_cancel_db(update_returns=(_JOB_ID, "cancel_requested", now))
        result = cancel_scan(
            db,
            scan_job_id=_JOB_ID,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            reason="operator requested",
            actor="operator-1",
        )
        assert result["status"] == "cancel_requested"
        assert result["scan_job_id"] == _JOB_ID
        db.commit.assert_called_once()

    def test_cancel_running_job_transitions_to_cancel_requested(self):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        db = _make_cancel_db(update_returns=(_JOB_ID, "cancel_requested", now))
        result = cancel_scan(
            db,
            scan_job_id=_JOB_ID,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            reason="operator requested",
            actor="operator-1",
        )
        assert result["status"] == "cancel_requested"

    def test_cancel_completed_job_raises(self):
        db = _make_cancel_db(update_returns=None, existing_status="complete")
        with pytest.raises(ScanAuthorizationError) as exc_info:
            cancel_scan(
                db,
                scan_job_id=_JOB_ID,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                reason="too late",
                actor="operator-1",
            )
        assert exc_info.value.audit_code == "CANCEL_TERMINAL_STATE"
        assert "complete" in exc_info.value.reason

    def test_cancel_failed_job_raises(self):
        db = _make_cancel_db(update_returns=None, existing_status="failed")
        with pytest.raises(ScanAuthorizationError) as exc_info:
            cancel_scan(
                db,
                scan_job_id=_JOB_ID,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                reason="too late",
                actor="operator-1",
            )
        assert exc_info.value.audit_code == "CANCEL_TERMINAL_STATE"

    def test_cancel_already_cancelled_is_idempotent(self):
        db = _make_cancel_db(update_returns=None, existing_status="cancelled")
        result = cancel_scan(
            db,
            scan_job_id=_JOB_ID,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            reason="duplicate",
            actor="operator-1",
        )
        assert result["status"] == "cancelled"
        assert result["idempotent"] is True

    def test_cancel_already_cancel_requested_is_idempotent(self):
        db = _make_cancel_db(update_returns=None, existing_status="cancel_requested")
        result = cancel_scan(
            db,
            scan_job_id=_JOB_ID,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            reason="duplicate",
            actor="operator-1",
        )
        assert result["status"] == "cancel_requested"
        assert result["idempotent"] is True

    def test_cancel_nonexistent_job_raises(self):
        db = _make_cancel_db(update_returns=None, existing_status=None)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            cancel_scan(
                db,
                scan_job_id="nonexistent-id",
                tenant_id=_TENANT,
                engagement_id=_ENG,
                reason="missing",
                actor="operator-1",
            )
        assert exc_info.value.audit_code == "CANCEL_JOB_NOT_FOUND"


class TestConfirmScanCancelled:
    def test_worker_confirms_cancel_requested_to_cancelled(self):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        db = _make_confirm_db(update_returns=(_JOB_ID, "cancelled", now))
        result = confirm_scan_cancelled(
            db,
            scan_job_id=_JOB_ID,
            tenant_id=_TENANT,
        )
        assert result["status"] == "cancelled"
        db.commit.assert_called_once()

    def test_already_cancelled_is_idempotent(self):
        db = _make_confirm_db(update_returns=None, existing_status="cancelled")
        result = confirm_scan_cancelled(
            db,
            scan_job_id=_JOB_ID,
            tenant_id=_TENANT,
        )
        assert result["status"] == "cancelled"
        assert result["idempotent"] is True

    def test_confirm_cancel_from_complete_raises(self):
        """CANCELLED wins over COMPLETED: worker must call confirm_scan_cancelled
        instead of mark_complete when it observes cancel_requested.
        If the job is already complete, raise — this is an ordering violation.
        """
        db = _make_confirm_db(update_returns=None, existing_status="complete")
        with pytest.raises(ScanAuthorizationError) as exc_info:
            confirm_scan_cancelled(
                db,
                scan_job_id=_JOB_ID,
                tenant_id=_TENANT,
            )
        assert exc_info.value.audit_code == "CONFIRM_CANCEL_INVALID_STATE"

    def test_confirm_cancel_nonexistent_raises(self):
        db = _make_confirm_db(update_returns=None, existing_status=None)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            confirm_scan_cancelled(
                db,
                scan_job_id="nonexistent",
                tenant_id=_TENANT,
            )
        assert exc_info.value.audit_code == "CONFIRM_CANCEL_JOB_NOT_FOUND"

    def test_cancel_state_survives_worker_crash(self):
        """cancel_requested is persisted in DB; a new worker reading the job
        still sees cancel_requested and can complete the transition.
        This test verifies the transition from cancel_requested → cancelled
        can be retried safely (idempotent once complete).
        """
        from datetime import datetime, timezone

        # First attempt — worker completes the transition.
        now = datetime.now(timezone.utc)
        db1 = _make_confirm_db(update_returns=(_JOB_ID, "cancelled", now))
        result1 = confirm_scan_cancelled(db1, scan_job_id=_JOB_ID, tenant_id=_TENANT)
        assert result1["status"] == "cancelled"

        # "Crashed" worker retries — job is already cancelled → idempotent.
        db2 = _make_confirm_db(update_returns=None, existing_status="cancelled")
        result2 = confirm_scan_cancelled(db2, scan_job_id=_JOB_ID, tenant_id=_TENANT)
        assert result2["idempotent"] is True
