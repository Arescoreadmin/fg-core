"""L14-SCAN-SAFETY-001 — tenant isolation adversarial tests.

Verifies that:
- Operator from tenant A cannot use tenant B's authorization
- Scan job from tenant A cannot be cancelled by tenant B operator
- Cross-tenant engagement reference denied at authorization check
- Forged tenant_id in scope ID denied
- Authorization receipt belonging to another engagement denied
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

from services.field_assessment.scan_authorization import (
    ScanAuthorizationError,
    cancel_scan,
    check_scan_authorized,
)

_TENANT_A = "tenant-isolation-a"
_TENANT_B = "tenant-isolation-b"
_ENG_A = "aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
_ENG_B = "bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb"
_JOB_A = "job-tenant-a-001"


def _now_plus(seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _auth_row_for_tenant_b() -> tuple:
    """An active authorization that belongs to tenant B, not tenant A."""
    return (
        "auth-tenant-b",
        _TENANT_B,  # tenant_id = B
        _ENG_B,  # engagement_id = B's engagement
        [{"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}],
        "active",
        None,
        _now_plus(86400),
        None,
    )


def _make_check_db(auth_row=None, emergency_stop: bool = False) -> MagicMock:
    db = MagicMock()

    stop_result = MagicMock()
    stop_result.fetchone.return_value = (1,) if emergency_stop else None

    auth_result = MagicMock()
    auth_result.fetchone.return_value = auth_row

    db.execute.side_effect = [stop_result, auth_result]
    return db


class TestCrossTenantAuthorizationDenied:
    def test_operator_a_cannot_use_tenant_b_authorization(self):
        """Even if tenant B's auth row is somehow returned, the tenant mismatch is caught."""
        # Simulate: DB (incorrectly) returns tenant B's auth row for tenant A's query.
        auth_row = _auth_row_for_tenant_b()
        db = _make_check_db(auth_row=auth_row)

        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT_A,  # caller is tenant A
                engagement_id=_ENG_A,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        # Tenant mismatch must be caught
        assert exc_info.value.audit_code in (
            "AUTHORIZATION_TENANT_MISMATCH",
            "AUTHORIZATION_ENGAGEMENT_MISMATCH",
        )

    def test_no_auth_for_tenant_a_raises(self):
        """Tenant A has no active authorization — the scan must be denied."""
        db = _make_check_db(auth_row=None)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT_A,
                engagement_id=_ENG_A,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "NO_ACTIVE_AUTHORIZATION"

    def test_forged_engagement_id_in_auth_row_caught(self):
        """Auth row with matching tenant but wrong engagement_id must be rejected."""
        forged_row = (
            "auth-forged",
            _TENANT_A,  # tenant matches
            _ENG_B,  # but engagement is B's, not A's
            [{"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}],
            "active",
            None,
            _now_plus(86400),
            None,
        )
        db = _make_check_db(auth_row=forged_row)

        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT_A,
                engagement_id=_ENG_A,  # caller's engagement
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "AUTHORIZATION_ENGAGEMENT_MISMATCH"


def _make_cancel_db(
    update_returns=None, existing_status: str | None = None
) -> MagicMock:
    db = MagicMock()

    update_result = MagicMock()
    update_result.fetchone.return_value = update_returns

    select_result = MagicMock()
    if existing_status is not None:
        select_result.fetchone.return_value = (_JOB_A, existing_status)
    else:
        select_result.fetchone.return_value = None

    db.execute.side_effect = [update_result, select_result]
    return db


class TestCrossTenantCancellationDenied:
    def test_tenant_b_cannot_cancel_tenant_a_job(self):
        """cancel_scan scopes the UPDATE to tenant_id — tenant B gets a not-found error."""
        # The UPDATE WHERE clause includes tenant_id = :tenant_id.
        # Tenant B's query finds no rows for tenant A's job → job not found.
        db = _make_cancel_db(update_returns=None, existing_status=None)

        with pytest.raises(ScanAuthorizationError) as exc_info:
            cancel_scan(
                db,
                scan_job_id=_JOB_A,
                tenant_id=_TENANT_B,  # wrong tenant
                engagement_id=_ENG_A,
                reason="cross-tenant attempt",
                actor="attacker",
            )
        assert exc_info.value.audit_code == "CANCEL_JOB_NOT_FOUND"

    def test_correct_tenant_can_cancel_own_job(self):
        """Tenant A can cancel their own queued job."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        db = _make_cancel_db(update_returns=(_JOB_A, "cancel_requested", now))

        result = cancel_scan(
            db,
            scan_job_id=_JOB_A,
            tenant_id=_TENANT_A,
            engagement_id=_ENG_A,
            reason="operator request",
            actor="operator-a",
        )
        assert result["status"] == "cancel_requested"
