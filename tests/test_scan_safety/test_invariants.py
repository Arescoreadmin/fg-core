"""L14-SCAN-SAFETY-001 — domain invariants A through L.

Each test corresponds to one of the 12 domain invariants specified in the
L14-SCAN-SAFETY-001 implementation brief.
"""

from __future__ import annotations

import inspect
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
    confirm_scan_cancelled,
    normalize_target,
    target_in_scope,
)
from services.connectors.safe_target_validator import SafeTargetValidationService


_TENANT = "tenant-invariants"
_ENG = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
_JOB = "job-invariant-001"


def _now_plus(seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _make_auth_db(auth_row=None, emergency_stop: bool = False) -> MagicMock:
    db = MagicMock()

    stop_result = MagicMock()
    stop_result.fetchone.return_value = (1,) if emergency_stop else None

    auth_result = MagicMock()
    auth_result.fetchone.return_value = auth_row

    db.execute.side_effect = [stop_result, auth_result]
    return db


def _active_auth_row(targets=None) -> tuple:
    return (
        "auth-inv",
        _TENANT,
        _ENG,
        targets
        or [
            {
                "target": "client.example.com",
                "type": "fqdn",
                "operations": ["network_scan"],
            }
        ],
        "active",
        None,
        _now_plus(86400),
        None,
    )


class TestInvariantA:
    """A: Technical reachability ≠ permission.

    A host that is publicly routable (passes SSRF) must still be denied if it
    is not in the engagement's authorized scope.
    """

    def test_reachable_but_unauthorized_target_denied(self):
        """8.8.8.8 is reachable but not in the engagement scope → denied."""
        # 8.8.8.8 passes SafeTargetValidationService (it's not RFC1918).
        svc = SafeTargetValidationService(dns_resolver=lambda h: ["8.8.8.8"])
        ssrf_result = svc.validate("8.8.8.8")
        assert ssrf_result.ok is True, "8.8.8.8 should pass SSRF check"

        # But the scan authorization denies it because it's not in the approved scope.
        db = _make_auth_db(
            auth_row=_active_auth_row(
                targets=[
                    {
                        "target": "client.example.com",
                        "type": "fqdn",
                        "operations": ["network_scan"],
                    }
                ]
            )
        )
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="8.8.8.8",
                target_type="ipv4",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "TARGET_NOT_IN_SCOPE"


class TestInvariantB:
    """B: Target must be in approved scope."""

    def test_target_not_in_scope_denied(self):
        db = _make_auth_db(auth_row=_active_auth_row())
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="attacker.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "TARGET_NOT_IN_SCOPE"


class TestInvariantC:
    """C: Target must belong to correct tenant+engagement."""

    def test_wrong_tenant_no_active_auth(self):
        """Tenant mismatch — the DB query returns no row for the wrong tenant."""
        db = _make_auth_db(auth_row=None)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id="other-tenant",
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "NO_ACTIVE_AUTHORIZATION"


class TestInvariantD:
    """D: Scope approval cannot silently authorize different scanner operation."""

    def test_web_headers_approval_does_not_permit_network_scan(self):
        db = _make_auth_db(
            auth_row=_active_auth_row(
                targets=[
                    {
                        "target": "client.example.com",
                        "type": "fqdn",
                        "operations": ["web_headers"],  # web_headers only
                    }
                ]
            )
        )
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",  # not permitted
            )
        assert exc_info.value.audit_code == "OPERATION_NOT_PERMITTED"


class TestInvariantE:
    """E: Revocation blocks new dispatch."""

    def test_revoked_authorization_blocks_scan(self):
        revoked_row = (
            "auth-revoked",
            _TENANT,
            _ENG,
            [
                {
                    "target": "client.example.com",
                    "type": "fqdn",
                    "operations": ["network_scan"],
                }
            ],
            "active",
            None,
            _now_plus(86400),
            datetime.now(timezone.utc) - timedelta(seconds=60),  # revoked_at set
        )
        db = _make_auth_db(auth_row=revoked_row)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "AUTHORIZATION_REVOKED"


class TestInvariantF:
    """F: Cancellation is durable (persists across restart).

    The cancellation state is in the DB (cancel_requested / cancelled columns),
    not in-memory. We verify the service uses DB-backed UPDATE.
    """

    def test_cancel_uses_db_update_not_memory(self):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        db = MagicMock()
        update_result = MagicMock()
        update_result.fetchone.return_value = (_JOB, "cancel_requested", now)
        db.execute.return_value = update_result

        result = cancel_scan(
            db,
            scan_job_id=_JOB,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            reason="durable test",
            actor="op",
        )
        # Verify db.execute was called (DB-backed, not in-memory)
        db.execute.assert_called_once()
        assert result["status"] == "cancel_requested"


class TestInvariantG:
    """G: Cancelled scan cannot become completed."""

    def test_confirm_cancel_from_complete_raises(self):
        """Once a job is complete, it cannot be cancelled."""
        db = MagicMock()
        update_result = MagicMock()
        update_result.fetchone.return_value = None  # no rows updated

        select_result = MagicMock()
        select_result.fetchone.return_value = ("complete",)

        db.execute.side_effect = [update_result, select_result]

        with pytest.raises(ScanAuthorizationError) as exc_info:
            confirm_scan_cancelled(db, scan_job_id=_JOB, tenant_id=_TENANT)
        assert exc_info.value.audit_code == "CONFIRM_CANCEL_INVALID_STATE"


class TestInvariantH:
    """H: Emergency stop blocks execution until cleared."""

    def test_emergency_stop_blocks_new_scan(self):
        db = _make_auth_db(emergency_stop=True)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_ACTIVE"


class TestInvariantI:
    """I: SSRF protections still active alongside authorization.

    SafeTargetValidationService is not bypassed by scan authorization.
    Private IPs remain blocked regardless of authorization state.
    """

    def test_private_ip_rejected_by_ssrf_independent_of_auth(self):
        """SSRF validation is independent of auth. Private IP blocked at SSRF layer."""
        svc = SafeTargetValidationService(dns_resolver=lambda h: ["192.168.1.1"])
        result = svc.validate("192.168.1.1")
        assert result.ok is False
        assert result.rejection_code == "BLOCKED_IP"

    def test_ssrf_does_not_check_engagement_scope(self):
        """SafeTargetValidationService has no engagement_id — it's purely SSRF.
        Authorization is a separate additional check."""
        sig = inspect.signature(SafeTargetValidationService.validate)
        assert "engagement_id" not in sig.parameters


class TestInvariantJ:
    """J: Unsupported/ambiguous scope expressions fail closed."""

    def test_unsupported_target_type_raises(self):
        with pytest.raises(ValueError, match="unsupported target_type"):
            normalize_target("example.com", "wildcard")

    def test_empty_target_raises(self):
        with pytest.raises(ValueError, match="empty"):
            normalize_target("", "fqdn")

    def test_malformed_ipv4_raises(self):
        with pytest.raises(ValueError):
            normalize_target("999.0.0.1", "ipv4")

    def test_ipv4_mapped_ipv6_fails_closed(self):
        with pytest.raises(ValueError, match="IPv4-mapped"):
            normalize_target("::ffff:1.2.3.4", "ipv6")

    def test_malformed_target_in_scope_check_raises(self):
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        with pytest.raises(ValueError):
            target_in_scope("not!valid", "fqdn", approved)


class TestInvariantK:
    """K: Missing authorization state fails closed."""

    def test_no_auth_record_fails_closed(self):
        db = _make_auth_db(auth_row=None)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "NO_ACTIVE_AUTHORIZATION"

    def test_db_error_fails_closed(self):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("DB timeout")
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        # Should fail closed, not let the scan through
        assert (
            "FAILED" in exc_info.value.audit_code
            or "ACTIVE" in exc_info.value.audit_code
        )

    def test_empty_approved_targets_fails_closed(self):
        empty_targets_row = (
            "auth-empty",
            _TENANT,
            _ENG,
            [],  # empty approved_targets
            "active",
            None,
            _now_plus(86400),
            None,
        )
        db = _make_auth_db(auth_row=empty_targets_row)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "AUTHORIZATION_TARGETS_EMPTY"


class TestInvariantL:
    """L: Denied operations produce audit events without leaking cross-tenant metadata.

    The ScanAuthorizationError reason field must NOT include the other tenant's
    data when a cross-tenant isolation check fails.
    """

    def test_denied_error_does_not_leak_other_tenant_data(self):
        """The error message should not expose other tenant's target list."""
        db = _make_auth_db(auth_row=None)  # No auth for caller's tenant

        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="client.example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        # The error reason must not contain other tenant's identifiers
        assert "tenant-b" not in exc_info.value.reason.lower()
        assert "other-tenant" not in exc_info.value.reason.lower()
        # It should just say "no active authorization"
        assert "no active" in exc_info.value.reason.lower()

    def test_denied_error_has_audit_code_without_target_details(self):
        """Audit code must not leak the full target list from the authorization record."""
        db = _make_auth_db(
            auth_row=_active_auth_row(
                targets=[
                    {
                        "target": "other-client.internal.example.com",
                        "type": "fqdn",
                        "operations": ["network_scan"],
                    }
                ]
            )
        )
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENG,
                target="attacker.com",
                target_type="fqdn",
                operation="network_scan",
            )
        # Audit code must be clean
        assert exc_info.value.audit_code == "TARGET_NOT_IN_SCOPE"
        # Reason must not expose the approved target list
        assert "other-client.internal.example.com" not in exc_info.value.reason
