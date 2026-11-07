"""L14-SCAN-SAFETY-001 — scope authorization adversarial tests.

Covers:
  - normalize_target() canonicalization
  - target_in_scope() matching rules (FQDN, IPv4, IPv6, CIDR)
  - check_scan_authorized() fail-closed authorization gate
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
    check_scan_authorized,
    normalize_target,
    target_in_scope,
)


# ---------------------------------------------------------------------------
# normalize_target
# ---------------------------------------------------------------------------


class TestNormalizeTarget:
    def test_fqdn_exact(self):
        assert normalize_target("example.com", "fqdn") == "example.com"

    def test_fqdn_uppercase_normalized(self):
        assert normalize_target("EXAMPLE.COM", "fqdn") == "example.com"

    def test_fqdn_trailing_dot_stripped(self):
        assert normalize_target("example.com.", "fqdn") == "example.com"

    def test_fqdn_subdomain_ok(self):
        assert normalize_target("sub.example.com", "fqdn") == "sub.example.com"

    def test_fqdn_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            normalize_target("", "fqdn")

    def test_fqdn_bare_dot_raises(self):
        with pytest.raises(ValueError):
            normalize_target(".", "fqdn")

    def test_fqdn_label_too_long_raises(self):
        long_label = "a" * 64
        with pytest.raises(ValueError):
            normalize_target(f"{long_label}.com", "fqdn")

    def test_fqdn_total_too_long_raises(self):
        # Build a name > 253 chars
        part = "a" * 60
        long_name = ".".join([part] * 5)  # 5 × 60 + 4 dots = 304 chars
        with pytest.raises(ValueError):
            normalize_target(long_name, "fqdn")

    def test_fqdn_invalid_chars_raises(self):
        with pytest.raises(ValueError):
            normalize_target("not_a_domain_or_ip!", "fqdn")

    def test_ipv4_canonical(self):
        assert normalize_target("8.8.8.8", "ipv4") == "8.8.8.8"

    def test_ipv4_malformed_raises(self):
        with pytest.raises(ValueError):
            normalize_target("999.999.0.0", "ipv4")

    def test_ipv6_canonical(self):
        result = normalize_target("2001:0db8::0001", "ipv6")
        assert result == "2001:db8::1"

    def test_ipv6_zone_id_raises(self):
        with pytest.raises(ValueError, match="zone"):
            normalize_target("fe80::1%eth0", "ipv6")

    def test_ipv4_mapped_ipv6_raises(self):
        """IPv4-mapped IPv6 must NOT be silently authorized as IPv4."""
        with pytest.raises(ValueError, match="IPv4-mapped"):
            normalize_target("::ffff:1.2.3.4", "ipv6")

    def test_cidr_v4_canonical(self):
        assert normalize_target("10.0.0.0/24", "cidr") == "10.0.0.0/24"

    def test_cidr_host_bits_normalized(self):
        # strict=False collapses host bits
        assert normalize_target("10.0.0.1/24", "cidr") == "10.0.0.0/24"

    def test_unsupported_type_raises(self):
        with pytest.raises(ValueError, match="unsupported target_type"):
            normalize_target("example.com", "unknown_type")


# ---------------------------------------------------------------------------
# target_in_scope
# ---------------------------------------------------------------------------


class TestTargetInScope:
    # FQDN exact match
    def test_fqdn_exact_match_authorized(self):
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        assert target_in_scope("example.com", "fqdn", approved) is True

    def test_fqdn_subdomain_no_explicit_permission_not_authorized(self):
        """Subdomains require explicit allow_subdomains=True — default is exact match only."""
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        assert target_in_scope("sub.example.com", "fqdn", approved) is False

    def test_fqdn_subdomain_with_explicit_permission_authorized(self):
        approved = [
            {
                "target": "example.com",
                "type": "fqdn",
                "operations": ["network_scan"],
                "allow_subdomains": True,
            }
        ]
        assert target_in_scope("sub.example.com", "fqdn", approved) is True

    def test_fqdn_lookalike_not_authorized(self):
        """evil-example.com must NOT match approved example.com."""
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        assert target_in_scope("evil-example.com", "fqdn", approved) is False

    def test_fqdn_subdomain_injection_not_authorized(self):
        """example.com.evil.tld must NOT match approved example.com."""
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        assert target_in_scope("example.com.evil.tld", "fqdn", approved) is False

    def test_fqdn_trailing_dot_normalized(self):
        """example.com. (trailing dot) == example.com."""
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        assert target_in_scope("example.com.", "fqdn", approved) is True

    def test_fqdn_mixed_case_normalized(self):
        """EXAMPLE.COM == example.com."""
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        assert target_in_scope("EXAMPLE.COM", "fqdn", approved) is True

    # IPv4 exact match
    def test_ipv4_exact_match_authorized(self):
        approved = [
            {"target": "1.2.3.4", "type": "ipv4", "operations": ["network_scan"]}
        ]
        assert target_in_scope("1.2.3.4", "ipv4", approved) is True

    def test_ipv4_cidr_containment_authorized(self):
        approved = [
            {"target": "1.2.3.0/24", "type": "cidr", "operations": ["network_scan"]}
        ]
        assert target_in_scope("1.2.3.100", "ipv4", approved) is True

    def test_ipv4_outside_cidr_not_authorized(self):
        approved = [
            {"target": "1.2.3.0/24", "type": "cidr", "operations": ["network_scan"]}
        ]
        assert target_in_scope("1.2.4.1", "ipv4", approved) is False

    # IPv4-mapped IPv6 never silently authorized
    def test_ipv4_mapped_ipv6_raises_on_normalization(self):
        approved = [
            {"target": "1.2.3.4", "type": "ipv4", "operations": ["network_scan"]}
        ]
        with pytest.raises(ValueError, match="IPv4-mapped"):
            target_in_scope("::ffff:1.2.3.4", "ipv6", approved)

    # Malformed target fails closed
    def test_malformed_candidate_raises(self):
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        with pytest.raises(ValueError):
            target_in_scope("not_a_domain_or_ip!", "fqdn", approved)

    def test_empty_candidate_raises(self):
        approved = [
            {"target": "example.com", "type": "fqdn", "operations": ["network_scan"]}
        ]
        with pytest.raises(ValueError, match="empty"):
            target_in_scope("", "fqdn", approved)

    def test_malformed_approved_entry_skipped_not_matched(self):
        """A malformed approved entry must not cause a match; it must be skipped."""
        approved = [
            {"target": "!!!invalid!!!", "type": "fqdn", "operations": ["network_scan"]},
            {"target": "good.com", "type": "fqdn", "operations": ["network_scan"]},
        ]
        assert target_in_scope("good.com", "fqdn", approved) is True
        assert target_in_scope("example.com", "fqdn", approved) is False


# ---------------------------------------------------------------------------
# check_scan_authorized — mock DB
# ---------------------------------------------------------------------------


def _make_db(
    *,
    emergency_stop: bool = False,
    auth_row: tuple | None = None,
    has_job: bool = False,
) -> MagicMock:
    """Build a mock DB session for unit-level authorization checks."""
    db = MagicMock()

    # Emergency stop query
    stop_result = MagicMock()
    stop_result.fetchone.return_value = (1,) if emergency_stop else None

    # Authorization query
    auth_result = MagicMock()
    auth_result.fetchone.return_value = auth_row

    db.execute.side_effect = [stop_result, auth_result]
    return db


def _now_plus(seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _now_minus(seconds: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


def _active_auth_row(
    *,
    approved_targets: list | None = None,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
    effective_from: datetime | None = None,
    tenant_id: str = "tenant-a",
    engagement_id: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
) -> tuple:
    return (
        "auth-001",  # id
        tenant_id,  # tenant_id
        engagement_id,  # engagement_id
        approved_targets
        or [
            {
                "target": "example.com",
                "type": "fqdn",
                "operations": ["network_scan", "web_headers", "dns_email"],
            }
        ],  # approved_targets
        "active",  # status
        effective_from,  # effective_from
        expires_at or _now_plus(86400),  # expires_at
        revoked_at,  # revoked_at
    )


class TestCheckScanAuthorized:
    _TENANT = "tenant-a"
    _ENG = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    def test_no_active_authorization_raises(self):
        db = _make_db(auth_row=None)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "NO_ACTIVE_AUTHORIZATION"

    def test_expired_authorization_raises(self):
        expired_at = _now_minus(60)
        db = _make_db(auth_row=_active_auth_row(expires_at=expired_at))
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "AUTHORIZATION_EXPIRED"

    def test_revoked_authorization_raises(self):
        db = _make_db(auth_row=_active_auth_row(revoked_at=_now_minus(60)))
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "AUTHORIZATION_REVOKED"

    def test_draft_no_active_raises(self):
        """The DB query filters status='active'; no active row → NO_ACTIVE_AUTHORIZATION."""
        db = _make_db(auth_row=None)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "NO_ACTIVE_AUTHORIZATION"

    def test_target_not_in_approved_list_raises(self):
        db = _make_db(
            auth_row=_active_auth_row(
                approved_targets=[
                    {
                        "target": "other.com",
                        "type": "fqdn",
                        "operations": ["network_scan"],
                    }
                ]
            )
        )
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "TARGET_NOT_IN_SCOPE"

    def test_operation_not_permitted_raises(self):
        db = _make_db(
            auth_row=_active_auth_row(
                approved_targets=[
                    {
                        "target": "example.com",
                        "type": "fqdn",
                        "operations": ["web_headers"],  # only web_headers allowed
                    }
                ]
            )
        )
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "OPERATION_NOT_PERMITTED"

    def test_emergency_stop_active_raises(self):
        db = _make_db(emergency_stop=True)
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_ACTIVE"

    def test_valid_auth_in_scope_permitted_operation_success(self):
        db = _make_db(auth_row=_active_auth_row())
        result = check_scan_authorized(
            db,
            tenant_id=self._TENANT,
            engagement_id=self._ENG,
            target="example.com",
            target_type="fqdn",
            operation="network_scan",
        )
        assert result["authorization_id"] == "auth-001"
        assert result["operation"] == "network_scan"

    def test_db_error_on_emergency_stop_check_fails_closed(self):
        """If DB raises during emergency stop check, fail closed."""
        db = MagicMock()
        db.execute.side_effect = RuntimeError("DB connection lost")
        with pytest.raises(ScanAuthorizationError) as exc_info:
            check_scan_authorized(
                db,
                tenant_id=self._TENANT,
                engagement_id=self._ENG,
                target="example.com",
                target_type="fqdn",
                operation="network_scan",
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_CHECK_FAILED"
