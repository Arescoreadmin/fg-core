"""
tests/control_plane/test_control_plane_phase4.py — Phase 4: MSP Delegation Tests.

Tests cover:
  - Delegation creation with valid inputs
  - Delegation expiry enforcement
  - Delegation revocation (permanent)
  - Cross-tenant access check (valid delegation)
  - Cross-tenant access check (missing/expired/revoked → ValueError)
  - Scope validation (only VALID_DELEGATION_SCOPES allowed)
  - Anti-enumeration: 404 for unauthorized cross-tenant
  - Negative tests for each invariant

Security invariants verified:
  - target_tenant never empty
  - Scope additive-only (valid scopes only)
  - Expired delegations permanently invalid
  - Revoked delegations cannot be un-revoked
  - Missing delegation → NOT_FOUND (anti-enumeration)
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

from services.cp_msp_delegation import (
    MSPDelegationService,
    DelegationRecord,
    DELEGATION_MAX_TTL_HOURS,
    ERR_DELEGATION_NOT_FOUND,
    ERR_DELEGATION_INVALID_TENANT,
    ERR_DELEGATION_INVALID_SCOPE,
    ERR_DELEGATION_TTL_EXCEEDED,
    reset_delegation_store,
)


class _MockLedger:
    """Minimal ledger stub for testing."""

    def __init__(self):
        self.events = []

    def append_event(self, **kwargs):
        from dataclasses import dataclass

        @dataclass
        class Entry:
            id: str = "test-event-id"

        self.events.append(kwargs)
        return Entry()


class _MockDB:
    """Minimal DB session stub for testing."""

    def query(self, *args):
        return self

    def filter_by(self, **kwargs):
        return self

    def all(self):
        return []

    def first(self):
        return None

    def add(self, obj):
        pass

    def flush(self):
        pass

    def begin(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture(autouse=True)
def clear_store():
    """Clear the in-memory delegation store before each test."""
    reset_delegation_store()
    yield
    reset_delegation_store()


@pytest.fixture
def svc():
    return MSPDelegationService()


@pytest.fixture
def ledger():
    return _MockLedger()


@pytest.fixture
def db():
    return _MockDB()


class TestDelegationCreation:
    """Tests for delegation creation."""

    def test_create_delegation_basic(self, svc, ledger, db):
        """Create a delegation with valid inputs."""
        rec = svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-actor-001",
            delegatee_id="operator-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read",
            ttl_hours=24,
            trace_id="trace-001",
        )
        assert rec.delegation_id
        assert rec.delegator_id == "msp-actor-001"
        assert rec.delegatee_id == "operator-001"
        assert rec.target_tenant == "tenant-alpha"
        assert "control-plane:read" in rec.scope
        assert rec.revoked is False

    def test_create_delegation_emits_ledger_event(self, svc, ledger, db):
        """Delegation creation emits a ledger event."""
        svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read",
            ttl_hours=1,
            trace_id="t1",
        )
        assert len(ledger.events) == 1
        evt = ledger.events[0]
        assert evt["severity"] == "warning"
        assert evt["tenant_id"] == "tenant-alpha"

    def test_create_delegation_expiry_set(self, svc, ledger, db):
        """Delegation expiry is set correctly."""
        rec = svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read",
            ttl_hours=48,
            trace_id="t1",
        )
        exp = datetime.fromisoformat(rec.expires_at.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        # Should be approximately 48 hours from now
        diff = exp - now
        assert timedelta(hours=47) < diff < timedelta(hours=49)

    def test_create_delegation_multiple_scopes(self, svc, ledger, db):
        """Multiple valid scopes can be granted."""
        rec = svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read,control-plane:audit:read",
            ttl_hours=1,
            trace_id="t1",
        )
        assert "control-plane:read" in rec.scope
        assert "control-plane:audit:read" in rec.scope

    def test_create_delegation_to_dict(self, svc, ledger, db):
        """DelegationRecord.to_dict() contains all required fields."""
        rec = svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-beta",
            scope="control-plane:read",
            ttl_hours=1,
            trace_id="t1",
        )
        d = rec.to_dict()
        required_fields = [
            "delegation_id", "delegator_id", "delegatee_id", "target_tenant",
            "scope", "expires_at", "revoked", "trace_id", "created_at",
        ]
        for f in required_fields:
            assert f in d, f"Missing field: {f}"


class TestDelegationNegative:
    """Negative tests for delegation invariants."""

    def test_invariant_empty_target_tenant_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Empty target_tenant must be rejected.
        Prevents global delegations (anti-enumeration).
        """
        with pytest.raises(ValueError, match=ERR_DELEGATION_INVALID_TENANT):
            svc.create_delegation(
                db_session=db,
                ledger=ledger,
                delegator_id="msp-001",
                delegatee_id="op-001",
                target_tenant="",
                scope="control-plane:read",
                ttl_hours=1,
                trace_id="t1",
            )

    def test_invariant_whitespace_tenant_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Whitespace-only target_tenant is rejected.
        """
        with pytest.raises(ValueError, match=ERR_DELEGATION_INVALID_TENANT):
            svc.create_delegation(
                db_session=db,
                ledger=ledger,
                delegator_id="msp-001",
                delegatee_id="op-001",
                target_tenant="   ",
                scope="control-plane:read",
                ttl_hours=1,
                trace_id="t1",
            )

    def test_invariant_unknown_scope_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Unknown scope is rejected.
        Only VALID_DELEGATION_SCOPES are allowed.
        """
        with pytest.raises(ValueError, match=ERR_DELEGATION_INVALID_SCOPE):
            svc.create_delegation(
                db_session=db,
                ledger=ledger,
                delegator_id="msp-001",
                delegatee_id="op-001",
                target_tenant="tenant-alpha",
                scope="control-plane:admin:superuser",  # Not in allowlist
                ttl_hours=1,
                trace_id="t1",
            )

    def test_invariant_dangerous_scope_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Scope granting filesystem access rejected.
        """
        with pytest.raises(ValueError, match=ERR_DELEGATION_INVALID_SCOPE):
            svc.create_delegation(
                db_session=db,
                ledger=ledger,
                delegator_id="msp-001",
                delegatee_id="op-001",
                target_tenant="tenant-alpha",
                scope="shell:exec",  # Not in allowlist
                ttl_hours=1,
                trace_id="t1",
            )

    def test_invariant_ttl_exceeds_max_rejected(self, svc, ledger, db):
        """
        NEGATIVE: TTL exceeding DELEGATION_MAX_TTL_HOURS is rejected.
        """
        with pytest.raises(ValueError, match=ERR_DELEGATION_TTL_EXCEEDED):
            svc.create_delegation(
                db_session=db,
                ledger=ledger,
                delegator_id="msp-001",
                delegatee_id="op-001",
                target_tenant="tenant-alpha",
                scope="control-plane:read",
                ttl_hours=DELEGATION_MAX_TTL_HOURS + 1,
                trace_id="t1",
            )


class TestDelegationRevocation:
    """Tests for delegation revocation."""

    def test_revoke_delegation(self, svc, ledger, db):
        """Delegation can be revoked."""
        rec = svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read",
            ttl_hours=24,
            trace_id="t1",
        )
        revoked = svc.revoke_delegation(
            db_session=db,
            ledger=ledger,
            delegation_id=rec.delegation_id,
            actor_id="msp-001",
            trace_id="t2",
        )
        assert revoked.revoked is True

    def test_revoke_nonexistent_raises(self, svc, ledger, db):
        """
        NEGATIVE: Revoking non-existent delegation raises NOT_FOUND.
        """
        with pytest.raises(ValueError, match=ERR_DELEGATION_NOT_FOUND):
            svc.revoke_delegation(
                db_session=db,
                ledger=ledger,
                delegation_id="nonexistent-id",
                actor_id="msp-001",
                trace_id="t1",
            )

    def test_revoked_delegation_invalid(self, svc, ledger, db):
        """
        NEGATIVE: Revoked delegation is permanently invalid.
        """
        rec = svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read",
            ttl_hours=24,
            trace_id="t1",
        )
        svc.revoke_delegation(
            db_session=db,
            ledger=ledger,
            delegation_id=rec.delegation_id,
            actor_id="msp-001",
            trace_id="t2",
        )
        # Now check_delegation should fail
        with pytest.raises(ValueError, match=ERR_DELEGATION_NOT_FOUND):
            svc.check_delegation(
                db_session=db,
                delegatee_id="op-001",
                target_tenant="tenant-alpha",
                required_scope="control-plane:read",
            )


class TestDelegationAccessCheck:
    """Tests for cross-tenant access check enforcement."""

    def test_check_delegation_valid(self, svc, ledger, db):
        """Valid delegation grants access."""
        svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read",
            ttl_hours=24,
            trace_id="t1",
        )
        # Should not raise
        result = svc.check_delegation(
            db_session=db,
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            required_scope="control-plane:read",
        )
        assert result.delegatee_id == "op-001"

    def test_check_delegation_missing_raises_not_found(self, svc, db):
        """
        NEGATIVE: Missing delegation raises NOT_FOUND (anti-enumeration: no 403).
        """
        with pytest.raises(ValueError, match=ERR_DELEGATION_NOT_FOUND):
            svc.check_delegation(
                db_session=db,
                delegatee_id="op-unknown",
                target_tenant="tenant-alpha",
                required_scope="control-plane:read",
            )

    def test_check_delegation_wrong_tenant_raises(self, svc, ledger, db):
        """
        NEGATIVE: Delegation for different tenant fails check for different tenant.
        Anti-enumeration: returns NOT_FOUND (not 403).
        """
        svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",  # delegated for alpha
            scope="control-plane:read",
            ttl_hours=24,
            trace_id="t1",
        )
        with pytest.raises(ValueError, match=ERR_DELEGATION_NOT_FOUND):
            svc.check_delegation(
                db_session=db,
                delegatee_id="op-001",
                target_tenant="tenant-beta",  # but trying to access beta
                required_scope="control-plane:read",
            )

    def test_check_delegation_insufficient_scope_raises(self, svc, ledger, db):
        """
        NEGATIVE: Delegation with read scope fails admin scope check.
        """
        svc.create_delegation(
            db_session=db,
            ledger=ledger,
            delegator_id="msp-001",
            delegatee_id="op-001",
            target_tenant="tenant-alpha",
            scope="control-plane:read",  # only read
            ttl_hours=24,
            trace_id="t1",
        )
        with pytest.raises(ValueError, match=ERR_DELEGATION_NOT_FOUND):
            svc.check_delegation(
                db_session=db,
                delegatee_id="op-001",
                target_tenant="tenant-alpha",
                required_scope="control-plane:admin",  # needs admin
            )


class TestDelegationRecord:
    """Tests for DelegationRecord validation methods."""

    def test_record_is_valid_not_expired(self):
        """Non-expired, non-revoked record is valid."""
        now = datetime.now(timezone.utc)
        rec = DelegationRecord(
            delegation_id="d1",
            delegator_id="m1",
            delegatee_id="o1",
            target_tenant="t1",
            scope="control-plane:read",
            expires_at=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            revoked=False,
            trace_id="",
            created_at=now.isoformat().replace("+00:00", "Z"),
        )
        assert rec.is_valid(now=now) is True

    def test_record_is_invalid_expired(self):
        """Expired record is invalid."""
        now = datetime.now(timezone.utc)
        rec = DelegationRecord(
            delegation_id="d1",
            delegator_id="m1",
            delegatee_id="o1",
            target_tenant="t1",
            scope="control-plane:read",
            expires_at=(now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            revoked=False,
            trace_id="",
            created_at=(now - timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
        )
        assert rec.is_valid(now=now) is False

    def test_record_is_invalid_revoked(self):
        """Revoked record is invalid even if not expired."""
        now = datetime.now(timezone.utc)
        rec = DelegationRecord(
            delegation_id="d1",
            delegator_id="m1",
            delegatee_id="o1",
            target_tenant="t1",
            scope="control-plane:read",
            expires_at=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            revoked=True,
            trace_id="",
            created_at=now.isoformat().replace("+00:00", "Z"),
        )
        assert rec.is_valid(now=now) is False

    def test_record_grants_scope(self):
        """grants_scope returns True for included scope."""
        rec = DelegationRecord(
            delegation_id="d1",
            delegator_id="m1",
            delegatee_id="o1",
            target_tenant="t1",
            scope="control-plane:read,control-plane:audit:read",
            expires_at="2099-01-01T00:00:00Z",
            revoked=False,
            trace_id="",
            created_at="2024-01-01T00:00:00Z",
        )
        assert rec.grants_scope("control-plane:read") is True
        assert rec.grants_scope("control-plane:audit:read") is True
        assert rec.grants_scope("control-plane:admin") is False
