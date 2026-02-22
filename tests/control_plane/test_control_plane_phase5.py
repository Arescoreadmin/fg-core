"""
tests/control_plane/test_control_plane_phase5.py — Phase 5: Policy Lifecycle Tests.

Tests cover:
  - Policy pinning with valid inputs
  - Policy staging (canary rollout) with valid rollout percentage
  - Policy rollback to previous pinned version
  - Listing active policy pins for a tenant
  - Version hash validation (must be 64-char hex)
  - TTL bounds enforcement
  - Rollout percentage bounds
  - Rollback without a prior pin (ERR_POLICY_NO_ROLLBACK_TARGET)
  - Cross-tenant pin isolation (no enumeration)
  - Negative tests for each invariant

Security invariants verified:
  - policy_id never empty / must match slug pattern
  - version_hash must be 64-char hex (SHA-256)
  - TTL bounded 1–POLICY_PIN_MAX_TTL_HOURS
  - rollout_pct bounded 0–100
  - Rollback without prior pin raises ERR_POLICY_NO_ROLLBACK_TARGET
  - Pins are per-tenant (no cross-tenant leakage)
  - All operations emit ledger events at warning severity
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from services.cp_policy_lifecycle import (
    PolicyLifecycleService,
    POLICY_PIN_MAX_TTL_HOURS,
    ERR_POLICY_NOT_FOUND,
    ERR_POLICY_INVALID_HASH,
    ERR_POLICY_INVALID_TTL,
    ERR_POLICY_NO_ROLLBACK_TARGET,
    ERR_POLICY_INVALID_ROLLOUT_PCT,
    ERR_POLICY_INVALID_POLICY_ID,
    reset_policy_lifecycle_store,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A valid SHA-256 hex string (64 chars, lowercase hex)
_VALID_HASH_A = "a" * 64
_VALID_HASH_B = "b" * 64
_VALID_HASH_C = "c" * 64


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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_store():
    """Clear the in-memory policy lifecycle store before each test."""
    reset_policy_lifecycle_store()
    yield
    reset_policy_lifecycle_store()


@pytest.fixture
def svc():
    return PolicyLifecycleService()


@pytest.fixture
def ledger():
    return _MockLedger()


@pytest.fixture
def db():
    return _MockDB()


# ---------------------------------------------------------------------------
# TestPolicyPinning
# ---------------------------------------------------------------------------


class TestPolicyPinning:
    """Tests for policy version pinning."""

    def test_pin_policy_version_basic(self, svc, ledger, db):
        """Pin a policy version with valid inputs."""
        rec = svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=24,
            actor_id="admin-001",
            trace_id="trace-001",
        )
        assert rec.pin_id
        assert rec.tenant_id == "tenant-alpha"
        assert rec.policy_id == "opa-core"
        assert rec.version_hash == _VALID_HASH_A
        assert rec.rollout_pct == 100
        assert rec.staged is False
        assert rec.active is True

    def test_pin_policy_emits_ledger_event(self, svc, ledger, db):
        """Pinning emits a ledger event at warning severity."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=24,
            actor_id="admin-001",
            trace_id="t1",
        )
        assert len(ledger.events) == 1
        evt = ledger.events[0]
        assert evt["severity"] == "warning"
        assert evt["event_type"] == "cp_policy_lifecycle"
        assert evt["tenant_id"] == "tenant-alpha"
        assert evt["payload"]["action"] == "policy_pinned"

    def test_pin_policy_expiry_set(self, svc, ledger, db):
        """Pin expiry is set correctly based on ttl_hours."""
        rec = svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=48,
            actor_id="admin-001",
            trace_id="t1",
        )
        exp = datetime.fromisoformat(rec.expires_at.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = exp - now
        assert 47 * 3600 < diff.total_seconds() < 49 * 3600

    def test_pin_records_previous_hash(self, svc, ledger, db):
        """A new pin records the previous version hash for rollback."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        rec2 = svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t2",
        )
        assert rec2.previous_hash == _VALID_HASH_A

    def test_pin_to_dict_contains_all_fields(self, svc, ledger, db):
        """PolicyPinRecord.to_dict() contains all required fields."""
        rec = svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=24,
            actor_id="admin-001",
            trace_id="t1",
        )
        d = rec.to_dict()
        for field in [
            "pin_id",
            "tenant_id",
            "policy_id",
            "version_hash",
            "rollout_pct",
            "staged",
            "expires_at",
            "created_at",
            "previous_hash",
            "trace_id",
            "active",
        ]:
            assert field in d, f"Missing field: {field}"

    def test_pin_deactivates_previous_pin(self, svc, ledger, db):
        """Pinning a new version deactivates the previous active pin."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t2",
        )
        active = svc.get_pin(db_session=db, tenant_id="tenant-alpha", policy_id="opa-core")
        assert active is not None
        assert active.version_hash == _VALID_HASH_B


# ---------------------------------------------------------------------------
# TestPolicyStaging
# ---------------------------------------------------------------------------


class TestPolicyStaging:
    """Tests for policy canary staging."""

    def test_stage_policy_version_basic(self, svc, ledger, db):
        """Stage a policy version with valid rollout percentage."""
        rec = svc.stage_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            rollout_pct=20,
            ttl_hours=24,
            actor_id="admin-001",
            trace_id="trace-001",
        )
        assert rec.staged is True
        assert rec.rollout_pct == 20
        assert rec.active is True
        assert rec.version_hash == _VALID_HASH_B

    def test_stage_policy_emits_ledger_event(self, svc, ledger, db):
        """Staging emits a ledger event at warning severity."""
        svc.stage_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            rollout_pct=50,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        assert len(ledger.events) == 1
        evt = ledger.events[0]
        assert evt["severity"] == "warning"
        assert evt["payload"]["action"] == "policy_staged"
        assert evt["payload"]["rollout_pct"] == 50

    def test_stage_zero_rollout(self, svc, ledger, db):
        """0% rollout is valid (stage prepared but not yet serving traffic)."""
        rec = svc.stage_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            rollout_pct=0,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        assert rec.rollout_pct == 0

    def test_stage_full_rollout(self, svc, ledger, db):
        """100% rollout is valid."""
        rec = svc.stage_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            rollout_pct=100,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        assert rec.rollout_pct == 100


# ---------------------------------------------------------------------------
# TestPolicyRollback
# ---------------------------------------------------------------------------


class TestPolicyRollback:
    """Tests for policy rollback."""

    def test_rollback_to_previous_hash(self, svc, ledger, db):
        """Rollback restores the previous pinned version hash."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t2",
        )
        rolled = svc.rollback(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            actor_id="admin-001",
            trace_id="t3",
        )
        assert rolled.version_hash == _VALID_HASH_A
        assert rolled.active is True

    def test_rollback_emits_ledger_event(self, svc, ledger, db):
        """Rollback emits a ledger event at warning severity."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t2",
        )
        ledger.events.clear()  # reset so we only see rollback event
        svc.rollback(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            actor_id="admin-001",
            trace_id="t3",
        )
        assert len(ledger.events) == 1
        evt = ledger.events[0]
        assert evt["severity"] == "warning"
        assert evt["payload"]["action"] == "policy_rolled_back"

    def test_rollback_records_payload(self, svc, ledger, db):
        """Rollback ledger payload includes rolled_back_from hash."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_B,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t2",
        )
        ledger.events.clear()
        svc.rollback(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            actor_id="admin-001",
            trace_id="t3",
        )
        payload = ledger.events[0]["payload"]
        assert payload["rolled_back_from"] == _VALID_HASH_B


# ---------------------------------------------------------------------------
# TestListPolicyPins
# ---------------------------------------------------------------------------


class TestListPolicyPins:
    """Tests for listing policy pins."""

    def test_list_pins_empty(self, svc, db):
        """Empty list returned when no pins exist."""
        pins = svc.list_pins(db_session=db, tenant_id="tenant-alpha")
        assert pins == []

    def test_list_pins_returns_active(self, svc, ledger, db):
        """list_pins returns currently active pins."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        pins = svc.list_pins(db_session=db, tenant_id="tenant-alpha")
        assert len(pins) == 1
        assert pins[0].policy_id == "opa-core"

    def test_list_pins_isolated_by_tenant(self, svc, ledger, db):
        """Pins from one tenant are not visible to another."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        pins_beta = svc.list_pins(db_session=db, tenant_id="tenant-beta")
        assert pins_beta == []

    def test_list_pins_multiple_policies(self, svc, ledger, db):
        """Multiple policies for the same tenant are listed."""
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-network",
            version_hash=_VALID_HASH_B,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t2",
        )
        pins = svc.list_pins(db_session=db, tenant_id="tenant-alpha")
        policy_ids = {p.policy_id for p in pins}
        assert "opa-core" in policy_ids
        assert "opa-network" in policy_ids


# ---------------------------------------------------------------------------
# TestPolicyNegative — Invariant Enforcement
# ---------------------------------------------------------------------------


class TestPolicyNegative:
    """Negative tests — all security invariants must hold."""

    def test_invariant_invalid_version_hash_rejected(self, svc, ledger, db):
        """
        NEGATIVE: version_hash shorter than 64 chars must be rejected.
        Only full SHA-256 hex strings are valid.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_HASH):
            svc.pin_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                version_hash="abc123",  # Too short
                ttl_hours=1,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_non_hex_version_hash_rejected(self, svc, ledger, db):
        """
        NEGATIVE: version_hash with non-hex characters must be rejected.
        """
        bad_hash = "g" * 64  # 'g' is not valid hex
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_HASH):
            svc.pin_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                version_hash=bad_hash,
                ttl_hours=1,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_ttl_exceeds_max_rejected(self, svc, ledger, db):
        """
        NEGATIVE: TTL exceeding POLICY_PIN_MAX_TTL_HOURS is rejected.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_TTL):
            svc.pin_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                version_hash=_VALID_HASH_A,
                ttl_hours=POLICY_PIN_MAX_TTL_HOURS + 1,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_ttl_zero_rejected(self, svc, ledger, db):
        """
        NEGATIVE: TTL of 0 hours must be rejected.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_TTL):
            svc.pin_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                version_hash=_VALID_HASH_A,
                ttl_hours=0,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_rollout_pct_exceeds_100_rejected(self, svc, ledger, db):
        """
        NEGATIVE: rollout_pct > 100 must be rejected.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_ROLLOUT_PCT):
            svc.stage_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                version_hash=_VALID_HASH_A,
                rollout_pct=101,
                ttl_hours=1,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_rollout_pct_negative_rejected(self, svc, ledger, db):
        """
        NEGATIVE: rollout_pct < 0 must be rejected.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_ROLLOUT_PCT):
            svc.stage_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                version_hash=_VALID_HASH_A,
                rollout_pct=-1,
                ttl_hours=1,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_rollback_without_previous_pin_raises(self, svc, ledger, db):
        """
        NEGATIVE: Rollback when no pin exists must raise ERR_POLICY_NOT_FOUND.
        Cannot roll back when nothing is pinned.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_NOT_FOUND):
            svc.rollback(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_rollback_without_rollback_target_raises(self, svc, ledger, db):
        """
        NEGATIVE: Rollback when first pin has no previous version raises
        ERR_POLICY_NO_ROLLBACK_TARGET. A single pin has no prior to return to.
        """
        svc.pin_version(
            db_session=db,
            ledger=ledger,
            tenant_id="tenant-alpha",
            policy_id="opa-core",
            version_hash=_VALID_HASH_A,
            ttl_hours=1,
            actor_id="admin-001",
            trace_id="t1",
        )
        with pytest.raises(ValueError, match=ERR_POLICY_NO_ROLLBACK_TARGET):
            svc.rollback(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                actor_id="admin-001",
                trace_id="t2",
            )

    def test_invariant_empty_policy_id_rejected(self, svc, ledger, db):
        """
        NEGATIVE: Empty policy_id must be rejected.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_POLICY_ID):
            svc.pin_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="",
                version_hash=_VALID_HASH_A,
                ttl_hours=1,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_invalid_policy_id_chars_rejected(self, svc, ledger, db):
        """
        NEGATIVE: policy_id with shell-dangerous characters must be rejected.
        """
        with pytest.raises(ValueError, match=ERR_POLICY_INVALID_POLICY_ID):
            svc.pin_version(
                db_session=db,
                ledger=ledger,
                tenant_id="tenant-alpha",
                policy_id="../../etc/passwd",  # Path traversal attempt
                version_hash=_VALID_HASH_A,
                ttl_hours=1,
                actor_id="admin-001",
                trace_id="t1",
            )

    def test_invariant_no_subprocess_in_policy_lifecycle(self):
        """
        NEGATIVE: cp_policy_lifecycle.py must not use subprocess.
        Shell execution is forbidden in the policy lifecycle service.
        """
        import pathlib

        src = pathlib.Path(
            "/home/user/fg-core/services/cp_policy_lifecycle.py"
        ).read_text()
        assert "import subprocess" not in src
        assert "subprocess.run" not in src
        assert "subprocess.Popen" not in src
        assert "os.system" not in src
        assert "os.popen" not in src

    def test_invariant_ledger_written_for_pin(self, svc, ledger, db):
        """
        NEGATIVE: Ledger must be called on every pin operation.
        If ledger raises, pin must NOT silently succeed.
        """

        class FailLedger:
            def append_event(self, **kwargs):
                raise RuntimeError("ledger unavailable")

        with pytest.raises(RuntimeError, match="Ledger write failed"):
            svc.pin_version(
                db_session=db,
                ledger=FailLedger(),
                tenant_id="tenant-alpha",
                policy_id="opa-core",
                version_hash=_VALID_HASH_A,
                ttl_hours=1,
                actor_id="admin-001",
                trace_id="t1",
            )
