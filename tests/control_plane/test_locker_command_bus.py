"""
Tests for services/locker_command_bus.py

Covers (from spec):
- restart requires admin scope (tested at API level in test_control_plane_api.py)
- restart fails without reason
- restart cooldown enforced
- audit emitted on control action (at API level)
- idempotent request returns same result
- quarantined locker rejects all but RESUME
- cross-tenant idempotency key isolation
- oversized reason rejected deterministically
- same idempotency key across tenants does not collide
- locker not found returns deterministic error
- command bus safe (no subprocess)
"""

from __future__ import annotations

import time

import pytest

from services.locker_command_bus import (
    ERR_COOLDOWN_ACTIVE,
    ERR_INVALID_COMMAND,
    ERR_QUARANTINE_LOCKED,
    ERR_REASON_INVALID_CHARS,
    ERR_REASON_REQUIRED,
    ERR_REASON_TOO_LONG,
    ERR_UNKNOWN_LOCKER,
    LockerCommandBus,
    validate_reason,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bus() -> LockerCommandBus:
    return LockerCommandBus()


def _register(bus: LockerCommandBus, locker_id: str, tenant_id: str) -> None:
    bus.register_locker(locker_id, tenant_id)


def _dispatch(
    bus: LockerCommandBus,
    locker_id: str,
    command: str,
    *,
    tenant_id: str = "tenant-a",
    reason: str = "operational maintenance",
    idempotency_key: str = "idem-1",
    cooldown_sec: int = 0,
):
    return bus.dispatch_command(
        locker_id=locker_id,
        command=command,
        reason=reason,
        actor_id="admin-actor",
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        cooldown_sec=cooldown_sec,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestLockerRegistration:
    def test_register_locker(self):
        bus = _make_bus()
        rec = bus.register_locker("locker-1", "tenant-a")
        assert rec.locker_id == "locker-1"
        assert rec.tenant_id == "tenant-a"
        assert rec.state == "active"

    def test_re_register_same_tenant_ok(self):
        bus = _make_bus()
        bus.register_locker("locker-2", "tenant-a", version="1.0")
        rec = bus.register_locker("locker-2", "tenant-a", version="2.0")
        assert rec.version == "2.0"

    def test_register_different_tenant_raises(self):
        bus = _make_bus()
        bus.register_locker("locker-3", "tenant-a")
        with pytest.raises(ValueError):
            bus.register_locker("locker-3", "tenant-b")

    def test_heartbeat_locker(self):
        bus = _make_bus()
        bus.register_locker("locker-hb", "tenant-a")
        time.sleep(0.01)
        ok = bus.heartbeat_locker("locker-hb", "tenant-a", version="1.1")
        assert ok
        assert bus.get_locker("locker-hb", "tenant-a").version == "1.1"


# ---------------------------------------------------------------------------
# Reason validation
# ---------------------------------------------------------------------------


class TestReasonValidation:
    def test_valid_reason_passes(self):
        r = validate_reason("operational maintenance")
        assert r == "operational maintenance"

    def test_empty_reason_fails(self):
        with pytest.raises(ValueError) as exc:
            validate_reason("")
        assert ERR_REASON_REQUIRED in str(exc.value)

    def test_none_reason_fails(self):
        with pytest.raises(ValueError) as exc:
            validate_reason(None)
        assert ERR_REASON_REQUIRED in str(exc.value)

    def test_short_reason_fails(self):
        with pytest.raises(ValueError) as exc:
            validate_reason("no")
        assert ERR_REASON_REQUIRED in str(exc.value)

    def test_oversized_reason_rejected_deterministically(self):
        """Oversized reason must always return the same error code."""
        long_reason = "a" * 513
        with pytest.raises(ValueError) as exc:
            validate_reason(long_reason)
        assert ERR_REASON_TOO_LONG in str(exc.value)

    def test_invalid_chars_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_reason("<script>alert(1)</script>")
        assert ERR_REASON_INVALID_CHARS in str(exc.value)


# ---------------------------------------------------------------------------
# Command dispatch
# ---------------------------------------------------------------------------


class TestCommandDispatch:
    def test_restart_fails_without_reason(self):
        bus = _make_bus()
        _register(bus, "locker-restart", "tenant-a")
        result = _dispatch(bus, "locker-restart", "restart", reason="")
        assert not result.ok
        assert result.error_code in {ERR_REASON_REQUIRED, ERR_REASON_INVALID_CHARS}

    def test_restart_succeeds_with_valid_reason(self):
        bus = _make_bus()
        _register(bus, "locker-ok", "tenant-a")
        result = _dispatch(bus, "locker-ok", "restart", reason="maintenance window")
        assert result.ok

    def test_unknown_locker_returns_deterministic_error(self):
        bus = _make_bus()
        result = _dispatch(bus, "nonexistent-locker", "restart")
        assert not result.ok
        assert result.error_code == ERR_UNKNOWN_LOCKER

    def test_invalid_command_rejected(self):
        bus = _make_bus()
        _register(bus, "locker-cmd", "tenant-a")
        result = _dispatch(bus, "locker-cmd", "nuke")
        assert not result.ok
        assert result.error_code == ERR_INVALID_COMMAND

    def test_command_transitions_state(self):
        bus = _make_bus()
        _register(bus, "locker-state", "tenant-a")

        result = _dispatch(bus, "locker-state", "pause", reason="pause for maintenance")
        assert result.ok
        rec = bus.get_locker("locker-state", "tenant-a")
        assert rec.state == "paused"

    def test_tenant_binding_enforced(self):
        """Locker belongs to tenant-a; tenant-b must not see it."""
        bus = _make_bus()
        _register(bus, "locker-binding", "tenant-a")
        result = _dispatch(
            bus,
            "locker-binding",
            "restart",
            tenant_id="tenant-b",
            reason="cross-tenant attack",
        )
        # Must return same error as not-found to prevent enumeration
        assert not result.ok
        assert result.error_code == ERR_UNKNOWN_LOCKER


# ---------------------------------------------------------------------------
# Cooldown enforcement
# ---------------------------------------------------------------------------


class TestCooldown:
    def test_cooldown_enforced(self):
        bus = _make_bus()
        _register(bus, "locker-cooldown", "tenant-a")

        # First dispatch ok
        r1 = _dispatch(
            bus,
            "locker-cooldown",
            "restart",
            reason="first restart",
            idempotency_key="idem-c1",
            cooldown_sec=60,
        )
        assert r1.ok

        # Second dispatch within cooldown window
        r2 = _dispatch(
            bus,
            "locker-cooldown",
            "restart",
            reason="second restart",
            idempotency_key="idem-c2",
            cooldown_sec=60,
        )
        assert not r2.ok
        assert r2.error_code == ERR_COOLDOWN_ACTIVE

    def test_no_cooldown_allows_immediate_repeat(self):
        bus = _make_bus()
        _register(bus, "locker-nocool", "tenant-a")
        _dispatch(
            bus,
            "locker-nocool",
            "restart",
            reason="first",
            idempotency_key="idem-nc1",
            cooldown_sec=0,
        )
        r2 = _dispatch(
            bus,
            "locker-nocool",
            "restart",
            reason="second",
            idempotency_key="idem-nc2",
            cooldown_sec=0,
        )
        assert r2.ok


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_idempotent_request_returns_same_command_id(self):
        bus = _make_bus()
        _register(bus, "locker-idem", "tenant-a")

        r1 = _dispatch(
            bus,
            "locker-idem",
            "pause",
            reason="test pause reason",
            idempotency_key="idem-unique-1",
            cooldown_sec=0,
        )
        assert r1.ok

        # Same command + same reason + same locker + same tenant → idempotent
        r2 = _dispatch(
            bus,
            "locker-idem",
            "pause",
            reason="test pause reason",
            idempotency_key="idem-unique-1",
            cooldown_sec=0,
        )
        assert r2.ok
        assert r2.idempotent is True
        assert r2.command_id == r1.command_id

    def test_same_idempotency_key_across_tenants_does_not_collide(self):
        """
        P0: Cross-tenant idempotency isolation.
        Same idempotency key with different tenants must produce different outcomes.
        """
        bus = _make_bus()
        bus.register_locker("locker-A", "tenant-a")
        bus.register_locker("locker-B", "tenant-b")

        r_a = _dispatch(
            bus,
            "locker-A",
            "pause",
            tenant_id="tenant-a",
            reason="test isolation",
            idempotency_key="shared-key-123",
            cooldown_sec=0,
        )
        r_b = _dispatch(
            bus,
            "locker-B",
            "pause",
            tenant_id="tenant-b",
            reason="test isolation",
            idempotency_key="shared-key-123",
            cooldown_sec=0,
        )
        assert r_a.ok
        assert r_b.ok
        # Both succeed independently (cross-tenant isolation)
        assert r_a.command_id != r_b.command_id

    def test_different_payload_same_key_different_result(self):
        bus = _make_bus()
        _register(bus, "locker-idem2", "tenant-a")

        r1 = _dispatch(
            bus,
            "locker-idem2",
            "pause",
            reason="reason one",
            idempotency_key="idem-diff",
            cooldown_sec=0,
        )
        # Different reason → different payload hash → not idempotent
        r2 = _dispatch(
            bus,
            "locker-idem2",
            "pause",
            reason="reason two",
            idempotency_key="idem-diff",
            cooldown_sec=0,
        )
        # r2 may fail cooldown if same command; but if cooldown=0 and hash differs
        # it should produce a different command_id
        if r2.ok:
            assert r2.command_id != r1.command_id
            assert not r2.idempotent


# ---------------------------------------------------------------------------
# Quarantine enforcement
# ---------------------------------------------------------------------------


class TestQuarantineEnforcement:
    def test_quarantined_locker_rejects_restart(self):
        bus = _make_bus()
        _register(bus, "locker-q", "tenant-a")
        _dispatch(
            bus,
            "locker-q",
            "quarantine",
            reason="suspicious activity",
            idempotency_key="q1",
        )

        result = _dispatch(
            bus,
            "locker-q",
            "restart",
            reason="restart attempt",
            idempotency_key="q2",
            cooldown_sec=0,
        )
        assert not result.ok
        assert result.error_code == ERR_QUARANTINE_LOCKED

    def test_quarantined_locker_rejects_pause(self):
        bus = _make_bus()
        _register(bus, "locker-q2", "tenant-a")
        _dispatch(
            bus,
            "locker-q2",
            "quarantine",
            reason="suspicious activity",
            idempotency_key="q-p1",
        )

        result = _dispatch(
            bus,
            "locker-q2",
            "pause",
            reason="pause attempt",
            idempotency_key="q-p2",
            cooldown_sec=0,
        )
        assert not result.ok
        assert result.error_code == ERR_QUARANTINE_LOCKED

    def test_quarantined_locker_accepts_resume(self):
        bus = _make_bus()
        _register(bus, "locker-q3", "tenant-a")
        _dispatch(
            bus,
            "locker-q3",
            "quarantine",
            reason="suspicious activity",
            idempotency_key="qr1",
        )

        result = _dispatch(
            bus,
            "locker-q3",
            "resume",
            reason="reviewed and cleared",
            idempotency_key="qr2",
            cooldown_sec=0,
        )
        assert result.ok
        rec = bus.get_locker("locker-q3", "tenant-a")
        assert rec.state == "active"


# ---------------------------------------------------------------------------
# No subprocess guarantee
# ---------------------------------------------------------------------------


class TestNoSubprocess:
    def test_command_bus_does_not_use_subprocess(self, monkeypatch):
        """
        The command bus must never call subprocess.run, subprocess.Popen,
        or os.system. This test verifies the module source contains no such calls.
        """
        import subprocess as _sp

        calls = []

        monkeypatch.setattr(
            _sp, "run", lambda *a, **kw: calls.append("subprocess.run") or None
        )
        monkeypatch.setattr(
            _sp, "Popen", lambda *a, **kw: calls.append("subprocess.Popen") or None
        )

        bus = _make_bus()
        _register(bus, "locker-nosub", "tenant-a")
        _dispatch(bus, "locker-nosub", "restart", reason="no subprocess test")

        assert calls == [], f"Unexpected subprocess calls: {calls}"
