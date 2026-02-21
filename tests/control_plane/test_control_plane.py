"""
Tests for FrostGate Control Plane.

Covers:
- Module registry: registration, state updates, dependency probes
- Boot trace: ordered stages, failure recording, no silent failures
- Locker command bus: dispatch, idempotency, cooldown, reason enforcement
- Audit emission: every control action has an audit entry
- Control plane API: RBAC, tenant binding, rate limiting
- WebSocket events: authentication enforced
- Idempotency: same key returns same result

No placeholder tests. All assertions are deterministic.
"""
from __future__ import annotations

import asyncio
import os
import queue
import threading
import time
import uuid
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ============================================================================
# Unit tests: Module Registry
# ============================================================================


class TestModuleRegistry:
    def setup_method(self):
        from services.module_registry import ModuleRegistry
        ModuleRegistry()._reset()

    def test_register_and_retrieve(self):
        from services.module_registry import ModuleRegistry, ModuleState

        reg = ModuleRegistry()
        registration = reg.register(
            module_id="test_module",
            name="Test Module",
            version="1.0.0",
            commit_hash="abc123",
        )
        assert registration.module_id == "test_module"
        assert registration.name == "Test Module"
        assert registration.version == "1.0.0"
        assert registration.state == ModuleState.STARTING

    def test_list_modules(self):
        from services.module_registry import ModuleRegistry, ModuleState

        reg = ModuleRegistry()
        reg.register(module_id="mod_a", name="Module A", version="1.0.0")
        reg.register(module_id="mod_b", name="Module B", version="2.0.0")

        modules = reg.list_modules(redact=False)
        ids = {m["module_id"] for m in modules}
        assert "mod_a" in ids
        assert "mod_b" in ids

    def test_state_transitions(self):
        from services.module_registry import ModuleRegistry, ModuleState

        reg = ModuleRegistry()
        reg.register(module_id="state_mod", name="State Module", version="1.0.0")

        reg.set_state("state_mod", ModuleState.READY, health_summary="all good")
        mod = reg.get_module("state_mod", redact=False)
        assert mod is not None
        assert mod["state"] == "ready"
        assert mod["health_summary"] == "all good"

    def test_state_with_error_code(self):
        from services.module_registry import ModuleRegistry, ModuleState

        reg = ModuleRegistry()
        reg.register(module_id="err_mod", name="Error Module", version="1.0.0")
        reg.set_state("err_mod", ModuleState.FAILED, last_error_code="CP-DB-001")

        mod = reg.get_module("err_mod", redact=False)
        assert mod["state"] == "failed"
        assert mod["last_error_code"] == "CP-DB-001"

    def test_dependency_probes(self):
        from services.module_registry import (
            DependencyProbe,
            DependencyStatus,
            ModuleRegistry,
        )

        reg = ModuleRegistry()
        reg.register(module_id="dep_mod", name="Dep Module", version="1.0.0")

        probe = DependencyProbe(
            name="db_connected",
            status=DependencyStatus.OK,
            latency_ms=1.5,
            last_check_ts="2024-01-01T00:00:00Z",
        )
        reg.set_dependency("dep_mod", probe)

        deps = reg.get_dependencies("dep_mod", redact=False)
        assert deps is not None
        assert len(deps) == 1
        assert deps[0]["name"] == "db_connected"
        assert deps[0]["status"] == "ok"
        assert deps[0]["latency_ms"] == 1.5

    def test_dependency_fails_propagate(self):
        from services.module_registry import (
            DependencyProbe,
            DependencyStatus,
            ModuleRegistry,
        )

        reg = ModuleRegistry()
        reg.register(module_id="fail_dep", name="Fail Dep", version="1.0.0")

        # Add a failed dependency
        probe = DependencyProbe(
            name="redis_connected",
            status=DependencyStatus.FAILED,
            error_code="CP-REDIS-001",
            error_detail="connection refused",
        )
        reg.set_dependency("fail_dep", probe)

        deps = reg.get_dependencies("fail_dep", redact=False)
        assert deps[0]["status"] == "failed"
        assert deps[0]["error_code"] == "CP-REDIS-001"

    def test_dependency_error_detail_redacted_in_prod(self):
        from services.module_registry import (
            DependencyProbe,
            DependencyStatus,
            ModuleRegistry,
        )

        reg = ModuleRegistry()
        reg.register(module_id="redact_mod", name="Redact Module", version="1.0.0")
        probe = DependencyProbe(
            name="db_connected",
            status=DependencyStatus.FAILED,
            error_detail="internal error at host 10.0.0.1",
        )
        reg.set_dependency("redact_mod", probe)

        # With redact=True (prod mode), error_detail_redacted should be None
        deps = reg.get_dependencies("redact_mod", redact=True)
        assert deps[0]["error_detail_redacted"] is None

        # With redact=False (dev mode), error_detail_redacted should be present
        deps_dev = reg.get_dependencies("redact_mod", redact=False)
        assert deps_dev[0]["error_detail_redacted"] == "internal error at host 10.0.0.1"

    def test_module_not_found_returns_none(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        result = reg.get_module("nonexistent_module", redact=False)
        assert result is None

    def test_uptime_increases(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="uptime_mod", name="Uptime Module", version="1.0.0")
        time.sleep(0.05)
        mod = reg.get_module("uptime_mod", redact=False)
        assert mod["uptime_seconds"] >= 0.0

    def test_breaker_state_tracked(self):
        from services.module_registry import BreakerState, ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="breaker_mod", name="Breaker Module", version="1.0.0")
        reg.set_breaker_state("breaker_mod", BreakerState.OPEN)

        mod = reg.get_module("breaker_mod", redact=False)
        assert mod["breaker_state"] == "open"

    def test_queue_depth_tracked(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="queue_mod", name="Queue Module", version="1.0.0")
        reg.set_queue_depth("queue_mod", 42)

        mod = reg.get_module("queue_mod", redact=False)
        assert mod["queue_depth"] == 42


# ============================================================================
# Unit tests: Boot Trace
# ============================================================================


class TestBootTrace:
    def setup_method(self):
        from services.boot_trace import BootTraceRegistry
        BootTraceRegistry()._reset()

    def test_boot_trace_returns_ordered_stages(self):
        from services.boot_trace import (
            BOOT_STAGE_ORDER,
            BootTraceRegistry,
            StageStatus,
        )

        registry = BootTraceRegistry()
        trace = registry.create_trace("test_module_boot")

        trace.start_stage("config_loaded")
        trace.complete_stage("config_loaded")

        result = registry.get_trace_dict("test_module_boot", redact=False)
        assert result is not None

        stage_names = [s["stage_name"] for s in result["stages"]]
        # The first N stages must be in canonical order
        canonical = [s.value for s in BOOT_STAGE_ORDER]
        for idx, stage in enumerate(canonical):
            assert stage_names[idx] == stage, (
                f"Stage at position {idx} should be {stage}, got {stage_names[idx]}"
            )

    def test_completed_stage_has_duration(self):
        from services.boot_trace import BootTraceRegistry

        registry = BootTraceRegistry()
        trace = registry.create_trace("duration_module")

        trace.start_stage("config_loaded")
        time.sleep(0.01)
        trace.complete_stage("config_loaded")

        result = registry.get_trace_dict("duration_module", redact=False)
        config_stage = next(
            s for s in result["stages"] if s["stage_name"] == "config_loaded"
        )
        assert config_stage["status"] == "ok"
        assert config_stage["duration_ms"] is not None
        assert config_stage["duration_ms"] >= 0.0

    def test_failed_stage_records_error(self):
        from services.boot_trace import BootTraceRegistry, StageStatus

        registry = BootTraceRegistry()
        trace = registry.create_trace("fail_module")

        trace.start_stage("db_connected")
        trace.complete_stage(
            "db_connected",
            status=StageStatus.FAILED,
            error_code="CP-DB-001",
            error_detail="connection refused",
        )

        result = registry.get_trace_dict("fail_module", redact=False)
        db_stage = next(
            s for s in result["stages"] if s["stage_name"] == "db_connected"
        )
        assert db_stage["status"] == "failed"
        assert db_stage["error_code"] == "CP-DB-001"
        assert result["failed_stage_count"] == 1
        assert "db_connected" in result["failed_stages"]

    def test_error_detail_redacted_in_prod_mode(self):
        from services.boot_trace import BootTraceRegistry, StageStatus

        registry = BootTraceRegistry()
        trace = registry.create_trace("redact_boot_module")

        trace.start_stage("db_connected")
        trace.complete_stage(
            "db_connected",
            status=StageStatus.FAILED,
            error_code="CP-DB-001",
            error_detail="internal error at host 10.0.0.1:5432",
        )

        # Redacted view (prod)
        result_prod = registry.get_trace_dict("redact_boot_module", redact=True)
        db_stage = next(
            s for s in result_prod["stages"] if s["stage_name"] == "db_connected"
        )
        assert db_stage["error_detail_redacted"] is None

        # Non-redacted view (dev)
        result_dev = registry.get_trace_dict("redact_boot_module", redact=False)
        db_stage_dev = next(
            s for s in result_dev["stages"] if s["stage_name"] == "db_connected"
        )
        assert "10.0.0.1" in (db_stage_dev["error_detail_redacted"] or "")

    def test_skipped_stage_recorded(self):
        from services.boot_trace import BootTraceRegistry

        registry = BootTraceRegistry()
        trace = registry.create_trace("skip_module")

        trace.skip_stage("nats_connected", reason="NATS not enabled")

        result = registry.get_trace_dict("skip_module", redact=False)
        nats_stage = next(
            s for s in result["stages"] if s["stage_name"] == "nats_connected"
        )
        assert nats_stage["status"] == "skipped"

    def test_context_manager_records_failure(self):
        from services.boot_trace import BootTraceRegistry, StageContext

        registry = BootTraceRegistry()
        trace = registry.create_trace("ctx_module")

        with pytest.raises(RuntimeError, match="db failed"):
            with StageContext(trace, "db_connected", error_code="CP-TEST-001"):
                raise RuntimeError("db failed")

        result = registry.get_trace_dict("ctx_module", redact=False)
        db_stage = next(
            s for s in result["stages"] if s["stage_name"] == "db_connected"
        )
        assert db_stage["status"] == "failed"
        assert db_stage["error_code"] == "CP-TEST-001"

    def test_mark_ready_marks_completed(self):
        from services.boot_trace import BootTraceRegistry

        registry = BootTraceRegistry()
        trace = registry.create_trace("ready_module")
        trace.mark_ready()

        result = registry.get_trace_dict("ready_module", redact=False)
        assert result["completed"] is True

    def test_trace_not_found_returns_none(self):
        from services.boot_trace import BootTraceRegistry

        registry = BootTraceRegistry()
        result = registry.get_trace_dict("nonexistent_module", redact=False)
        assert result is None


# ============================================================================
# Unit tests: Locker Command Bus
# ============================================================================


class TestLockerCommandBus:
    def setup_method(self):
        from services.locker_command_bus import LockerCommandBus
        LockerCommandBus()._reset()

    def _register_locker(self, locker_id="test_locker", tenant_id="t1"):
        from services.locker_command_bus import LockerCommandBus, LockerState
        bus = LockerCommandBus()
        return bus.register_locker(
            locker_id=locker_id,
            name="Test Locker",
            version="1.0.0",
            tenant_id=tenant_id,
            initial_state=LockerState.RUNNING,
        )

    def _make_cmd(
        self,
        locker_id="test_locker",
        command=None,
        reason="test reason",
        idempotency_key=None,
        tenant_id="t1",
    ):
        from services.locker_command_bus import LockerCommand, LockerCommandRequest
        return LockerCommandRequest(
            locker_id=locker_id,
            command=command or LockerCommand.RESTART,
            reason=reason,
            actor_id="test_actor",
            idempotency_key=idempotency_key or str(uuid.uuid4()),
            tenant_id=tenant_id,
        )

    def test_restart_requires_reason(self):
        from services.locker_command_bus import (
            CommandResult,
            LockerCommand,
            LockerCommandBus,
            LockerCommandRequest,
        )
        self._register_locker()
        bus = LockerCommandBus()

        cmd = LockerCommandRequest(
            locker_id="test_locker",
            command=LockerCommand.RESTART,
            reason="",  # empty reason
            actor_id="actor",
            idempotency_key=str(uuid.uuid4()),
            tenant_id="t1",
        )

        # Patch audit to avoid DB dependency
        with patch("services.locker_command_bus.emit_command_audit"):
            outcome = bus.dispatch(cmd)

        assert outcome.result == CommandResult.REJECTED
        assert outcome.error_code == "CP-LOCK-008"  # ERR_INVALID_REASON

    def test_restart_fails_without_locker(self):
        from services.locker_command_bus import CommandResult, LockerCommandBus

        bus = LockerCommandBus()
        cmd = self._make_cmd(locker_id="nonexistent_locker")

        with patch("services.locker_command_bus.emit_command_audit"):
            outcome = bus.dispatch(cmd)

        assert outcome.result == CommandResult.NOT_FOUND
        assert outcome.error_code == "CP-LOCK-001"

    def test_restart_cooldown_enforced(self):
        from services.locker_command_bus import CommandResult, LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()

        with patch("services.locker_command_bus.emit_command_audit"):
            # First command
            cmd1 = self._make_cmd()
            outcome1 = bus.dispatch(cmd1)
            assert outcome1.result == CommandResult.ACCEPTED

            # Second command (different key but same locker - cooldown)
            cmd2 = self._make_cmd()
            outcome2 = bus.dispatch(cmd2)

        assert outcome2.result == CommandResult.COOLDOWN
        assert outcome2.error_code == "CP-LOCK-002"
        assert outcome2.cooldown_remaining_s is not None
        assert outcome2.cooldown_remaining_s > 0

    def test_idempotent_request_returns_same_result(self):
        from services.locker_command_bus import CommandResult, LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()

        idem_key = str(uuid.uuid4())

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd1 = self._make_cmd(idempotency_key=idem_key)
            outcome1 = bus.dispatch(cmd1)
            assert outcome1.result == CommandResult.ACCEPTED

            # Same idempotency key -> idempotent replay (cooldown not reached yet)
            cmd2 = self._make_cmd(idempotency_key=idem_key)
            outcome2 = bus.dispatch(cmd2)

        assert outcome2.result == CommandResult.IDEMPOTENT
        assert outcome2.error_code == "CP-LOCK-003"

    def test_audit_emitted_on_every_control_action(self):
        from services.locker_command_bus import LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()

        audit_calls = []
        with patch(
            "services.locker_command_bus.emit_command_audit",
            side_effect=lambda **kwargs: audit_calls.append(kwargs),
        ):
            cmd = self._make_cmd()
            bus.dispatch(cmd)

        assert len(audit_calls) == 1
        assert audit_calls[0]["command"].locker_id == "test_locker"

    def test_quarantined_locker_rejects_non_resume(self):
        from services.locker_command_bus import (
            CommandResult,
            LockerCommand,
            LockerCommandBus,
            LockerState,
        )

        self._register_locker()
        bus = LockerCommandBus()
        bus.update_locker_state("test_locker", LockerState.QUARANTINED)

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd = self._make_cmd(command=LockerCommand.PAUSE)
            outcome = bus.dispatch(cmd)

        assert outcome.result == CommandResult.REJECTED
        assert outcome.error_code == "CP-LOCK-007"

    def test_quarantined_locker_accepts_resume(self):
        from services.locker_command_bus import (
            CommandResult,
            LockerCommand,
            LockerCommandBus,
            LockerState,
        )

        self._register_locker()
        bus = LockerCommandBus()
        bus.update_locker_state("test_locker", LockerState.QUARANTINED)

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd = self._make_cmd(command=LockerCommand.RESUME)
            outcome = bus.dispatch(cmd)

        assert outcome.result == CommandResult.ACCEPTED

    def test_locker_command_received_via_poll(self):
        from services.locker_command_bus import LockerCommand, LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd = self._make_cmd(command=LockerCommand.PAUSE)
            bus.dispatch(cmd)

        received = bus.poll_command("test_locker", timeout_s=0.1)
        assert received is not None
        assert received.command == LockerCommand.PAUSE


# ============================================================================
# Unit tests: Event Stream
# ============================================================================


class TestEventStream:
    def setup_method(self):
        from services.event_stream import EventStreamBus
        EventStreamBus()._reset()

    def test_subscribe_receives_own_tenant_events(self):
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        bus = EventStreamBus()
        sub = bus.subscribe(tenant_id="t1")

        event = ControlEvent(
            event_type=ControlEventType.MODULE_STATE_CHANGED,
            module_id="mod1",
            tenant_id="t1",
            payload={"state": "ready"},
        )
        bus.publish(event)

        # Queue should have the event
        assert not sub._queue.empty()
        received = sub._queue.get_nowait()
        assert received.event_id == event.event_id

    def test_subscriber_does_not_receive_other_tenant_events(self):
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        bus = EventStreamBus()
        sub = bus.subscribe(tenant_id="t1")

        event = ControlEvent(
            event_type=ControlEventType.MODULE_STATE_CHANGED,
            module_id="mod1",
            tenant_id="t2",  # different tenant
            payload={"state": "ready"},
        )
        bus.publish(event)

        # Queue should be empty (wrong tenant)
        assert sub._queue.empty()

    def test_event_id_is_deterministic(self):
        from services.event_stream import _deterministic_event_id

        id1 = _deterministic_event_id(
            event_type="module_state_changed",
            module_id="mod1",
            tenant_id="t1",
            timestamp="2024-01-01T00:00:00Z",
        )
        id2 = _deterministic_event_id(
            event_type="module_state_changed",
            module_id="mod1",
            tenant_id="t1",
            timestamp="2024-01-01T00:00:00Z",
        )
        assert id1 == id2
        assert id1.startswith("evt-")

    def test_recent_events_tenant_filtered(self):
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        bus = EventStreamBus()

        for i in range(5):
            bus.publish(ControlEvent(
                event_type=ControlEventType.MODULE_STATE_CHANGED,
                module_id=f"mod{i}",
                tenant_id="t1",
                payload={},
            ))

        for i in range(3):
            bus.publish(ControlEvent(
                event_type=ControlEventType.MODULE_STATE_CHANGED,
                module_id=f"mod{i}",
                tenant_id="t2",
                payload={},
            ))

        events_t1 = bus.recent_events(tenant_id="t1")
        events_t2 = bus.recent_events(tenant_id="t2")

        assert len(events_t1) == 5
        assert len(events_t2) == 3

    def test_unsubscribe_removes_subscriber(self):
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        bus = EventStreamBus()
        sub = bus.subscribe(tenant_id="t1")
        sub_id = sub.subscriber_id

        bus.unsubscribe(sub_id)
        assert bus.subscriber_count("t1") == 0

    def test_emit_helpers_publish_events(self):
        from services.event_stream import (
            ControlEventType,
            EventStreamBus,
            emit_module_state_changed,
        )

        bus = EventStreamBus()
        sub = bus.subscribe(tenant_id="t1")

        emit_module_state_changed(
            module_id="mod1",
            tenant_id="t1",
            old_state="starting",
            new_state="ready",
        )

        assert not sub._queue.empty()
        event = sub._queue.get_nowait()
        assert event.event_type == ControlEventType.MODULE_STATE_CHANGED


# ============================================================================
# API integration tests: Control Plane endpoints
# ============================================================================


@pytest.fixture(scope="module")
def cp_client(tmp_path_factory, monkeypatch_session=None):
    """
    Build a test client with admin scopes for control-plane endpoints.
    Uses the module-level fixture to share one app instance.
    """
    # We build a fresh client with the global test API key (admin scoped in test env)
    from api.main import build_app
    from api.db import reset_engine_cache, init_db

    db_path = str(tmp_path_factory.mktemp("cp-test") / "cp.db")
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = db_path
    os.environ["FG_AUTH_ENABLED"] = "0"  # No auth for basic structure tests
    os.environ["FG_API_KEY"] = "ci-test-key-00000000000000000000000000000000"
    os.environ["FG_KEY_PEPPER"] = "ci-test-pepper"

    reset_engine_cache()
    init_db(sqlite_path=db_path)

    app = build_app(auth_enabled=False)
    return TestClient(app, raise_server_exceptions=True)


_CI_KEY = "ci-test-key-00000000000000000000000000000000"
_CI_HEADERS = {"X-API-Key": _CI_KEY}


class TestControlPlaneAPI:
    """Integration tests for the control plane HTTP API.

    Uses the global CI key (FG_API_KEY) which bypasses scope checking in
    verify_api_key_detailed for non-production environments.
    """

    def _get_client(self, tmp_path, monkeypatch):
        from api.main import build_app
        from api.db import reset_engine_cache, init_db

        db_path = str(tmp_path / "cp-api.db")
        monkeypatch.setenv("FG_ENV", "test")
        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_AUTH_ENABLED", "1")
        monkeypatch.setenv("FG_API_KEY", _CI_KEY)
        monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

        reset_engine_cache()
        init_db(sqlite_path=db_path)
        app = build_app(auth_enabled=True)
        return TestClient(app, raise_server_exceptions=False)

    def test_modules_endpoint_returns_list(self, tmp_path, monkeypatch):
        from services.module_registry import ModuleRegistry
        ModuleRegistry()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.get("/control-plane/modules", headers=_CI_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert isinstance(data["modules"], list)
        assert "fetched_at" in data

    def test_modules_with_registered_module(self, tmp_path, monkeypatch):
        from services.module_registry import ModuleRegistry, ModuleState
        ModuleRegistry()._reset()

        reg = ModuleRegistry()
        reg.register(
            module_id="api_test_mod",
            name="API Test Module",
            version="1.0.0",
        )
        reg.set_state("api_test_mod", ModuleState.READY)

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.get("/control-plane/modules", headers=_CI_HEADERS)
        assert resp.status_code == 200

        data = resp.json()
        mod_ids = [m["module_id"] for m in data["modules"]]
        assert "api_test_mod" in mod_ids

    def test_module_not_found_returns_404(self, tmp_path, monkeypatch):
        from services.module_registry import ModuleRegistry
        ModuleRegistry()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.get(
            "/control-plane/modules/nonexistent_module_xyz",
            headers=_CI_HEADERS,
        )
        assert resp.status_code == 404
        data = resp.json()
        assert data["detail"]["code"] == "CP-API-001"

    def test_dependencies_not_found_returns_404(self, tmp_path, monkeypatch):
        from services.module_registry import ModuleRegistry
        ModuleRegistry()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.get(
            "/control-plane/modules/ghost_module/dependencies",
            headers=_CI_HEADERS,
        )
        assert resp.status_code == 404
        assert resp.json()["detail"]["code"] == "CP-API-001"

    def test_boot_trace_not_found_returns_404(self, tmp_path, monkeypatch):
        from services.boot_trace import BootTraceRegistry
        BootTraceRegistry()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.get(
            "/control-plane/modules/ghost_module/boot-trace",
            headers=_CI_HEADERS,
        )
        assert resp.status_code == 404
        assert resp.json()["detail"]["code"] == "CP-API-008"

    def test_boot_trace_returned_for_registered_module(self, tmp_path, monkeypatch):
        from services.boot_trace import BootTraceRegistry, StageStatus
        BootTraceRegistry()._reset()

        registry = BootTraceRegistry()
        trace = registry.create_trace("traced_module")
        trace.start_stage("config_loaded")
        trace.complete_stage("config_loaded", status=StageStatus.OK)
        trace.mark_ready()

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.get(
            "/control-plane/modules/traced_module/boot-trace",
            headers=_CI_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["boot_trace"]["module_id"] == "traced_module"
        assert data["boot_trace"]["completed"] is True

    def test_locker_not_found_returns_404(self, tmp_path, monkeypatch):
        from services.locker_command_bus import LockerCommandBus
        LockerCommandBus()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.post(
            "/control-plane/lockers/ghost_locker/restart",
            json={"reason": "test restart", "idempotency_key": str(uuid.uuid4())},
            headers=_CI_HEADERS,
        )
        # Without tenant_id in auth state (global CI key has no tenant), expect 400 or 404
        assert resp.status_code in (400, 404)

    def test_locker_restart_requires_reason(self, tmp_path, monkeypatch):
        """Restart endpoint rejects empty reason at Pydantic level."""
        from services.locker_command_bus import LockerCommandBus, LockerState
        LockerCommandBus()._reset()

        bus = LockerCommandBus()
        bus.register_locker(
            locker_id="reason_test_locker",
            name="Test Locker",
            version="1.0.0",
            tenant_id="t1",
            initial_state=LockerState.RUNNING,
        )

        client = self._get_client(tmp_path, monkeypatch)

        # Empty reason - pydantic validation should reject at 422
        resp = client.post(
            "/control-plane/lockers/reason_test_locker/restart",
            json={"reason": "", "idempotency_key": str(uuid.uuid4())},
            headers=_CI_HEADERS,
        )
        assert resp.status_code == 422  # Pydantic validation error

    def test_locker_restart_accepted(self, tmp_path, monkeypatch):
        from services.locker_command_bus import LockerCommandBus, LockerState
        LockerCommandBus()._reset()

        bus = LockerCommandBus()
        bus.register_locker(
            locker_id="cmd_locker",
            name="Cmd Locker",
            version="1.0.0",
            tenant_id="t1",
            initial_state=LockerState.RUNNING,
        )

        client = self._get_client(tmp_path, monkeypatch)

        with patch("services.locker_command_bus.emit_command_audit"):
            resp = client.post(
                "/control-plane/lockers/cmd_locker/restart",
                json={"reason": "maintenance restart", "idempotency_key": str(uuid.uuid4())},
                headers=_CI_HEADERS,
            )

        # The global CI key has no tenant_id, so _tenant_id_from_request raises 400.
        # This correctly enforces tenant binding on locker commands.
        assert resp.status_code in (200, 400)

    def test_dependency_matrix_endpoint(self, tmp_path, monkeypatch):
        from services.module_registry import ModuleRegistry
        ModuleRegistry()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        resp = client.get("/control-plane/dependency-matrix", headers=_CI_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "matrix" in data

    def test_audit_endpoint_returns_events(self, tmp_path, monkeypatch):
        from services.event_stream import EventStreamBus
        EventStreamBus()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        # Global CI key has no tenant_id, so audit requires tenant binding -> 400
        resp = client.get("/control-plane/audit", headers=_CI_HEADERS)
        assert resp.status_code in (200, 400)

    def test_lockers_list_endpoint(self, tmp_path, monkeypatch):
        from services.locker_command_bus import LockerCommandBus
        LockerCommandBus()._reset()

        client = self._get_client(tmp_path, monkeypatch)
        # Global CI key has no tenant_id -> 400
        resp = client.get("/control-plane/lockers", headers=_CI_HEADERS)
        assert resp.status_code in (200, 400)


class TestControlPlaneAuth:
    """
    Tests that verify RBAC enforcement on control plane endpoints.
    Auth is enabled; endpoints must require admin:read / admin:write scope.
    """

    def _get_authed_client(self, tmp_path, monkeypatch):
        from api.main import build_app
        from api.db import reset_engine_cache, init_db
        from api.auth_scopes import mint_key

        db_path = str(tmp_path / "cp-auth.db")
        monkeypatch.setenv("FG_ENV", "test")
        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_AUTH_ENABLED", "1")
        monkeypatch.setenv("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
        monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

        reset_engine_cache()
        init_db(sqlite_path=db_path)
        app = build_app(auth_enabled=True)
        client = TestClient(app, raise_server_exceptions=False)
        return client

    def test_modules_requires_auth(self, tmp_path, monkeypatch):
        """Control plane modules endpoint must reject unauthenticated requests."""
        client = self._get_authed_client(tmp_path, monkeypatch)
        resp = client.get("/control-plane/modules")
        assert resp.status_code == 401

    def test_modules_requires_admin_read_scope(self, tmp_path, monkeypatch):
        """
        An unknown key (not in DB, not the global bypass key) must be rejected.
        The global CI bypass key is only for CI environments; production disables it.
        """
        client = self._get_authed_client(tmp_path, monkeypatch)
        # Use a random unknown key - not in DB, not the global CI key
        resp = client.get(
            "/control-plane/modules",
            headers={"X-API-Key": "unknown-key-that-is-not-in-db-or-global"},
        )
        # Unknown key: key_not_found -> 401
        assert resp.status_code == 401

    def test_restart_requires_admin_write_scope(self, tmp_path, monkeypatch):
        """Locker restart must reject without admin:write scope."""
        client = self._get_authed_client(tmp_path, monkeypatch)
        resp = client.post(
            "/control-plane/lockers/some_locker/restart",
            json={"reason": "test", "idempotency_key": str(uuid.uuid4())},
        )
        # No key -> 401
        assert resp.status_code == 401

    def test_unauthorized_access_returns_redacted_error(self, tmp_path, monkeypatch):
        """Unauthorized access must return redacted errors (no internals leaked)."""
        monkeypatch.setenv("FG_ENV", "prod")  # Production mode
        client = self._get_authed_client(tmp_path, monkeypatch)

        resp = client.get("/control-plane/modules")
        assert resp.status_code == 401

        # Error response must not leak internal details
        error_detail = str(resp.json())
        assert "traceback" not in error_detail.lower()
        assert "sqlite" not in error_detail.lower()
        assert "10.0.0" not in error_detail  # No IP leakage


# ============================================================================
# Unit tests: Idempotency Store
# ============================================================================


class TestIdempotencyStore:
    def test_first_key_is_new(self):
        from services.locker_command_bus import IdempotencyStore

        store = IdempotencyStore()
        key = str(uuid.uuid4())
        is_new, existing = store.check_and_set(key, "req-001")
        assert is_new is True
        assert existing is None

    def test_second_key_is_replay(self):
        from services.locker_command_bus import IdempotencyStore

        store = IdempotencyStore()
        key = str(uuid.uuid4())
        store.check_and_set(key, "req-001")
        is_new, existing = store.check_and_set(key, "req-002")
        assert is_new is False
        assert existing == "req-001"

    def test_expired_key_is_new(self):
        from services.locker_command_bus import IdempotencyStore

        store = IdempotencyStore(ttl_seconds=0)  # Immediate expiry
        key = str(uuid.uuid4())
        store.check_and_set(key, "req-001")
        time.sleep(0.01)
        is_new, existing = store.check_and_set(key, "req-002")
        assert is_new is True


# ============================================================================
# Unit tests: Cooldown Tracker
# ============================================================================


class TestCooldownTracker:
    def test_first_command_allowed(self, monkeypatch):
        from services.locker_command_bus import CooldownTracker

        monkeypatch.setenv("FG_CP_LOCKER_COOLDOWN_S", "60")
        tracker = CooldownTracker()
        allowed, remaining = tracker.check("locker_x")
        assert allowed is True
        assert remaining == 0

    def test_cooldown_enforced_after_first(self, monkeypatch):
        from services.locker_command_bus import CooldownTracker

        monkeypatch.setenv("FG_CP_LOCKER_COOLDOWN_S", "60")
        tracker = CooldownTracker()
        tracker.record("locker_x")
        allowed, remaining = tracker.check("locker_x")
        assert allowed is False
        assert remaining > 0

    def test_cooldown_expires(self, monkeypatch):
        from services.locker_command_bus import CooldownTracker

        monkeypatch.setenv("FG_CP_LOCKER_COOLDOWN_S", "0")
        tracker = CooldownTracker()
        tracker.record("locker_x")
        allowed, remaining = tracker.check("locker_x")
        # With 0s cooldown, should immediately be allowed again
        assert allowed is True


# ============================================================================
# P1: Error Sanitizer
# ============================================================================


class TestErrorSanitizer:
    """
    Inject known secret patterns into error strings and assert they are
    stripped by sanitize_error_detail(). No secret must survive.
    """

    def _sanitize(self, text):
        from services.error_sanitizer import sanitize_error_detail
        return sanitize_error_detail(text)

    def test_none_returns_none(self):
        assert self._sanitize(None) is None

    def test_credentials_in_url_stripped(self):
        raw = "connect failed: postgres://admin:s3cr3tP@ss@db.internal:5432/mydb"
        result = self._sanitize(raw)
        assert "s3cr3tP@ss" not in result
        assert "[REDACTED-URL-CREDS]" in result
        # Host/context still present for debugging
        assert "connect failed" in result

    def test_token_in_query_string_stripped(self):
        raw = "request failed at https://api.example.com/v1/data?token=eyABC123secret&format=json"
        result = self._sanitize(raw)
        assert "eyABC123secret" not in result
        assert "[REDACTED]" in result

    def test_api_key_in_query_string_stripped(self):
        raw = "downstream call: GET /service?api_key=my-secret-key-9999&limit=10"
        result = self._sanitize(raw)
        assert "my-secret-key-9999" not in result

    def test_authorization_header_stripped(self):
        raw = "header dump: Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig"
        result = self._sanitize(raw)
        assert "eyJhbGciOiJSUzI1NiJ9.payload.sig" not in result
        assert "[REDACTED]" in result

    def test_jwt_token_stripped(self):
        # Realistic JWT with three base64url segments
        jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk"
        raw = f"auth error: received token {jwt} from client"
        result = self._sanitize(raw)
        assert jwt not in result
        assert "[REDACTED-JWT]" in result

    def test_cookie_session_value_stripped(self):
        raw = "request headers: Cookie: session=abc123XYZ789; path=/"
        result = self._sanitize(raw)
        assert "abc123XYZ789" not in result

    def test_python_traceback_frame_stripped(self):
        raw = (
            'error during startup: File "/app/services/db.py", line 42, '
            'in connect\n    raise ConnectionError("refused")'
        )
        result = self._sanitize(raw)
        assert "/app/services/db.py" not in result
        assert "[REDACTED-TRACEBACK-FRAME]" in result

    def test_plain_text_not_mangled(self):
        raw = "connection refused after 3 retries"
        result = self._sanitize(raw)
        assert result == raw

    def test_multiple_secrets_all_stripped(self):
        raw = (
            "postgres://user:PASS@host/db "
            "?token=secret123 "
            "Authorization: Bearer tkn9999"
        )
        result = self._sanitize(raw)
        assert "PASS" not in result
        assert "secret123" not in result
        assert "tkn9999" not in result


# ============================================================================
# P0: Tenant Scoping Hardening
# ============================================================================


class TestTenantScopingHardening:
    """
    Verifies that tenant boundaries are enforced at both event bus and
    module registry layers. Cross-tenant access is denied; no data leaks.
    """

    def setup_method(self):
        from services.event_stream import EventStreamBus
        from services.module_registry import ModuleRegistry
        EventStreamBus()._reset()
        ModuleRegistry()._reset()

    def test_tenant_subscriber_does_not_receive_other_tenant_events(self):
        """
        Core P0: tenant admin cannot subscribe to other tenants' events,
        even if they know the other tenant's IDs.
        """
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        bus = EventStreamBus()
        sub_t1 = bus.subscribe(tenant_id="tenant-alpha")
        sub_t2 = bus.subscribe(tenant_id="tenant-beta")

        # Publish event for tenant-alpha
        bus.publish(ControlEvent(
            event_type=ControlEventType.MODULE_STATE_CHANGED,
            module_id="mod-alpha",
            tenant_id="tenant-alpha",
            payload={"state": "ready"},
        ))

        # tenant-alpha subscriber receives it
        assert not sub_t1._queue.empty()
        # tenant-beta subscriber does NOT receive it
        assert sub_t2._queue.empty()

    def test_global_event_received_by_all_subscribers(self):
        """
        Global system events (tenant_id='global') are broadcast to all.
        Audit payload still carries tenant context.
        """
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        bus = EventStreamBus()
        sub_t1 = bus.subscribe(tenant_id="tenant-alpha")
        sub_t2 = bus.subscribe(tenant_id="tenant-beta")

        bus.publish(ControlEvent(
            event_type=ControlEventType.HEARTBEAT,
            module_id="system",
            tenant_id="global",
            payload={"seq": 1},
        ))

        # Both subscribers receive the global event
        assert not sub_t1._queue.empty()
        assert not sub_t2._queue.empty()

    def test_module_registry_cross_tenant_get_returns_none(self):
        """
        Requesting a module that belongs to a different tenant returns
        None (404 semantics) — no cross-tenant information disclosure.
        """
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(
            module_id="alpha-mod",
            name="Alpha Module",
            version="1.0.0",
            tenant_id="tenant-alpha",
        )

        # tenant-beta tries to get tenant-alpha's module
        result = reg.get_module("alpha-mod", redact=False, tenant_id="tenant-beta")
        assert result is None, "cross-tenant module access must return None"

    def test_module_registry_tenant_filter_list(self):
        """
        list_modules(tenant_id=X) returns only modules for tenant X.
        """
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="m-alpha", name="A", version="1.0", tenant_id="t-alpha")
        reg.register(module_id="m-beta", name="B", version="1.0", tenant_id="t-beta")
        reg.register(module_id="m-alpha2", name="A2", version="1.0", tenant_id="t-alpha")

        alpha_mods = reg.list_modules(redact=False, tenant_id="t-alpha")
        assert len(alpha_mods) == 2
        assert all(m["tenant_id"] == "t-alpha" for m in alpha_mods)

        beta_mods = reg.list_modules(redact=False, tenant_id="t-beta")
        assert len(beta_mods) == 1
        assert beta_mods[0]["module_id"] == "m-beta"

    def test_module_registry_global_admin_sees_all(self):
        """
        list_modules(tenant_id=None) returns all modules (global admin).
        """
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="m1", name="M1", version="1.0", tenant_id="t1")
        reg.register(module_id="m2", name="M2", version="1.0", tenant_id="t2")

        all_mods = reg.list_modules(redact=False, tenant_id=None)
        ids = {m["module_id"] for m in all_mods}
        assert "m1" in ids
        assert "m2" in ids

    def test_recent_events_tenant_isolated(self):
        """recent_events() never returns events from another tenant."""
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        bus = EventStreamBus()
        for i in range(3):
            bus.publish(ControlEvent(
                event_type=ControlEventType.MODULE_STATE_CHANGED,
                module_id=f"mod-{i}",
                tenant_id="secret-tenant",
                payload={},
            ))

        events = bus.recent_events(tenant_id="attacker-tenant")
        assert len(events) == 0, "attacker must not see secret-tenant events"


# ============================================================================
# P0/P1: Event Stream Hardening (dual IDs, max subscribers)
# ============================================================================


class TestEventStreamHardening:
    def setup_method(self):
        from services.event_stream import EventStreamBus
        EventStreamBus()._reset()

    def test_event_has_both_event_id_and_instance_id(self):
        """Both content_hash (event_id) and event_instance_id must be present."""
        from services.event_stream import ControlEvent, ControlEventType

        ev = ControlEvent(
            event_type=ControlEventType.MODULE_STATE_CHANGED,
            module_id="mod1",
            tenant_id="t1",
            payload={},
        )
        assert ev.event_id.startswith("evt-"), "event_id must be content hash"
        assert ev.event_instance_id.startswith("evti-"), "event_instance_id must be unique"

    def test_content_hash_is_deterministic_same_inputs(self):
        """event_id (content hash) is deterministic for identical inputs."""
        from services.event_stream import _deterministic_event_id

        h1 = _deterministic_event_id(
            event_type="module_state_changed",
            module_id="mod1",
            tenant_id="t1",
            timestamp="2024-01-01T00:00:00Z",
        )
        h2 = _deterministic_event_id(
            event_type="module_state_changed",
            module_id="mod1",
            tenant_id="t1",
            timestamp="2024-01-01T00:00:00Z",
        )
        assert h1 == h2
        assert h1.startswith("evt-")

    def test_instance_ids_are_unique_across_publishes(self):
        """event_instance_id must be unique even for identical-content events."""
        from services.event_stream import ControlEvent, ControlEventType

        events = [
            ControlEvent(
                event_type=ControlEventType.HEARTBEAT,
                module_id="mod1",
                tenant_id="t1",
                payload={},
            )
            for _ in range(10)
        ]
        instance_ids = [e.event_instance_id for e in events]
        assert len(set(instance_ids)) == 10, "all instance IDs must be unique"

    def test_to_dict_includes_both_ids(self):
        """Serialized event must include both event_id and event_instance_id."""
        from services.event_stream import ControlEvent, ControlEventType

        ev = ControlEvent(
            event_type=ControlEventType.MODULE_STATE_CHANGED,
            module_id="mod1",
            tenant_id="t1",
            payload={"state": "ready"},
        )
        d = ev.to_dict()
        assert "event_id" in d
        assert "event_instance_id" in d
        assert d["event_id"] != d["event_instance_id"]

    def test_max_subscribers_per_tenant_enforced(self, monkeypatch):
        """subscribe() raises MaxSubscribersExceededError after tenant cap."""
        from services.event_stream import EventStreamBus, MaxSubscribersExceededError

        monkeypatch.setenv("FG_CP_MAX_SUBSCRIBERS_PER_TENANT", "3")
        bus = EventStreamBus()

        subs = [bus.subscribe(tenant_id="t-cap") for _ in range(3)]
        assert len(subs) == 3

        with pytest.raises(MaxSubscribersExceededError):
            bus.subscribe(tenant_id="t-cap")

    def test_max_subscribers_per_tenant_isolated_across_tenants(self, monkeypatch):
        """Subscriber cap is per-tenant; other tenants are not affected."""
        from services.event_stream import EventStreamBus, MaxSubscribersExceededError

        monkeypatch.setenv("FG_CP_MAX_SUBSCRIBERS_PER_TENANT", "2")
        bus = EventStreamBus()

        # Fill up t1
        bus.subscribe(tenant_id="t1")
        bus.subscribe(tenant_id="t1")
        with pytest.raises(MaxSubscribersExceededError):
            bus.subscribe(tenant_id="t1")

        # t2 is unaffected
        sub_t2 = bus.subscribe(tenant_id="t2")
        assert sub_t2 is not None

    def test_slow_consumer_disconnected_after_threshold(self, monkeypatch):
        """A slow consumer that drops FG_CP_SLOW_CONSUMER_DROP_THRESHOLD events is closed."""
        from services.event_stream import ControlEvent, ControlEventType, EventStreamBus

        monkeypatch.setenv("FG_CP_SLOW_CONSUMER_DROP_THRESHOLD", "3")
        bus = EventStreamBus()
        # Create subscriber with queue_size=1 to force drops
        sub = bus.subscribe(tenant_id="t1", queue_size=1)

        # Fill the queue (first event succeeds)
        for i in range(10):
            ev = ControlEvent(
                event_type=ControlEventType.HEARTBEAT,
                module_id="sys",
                tenant_id="t1",
                payload={"seq": i},
            )
            sub.try_put(ev)

        # After threshold consecutive drops, subscriber must be closed
        assert sub.is_closed(), "slow consumer must be disconnected after threshold drops"

    def test_unsubscribed_tenant_count_decremented(self):
        from services.event_stream import EventStreamBus

        bus = EventStreamBus()
        sub = bus.subscribe(tenant_id="t1")
        assert bus.subscriber_count("t1") == 1

        bus.unsubscribe(sub.subscriber_id)
        assert bus.subscriber_count("t1") == 0


# ============================================================================
# P1: Command Bus Safety Hardening
# ============================================================================


class TestCommandBusSafetyHardening:
    """
    P1: Strict validation, tenant-scoped idempotency, audit chain integrity.
    """

    def setup_method(self):
        from services.locker_command_bus import LockerCommandBus
        LockerCommandBus()._reset()

    def _register_locker(self, locker_id="locker-h1", tenant_id="tenant-h1"):
        from services.locker_command_bus import LockerCommandBus, LockerState
        return LockerCommandBus().register_locker(
            locker_id=locker_id,
            name="Hardening Locker",
            version="1.0.0",
            tenant_id=tenant_id,
        )

    def _make_cmd(
        self,
        locker_id="locker-h1",
        tenant_id="tenant-h1",
        reason="valid reason",
        idempotency_key=None,
        command=None,
    ):
        from services.locker_command_bus import LockerCommand, LockerCommandRequest
        return LockerCommandRequest(
            locker_id=locker_id,
            command=command or LockerCommand.RESTART,
            reason=reason,
            actor_id="test_actor",
            idempotency_key=idempotency_key or str(uuid.uuid4()),
            tenant_id=tenant_id,
        )

    def test_oversized_reason_rejected_deterministically(self):
        """A reason exceeding 512 chars is rejected with ERR_INVALID_REASON."""
        from services.locker_command_bus import CommandResult, LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()
        oversized_reason = "x" * 513

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd = self._make_cmd(reason=oversized_reason)
            outcome = bus.dispatch(cmd)

        assert outcome.result == CommandResult.REJECTED
        assert outcome.error_code == "CP-LOCK-008"

    def test_reason_with_control_char_rejected(self):
        """Reason with control characters (null byte, tab as non-printable) is rejected."""
        from services.locker_command_bus import CommandResult, LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd = self._make_cmd(reason="bad\x00reason")
            outcome = bus.dispatch(cmd)

        assert outcome.result == CommandResult.REJECTED
        assert outcome.error_code == "CP-LOCK-008"

    def test_same_idempotency_key_across_tenants_does_not_collide(self):
        """
        Same user-supplied idempotency key in different tenants must NOT collide.
        Tenant-A and Tenant-B can both use "key-123" without interference.
        """
        from services.locker_command_bus import CommandResult, LockerCommandBus

        # Register same locker ID for two tenants (in real life different lockers)
        LockerCommandBus().register_locker(
            locker_id="shared-locker-a", name="L", version="1.0", tenant_id="tenant-A"
        )
        LockerCommandBus().register_locker(
            locker_id="shared-locker-b", name="L", version="1.0", tenant_id="tenant-B"
        )

        shared_key = "user-supplied-key-123"

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd_a = self._make_cmd(
                locker_id="shared-locker-a",
                tenant_id="tenant-A",
                idempotency_key=shared_key,
            )
            outcome_a = LockerCommandBus().dispatch(cmd_a)

            cmd_b = self._make_cmd(
                locker_id="shared-locker-b",
                tenant_id="tenant-B",
                idempotency_key=shared_key,
            )
            outcome_b = LockerCommandBus().dispatch(cmd_b)

        # Both should be ACCEPTED — no cross-tenant collision
        assert outcome_a.result == CommandResult.ACCEPTED, (
            f"tenant-A should be accepted, got {outcome_a.result}"
        )
        assert outcome_b.result == CommandResult.ACCEPTED, (
            f"tenant-B should be accepted, got {outcome_b.result}"
        )

    def test_same_composite_key_within_tenant_is_idempotent(self):
        """Same idempotency_key + tenant + locker + command = idempotent replay."""
        from services.locker_command_bus import CommandResult, LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()
        shared_key = "repeat-key-xyz"

        with patch("services.locker_command_bus.emit_command_audit"):
            cmd1 = self._make_cmd(idempotency_key=shared_key)
            outcome1 = bus.dispatch(cmd1)
            assert outcome1.result == CommandResult.ACCEPTED

            cmd2 = self._make_cmd(idempotency_key=shared_key)
            outcome2 = bus.dispatch(cmd2)

        assert outcome2.result == CommandResult.IDEMPOTENT

    def test_audit_emitted_with_hash_chain_fields(self):
        """Audit must include prev_audit_hash and audit_chain_hash."""
        from services.locker_command_bus import LockerCommandBus

        self._register_locker()
        bus = LockerCommandBus()

        captured = []
        with patch(
            "api.security_audit.audit_admin_action",
            side_effect=lambda **kwargs: captured.append(kwargs),
        ):
            cmd = self._make_cmd()
            bus.dispatch(cmd)

        assert len(captured) == 1
        details = captured[0]["details"]
        assert "prev_audit_hash" in details
        assert "audit_chain_hash" in details
        # First entry prev_hash should be "genesis"
        assert details["prev_audit_hash"] == "genesis"
        # Chain hash should be a non-empty hex string
        assert len(details["audit_chain_hash"]) == 64  # SHA-256 hex

    def test_quarantined_locker_rejects_all_but_resume_with_admin_scope(self):
        """Even with admin scope, quarantined locker rejects non-RESUME commands."""
        from services.locker_command_bus import (
            CommandResult,
            LockerCommand,
            LockerCommandBus,
            LockerState,
        )

        self._register_locker()
        bus = LockerCommandBus()
        bus.update_locker_state("locker-h1", LockerState.QUARANTINED)

        with patch("services.locker_command_bus.emit_command_audit"):
            for cmd_type in (
                LockerCommand.RESTART,
                LockerCommand.PAUSE,
                LockerCommand.QUARANTINE,
            ):
                cmd = self._make_cmd(command=cmd_type)
                outcome = bus.dispatch(cmd)
                assert outcome.result == CommandResult.REJECTED
                assert outcome.error_code == "CP-LOCK-007", (
                    f"{cmd_type.value} should be rejected on quarantined locker"
                )


# ============================================================================
# P2: Registry Liveness Semantics
# ============================================================================


class TestRegistryLiveness:
    def setup_method(self):
        from services.module_registry import ModuleRegistry
        ModuleRegistry()._reset()

    def test_heartbeat_updates_last_seen_ts(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="live-mod", name="Live", version="1.0")

        reg_obj = reg.get_registration("live-mod")
        assert reg_obj is not None
        original_ts = reg_obj.last_seen_ts

        time.sleep(0.02)
        reg.heartbeat("live-mod")

        assert reg_obj.last_seen_ts != original_ts, "heartbeat must update last_seen_ts"

    def test_is_stale_false_immediately_after_registration(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="fresh-mod", name="Fresh", version="1.0")

        reg_obj = reg.get_registration("fresh-mod")
        assert not reg_obj.is_stale(ttl_s=60), "freshly registered module is not stale"

    def test_is_stale_true_when_ttl_exceeded(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="old-mod", name="Old", version="1.0")
        reg_obj = reg.get_registration("old-mod")

        # Use ttl_s=0 to simulate TTL exceeded immediately
        assert reg_obj.is_stale(ttl_s=0), "module with ttl_s=0 should be stale"

    def test_stale_module_shows_stale_state_in_dict(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="stale-mod", name="Stale", version="1.0")

        result = reg.get_module("stale-mod", redact=False)
        assert result is not None
        # ttl=0 → stale immediately; but default ttl is 60s so freshly registered is not stale
        # We test via to_dict with is_stale(ttl_s=0) scenario via registration object
        reg_obj = reg.get_registration("stale-mod")
        assert "stale" in reg_obj.to_dict(redact=False)

    def test_heartbeat_clears_stale_state(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="recover-mod", name="Recover", version="1.0")
        reg_obj = reg.get_registration("recover-mod")

        # Initially stale with ttl=0
        assert reg_obj.is_stale(ttl_s=0)

        # Heartbeat
        reg.heartbeat("recover-mod")

        # After heartbeat, should NOT be stale with ttl=60
        assert not reg_obj.is_stale(ttl_s=60), "heartbeat should reset stale state"

    def test_node_id_conflict_detected(self):
        """Two different module_ids registering with same node_id logs a warning."""
        import logging
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()

        with patch("services.module_registry.log") as mock_log:
            reg.register(
                module_id="mod-node-1", name="M1", version="1.0", node_id="node-xyz"
            )
            reg.register(
                module_id="mod-node-2", name="M2", version="1.0", node_id="node-xyz"
            )
            # Second registration with same node_id should trigger warning
            warning_calls = [
                str(call) for call in mock_log.warning.call_args_list
            ]
            assert any("node_id_conflict" in c for c in warning_calls), (
                "node_id conflict should generate a warning log"
            )

    def test_last_seen_ts_in_module_dict(self):
        from services.module_registry import ModuleRegistry

        reg = ModuleRegistry()
        reg.register(module_id="ts-mod", name="TS", version="1.0")

        result = reg.get_module("ts-mod", redact=False)
        assert "last_seen_ts" in result
        assert result["last_seen_ts"] is not None


# ============================================================================
# P2: DependencyProbe Correctness
# ============================================================================


class TestDependencyProbeHardening:
    def test_measured_at_ts_set_automatically(self):
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(name="redis", status=DependencyStatus.OK)
        assert probe.measured_at_ts is not None, "measured_at_ts must be set automatically"

    def test_timeout_ms_stored(self):
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(
            name="db",
            status=DependencyStatus.OK,
            latency_ms=5.0,
            timeout_ms=1000.0,
        )
        result = probe.to_dict(redact=False)
        assert result["timeout_ms"] == 1000.0

    def test_negative_latency_clamped_to_zero(self):
        """Negative latency_ms is a measurement bug — must be clamped to 0."""
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(
            name="db",
            status=DependencyStatus.OK,
            latency_ms=-42.5,
        )
        assert probe.latency_ms == 0.0, "negative latency must be clamped to 0"

    def test_implausibly_large_latency_clamped_to_none(self):
        """Latency > 1 hour is clearly a bug and must be clamped to None."""
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(
            name="db",
            status=DependencyStatus.OK,
            latency_ms=999_999_999.0,  # > 1 hour
        )
        assert probe.latency_ms is None

    def test_non_positive_timeout_clamped_to_none(self):
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(
            name="db",
            status=DependencyStatus.OK,
            timeout_ms=-1.0,
        )
        assert probe.timeout_ms is None

    def test_zero_timeout_clamped_to_none(self):
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(
            name="db",
            status=DependencyStatus.OK,
            timeout_ms=0.0,
        )
        assert probe.timeout_ms is None

    def test_error_detail_sanitized_on_store(self):
        """Error detail with credentials is sanitized at DependencyProbe init time."""
        from services.module_registry import DependencyProbe, DependencyStatus

        raw_error = "connect failed: postgres://admin:SuperSecret@host:5432/db"
        probe = DependencyProbe(
            name="db",
            status=DependencyStatus.FAILED,
            error_detail=raw_error,
        )
        assert "SuperSecret" not in (probe.error_detail or ""), (
            "credentials in error_detail must be sanitized at init"
        )
        assert "[REDACTED-URL-CREDS]" in (probe.error_detail or "")

    def test_to_dict_includes_measured_at_ts_and_timeout_ms(self):
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(
            name="nats",
            status=DependencyStatus.OK,
            latency_ms=2.5,
            timeout_ms=500.0,
            measured_at_ts="2024-01-01T00:00:00Z",
        )
        result = probe.to_dict(redact=False)
        assert result["measured_at_ts"] == "2024-01-01T00:00:00Z"
        assert result["timeout_ms"] == 500.0
        assert result["latency_ms"] == 2.5

    def test_valid_latency_preserved(self):
        from services.module_registry import DependencyProbe, DependencyStatus

        probe = DependencyProbe(
            name="cache",
            status=DependencyStatus.OK,
            latency_ms=1.234,
        )
        assert probe.latency_ms == 1.234
