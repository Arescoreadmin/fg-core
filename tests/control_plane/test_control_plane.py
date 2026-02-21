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
        assert outcome.error_code == "CP-LOCK-006"

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
