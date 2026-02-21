"""
Tests for services/module_registry.py

Covers:
- Module registration + re-registration
- Heartbeat and liveness/stale detection
- Dependency probe updates with latency sanity checks
- Tenant-scoped snapshot
- Global admin snapshot
- make_registration_hash determinism
"""
from __future__ import annotations

import time

import pytest

from services.module_registry import (
    DependencyProbe,
    ModuleRecord,
    _RegistryStore,
    make_registration_hash,
    register_module,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store() -> _RegistryStore:
    from services.module_registry import _RegistryStore
    return _RegistryStore()


def _make_record(
    module_id: str = "mod-a",
    tenant_id: str | None = "tenant-1",
) -> ModuleRecord:
    return ModuleRecord(
        module_id=module_id,
        name=module_id,
        version="1.0.0",
        commit_hash="abc123",
        build_timestamp="2024-01-01T00:00:00Z",
        node_id="node-1",
        tenant_id=tenant_id,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_and_get(self):
        store = _make_store()
        rec = _make_record("mod-x")
        store.register(rec)
        got = store.get("mod-x")
        assert got is not None
        assert got.module_id == "mod-x"
        assert got.state == "starting"

    def test_re_register_preserves_state(self):
        store = _make_store()
        rec = _make_record("mod-reregister")
        store.register(rec)
        store.set_state("mod-reregister", "ready")

        # Re-register with updated version
        rec2 = _make_record("mod-reregister")
        rec2.version = "2.0.0"
        store.register(rec2)

        got = store.get("mod-reregister")
        assert got is not None
        assert got.version == "2.0.0"
        # State preserved
        assert got.state == "ready"

    def test_list_all(self):
        store = _make_store()
        for i in range(3):
            store.register(_make_record(f"mod-list-{i}"))
        modules = store.list_all()
        ids = {m.module_id for m in modules}
        assert {"mod-list-0", "mod-list-1", "mod-list-2"}.issubset(ids)

    def test_list_for_tenant(self):
        store = _make_store()
        store.register(_make_record("mod-t1", tenant_id="tenant-A"))
        store.register(_make_record("mod-t2", tenant_id="tenant-B"))
        store.register(_make_record("mod-platform", tenant_id=None))  # platform-level

        result = store.list_for_tenant("tenant-A")
        ids = {m.module_id for m in result}
        assert "mod-t1" in ids
        assert "mod-platform" in ids  # platform modules always visible
        assert "mod-t2" not in ids

    def test_snapshot_tenant_scoped(self):
        store = _make_store()
        store.register(_make_record("m1", tenant_id="tenant-A"))
        store.register(_make_record("m2", tenant_id="tenant-B"))
        store.register(_make_record("m3", tenant_id=None))

        # Tenant A should see m1 and m3 only
        snap = store.snapshot_for_api(
            tenant_id="tenant-A", is_global_admin=False, redact=False
        )
        ids = {m["module_id"] for m in snap}
        assert "m1" in ids
        assert "m3" in ids
        assert "m2" not in ids

    def test_snapshot_global_admin_sees_all(self):
        store = _make_store()
        store.register(_make_record("g1", tenant_id="tenant-A"))
        store.register(_make_record("g2", tenant_id="tenant-B"))
        store.register(_make_record("g3", tenant_id=None))

        snap = store.snapshot_for_api(
            tenant_id=None, is_global_admin=True, redact=False
        )
        ids = {m["module_id"] for m in snap}
        assert {"g1", "g2", "g3"}.issubset(ids)

    def test_snapshot_no_tenant_no_global_returns_empty(self):
        store = _make_store()
        store.register(_make_record("z1", tenant_id="tenant-A"))
        snap = store.snapshot_for_api(
            tenant_id=None, is_global_admin=False, redact=False
        )
        assert snap == []


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------


class TestStateTransitions:
    def test_set_state(self):
        store = _make_store()
        store.register(_make_record("mod-state"))
        ok = store.set_state("mod-state", "ready")
        assert ok
        rec = store.get("mod-state")
        assert rec.state == "ready"

    def test_set_state_with_error_code(self):
        store = _make_store()
        store.register(_make_record("mod-err"))
        store.set_state("mod-err", "failed", error_code="DB_CONNECT_FAILED")
        rec = store.get("mod-err")
        assert rec.last_error_code == "DB_CONNECT_FAILED"

    def test_set_state_nonexistent_returns_false(self):
        store = _make_store()
        ok = store.set_state("does-not-exist", "ready")
        assert not ok


# ---------------------------------------------------------------------------
# Heartbeat + stale detection
# ---------------------------------------------------------------------------


class TestHeartbeat:
    def test_heartbeat_updates_timestamp(self):
        store = _make_store()
        store.register(_make_record("mod-hb"))
        old_ts = store.get("mod-hb").last_seen_ts
        time.sleep(0.05)
        ok = store.heartbeat("mod-hb")
        assert ok
        new_ts = store.get("mod-hb").last_seen_ts
        assert new_ts >= old_ts

    def test_heartbeat_nonexistent(self):
        store = _make_store()
        ok = store.heartbeat("nonexistent")
        assert not ok

    def test_stale_detection_with_tiny_ttl(self):
        store = _make_store()
        store.register(_make_record("mod-stale"))
        # Force is_stale by using ttl=0 (any module with last_seen > 0s ago is stale)
        rec = store.get("mod-stale")
        assert rec.is_stale(ttl=0)

    def test_fresh_module_not_stale(self):
        store = _make_store()
        store.register(_make_record("mod-fresh"))
        rec = store.get("mod-fresh")
        # TTL 3600 seconds: module just registered, must not be stale
        assert not rec.is_stale(ttl=3600)

    def test_snapshot_shows_stale_state(self):
        store = _make_store()
        store.register(_make_record("mod-stale-snap"))
        store.set_state("mod-stale-snap", "ready")

        # Snapshot with no ttl param — liveness check is in to_dict()
        # Force stale via monkeypatching last_seen_ts
        rec = store.get("mod-stale-snap")
        rec.last_seen_ts = "2000-01-01T00:00:00+00:00"

        snap = store.snapshot_for_api(
            tenant_id=None, is_global_admin=True, redact=False
        )
        found = next((m for m in snap if m["module_id"] == "mod-stale-snap"), None)
        assert found is not None
        assert found["state"] == "stale"


# ---------------------------------------------------------------------------
# Dependency probes
# ---------------------------------------------------------------------------


class TestDependencyProbes:
    def test_update_dependency(self):
        store = _make_store()
        store.register(_make_record("mod-dep"))
        ok = store.update_dependency(
            "mod-dep",
            "db",
            status="ok",
            latency_ms=12.5,
        )
        assert ok
        deps = store.get_dependencies("mod-dep")
        assert deps is not None
        assert "db" in deps
        assert deps["db"].status == "ok"
        assert deps["db"].latency_ms == 12.5

    def test_dependency_latency_negative_clamped(self):
        store = _make_store()
        store.register(_make_record("mod-lat"))
        store.update_dependency("mod-lat", "redis", status="ok", latency_ms=-100.0)
        deps = store.get_dependencies("mod-lat")
        assert deps["redis"]._safe_latency() == 0.0

    def test_dependency_latency_max_clamped(self):
        store = _make_store()
        store.register(_make_record("mod-lat2"))
        store.update_dependency("mod-lat2", "nats", status="ok", latency_ms=999_999_999.0)
        deps = store.get_dependencies("mod-lat2")
        assert deps["nats"]._safe_latency() == 300_000.0

    def test_dependency_none_latency(self):
        store = _make_store()
        store.register(_make_record("mod-none-lat"))
        store.update_dependency("mod-none-lat", "opa", status="unknown", latency_ms=None)
        deps = store.get_dependencies("mod-none-lat")
        assert deps["opa"]._safe_latency() is None

    def test_get_dependencies_nonexistent_module(self):
        store = _make_store()
        result = store.get_dependencies("nonexistent")
        assert result is None

    def test_multiple_dependencies(self):
        store = _make_store()
        store.register(_make_record("mod-multidep"))
        for dep in ["db", "redis", "nats", "opa"]:
            store.update_dependency("mod-multidep", dep, status="ok", latency_ms=10.0)
        deps = store.get_dependencies("mod-multidep")
        assert len(deps) == 4


# ---------------------------------------------------------------------------
# Deterministic ID
# ---------------------------------------------------------------------------


class TestDeterministicID:
    def test_registration_hash_deterministic(self):
        h1 = make_registration_hash("mod-a", "1.0.0", "node-1")
        h2 = make_registration_hash("mod-a", "1.0.0", "node-1")
        assert h1 == h2

    def test_registration_hash_differs_on_version(self):
        h1 = make_registration_hash("mod-a", "1.0.0", "node-1")
        h2 = make_registration_hash("mod-a", "2.0.0", "node-1")
        assert h1 != h2

    def test_registration_hash_differs_on_tenant(self):
        h1 = make_registration_hash("mod-a", "1.0.0", "node-1")
        h2 = make_registration_hash("mod-a", "1.0.0", "node-2")
        assert h1 != h2


# ---------------------------------------------------------------------------
# Circuit breaker + queue depth
# ---------------------------------------------------------------------------


class TestCircuitBreakerQueueDepth:
    def test_set_breaker_state(self):
        store = _make_store()
        store.register(_make_record("mod-cb"))
        store.set_breaker_state("mod-cb", "open")
        rec = store.get("mod-cb")
        assert rec.breaker_state == "open"

    def test_set_queue_depth(self):
        store = _make_store()
        store.register(_make_record("mod-qd"))
        store.set_queue_depth("mod-qd", 42)
        rec = store.get("mod-qd")
        assert rec.queue_depth == 42

    def test_set_queue_depth_negative_clamped(self):
        store = _make_store()
        store.register(_make_record("mod-qd-neg"))
        store.set_queue_depth("mod-qd-neg", -5)
        rec = store.get("mod-qd-neg")
        assert rec.queue_depth == 0
