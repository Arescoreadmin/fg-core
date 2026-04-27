"""
tests/agent/test_collector_telemetry.py

Tests for task 17.2 — ProcessInventoryCollector (agent collector telemetry).

Coverage:
- Real non-heartbeat telemetry is emitted
- Event carries collector name, event type, schema version
- Event is tenant-safe (tenant_id and agent_id are explicit, no global inference)
- Missing tenant/agent context fails explicitly via validate()
- Broken collector (provider raises) fails through scheduler result path
- Empty snapshot is not treated as failure
- Sensitive fields (raw hostname) are not emitted in payload
- Collector registers through supported registry
- Scheduler can execute this collector through the 17.1 cadence path
- Default snapshot provider does not depend on injected/live state for shape

All tests are offline and deterministic.
Provider is injected in all tests; live host state is never asserted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from agent.app.collector.base import Collector as _CollectorBase
from agent.app.collector.base import CollectorEvent
from agent.app.collector.process_inventory import (
    COLLECTOR_NAME,
    DEFAULT_CADENCE_SECONDS,
    EVENT_TYPE,
    PAYLOAD_SCHEMA_VERSION,
    ProcessInventoryCollector,
    _default_snapshot,
)
from agent.app.collector.registry import CollectorRegistry
from agent.app.collector.scheduler import CollectorScheduler


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

_FIXED_SNAPSHOT: dict[str, Any] = {
    "schema_version": PAYLOAD_SCHEMA_VERSION,
    "platform": "linux",
    "os_release": "5.15.0",
    "os_version": "#1 SMP PREEMPT",
    "machine": "x86_64",
    "hostname_hash": "abcdef0123456789",
    "cpu_count": 4,
}

_EMPTY_SNAPSHOT: dict[str, Any] = {}


def _fixed_provider() -> dict[str, Any]:
    return dict(_FIXED_SNAPSHOT)


def _empty_provider() -> dict[str, Any]:
    return {}


def _raising_provider() -> dict[str, Any]:
    raise RuntimeError("snapshot provider unavailable: disk error")


def _scheduler_with(
    collector: ProcessInventoryCollector, t: float = 0.0
) -> tuple[CollectorScheduler, list[float]]:
    reg = CollectorRegistry()
    reg.register(collector)
    clock: list[float] = [t]
    return CollectorScheduler(reg, clock=lambda: clock[0]), clock


# ---------------------------------------------------------------------------
# ProcessInventoryCollector — identity and contract
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_name_is_stable() -> None:
    """Collector name matches the module constant and is non-empty."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    assert c.name == COLLECTOR_NAME
    assert c.name == "process_inventory"


def test_agent_collector_telemetry_cadence_default_is_positive() -> None:
    """Default cadence is positive (> 0)."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    assert c.cadence_seconds == DEFAULT_CADENCE_SECONDS
    assert c.cadence_seconds > 0


def test_agent_collector_telemetry_cadence_custom_respected() -> None:
    """Custom cadence is stored correctly."""
    c = ProcessInventoryCollector(
        cadence_seconds=60.0, snapshot_provider=_fixed_provider
    )
    assert c.cadence_seconds == 60.0


# ---------------------------------------------------------------------------
# ProcessInventoryCollector — non-heartbeat telemetry
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_emits_non_heartbeat_event() -> None:
    """Collector emits an event whose event_type is NOT heartbeat."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="a1")
    assert len(events) == 1
    assert events[0].event_type != "heartbeat"
    assert events[0].event_type == EVENT_TYPE


def test_agent_collector_telemetry_event_type_is_inventory_snapshot() -> None:
    """Event type is 'inventory.process_snapshot'."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="a1")
    assert events[0].event_type == "inventory.process_snapshot"


def test_agent_collector_telemetry_event_has_collector_name() -> None:
    """Emitted event carries the stable collector name."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="a1")
    assert events[0].collector_name == COLLECTOR_NAME


def test_agent_collector_telemetry_event_has_schema_version() -> None:
    """Emitted event carries a non-empty schema_version."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="a1")
    assert events[0].schema_version
    assert isinstance(events[0].schema_version, str)


def test_agent_collector_telemetry_event_has_occurred_at() -> None:
    """Emitted event has a non-empty occurred_at ISO timestamp."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="a1")
    assert events[0].occurred_at
    # Must be parseable as ISO 8601
    datetime.fromisoformat(events[0].occurred_at)


def test_agent_collector_telemetry_payload_contains_snapshot_data() -> None:
    """Event payload contains injected snapshot fields."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="a1")
    payload = events[0].payload
    assert payload["platform"] == "linux"
    assert payload["cpu_count"] == 4
    assert "hostname_hash" in payload


# ---------------------------------------------------------------------------
# Tenant-safety
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_event_carries_tenant_id() -> None:
    """Emitted event carries the tenant_id passed to collect()."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="explicit-tenant", agent_id="a1")
    assert events[0].tenant_id == "explicit-tenant"


def test_agent_collector_telemetry_event_carries_agent_id() -> None:
    """Emitted event carries the agent_id passed to collect()."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="explicit-agent")
    assert events[0].agent_id == "explicit-agent"


def test_agent_collector_telemetry_different_tenants_produce_distinct_events() -> None:
    """Two collect() calls with different tenant_ids produce distinct event bindings."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    e1 = c.collect(tenant_id="tenant-A", agent_id="a1")
    e2 = c.collect(tenant_id="tenant-B", agent_id="a2")
    assert e1[0].tenant_id == "tenant-A"
    assert e2[0].tenant_id == "tenant-B"
    assert e1[0].tenant_id != e2[0].tenant_id


def test_agent_collector_telemetry_validate_passes_on_valid_event() -> None:
    """A well-formed event from the collector passes validate() without error."""
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    events = c.collect(tenant_id="t1", agent_id="a1")
    events[0].validate()  # must not raise


def test_agent_collector_telemetry_empty_tenant_fails_validate() -> None:
    """CollectorEvent with empty tenant_id fails validate() — tenant-safety enforced."""
    evt = CollectorEvent(
        collector_name=COLLECTOR_NAME,
        event_type=EVENT_TYPE,
        tenant_id="",
        agent_id="a1",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        payload=_FIXED_SNAPSHOT,
    )
    with pytest.raises(ValueError, match="tenant_id"):
        evt.validate()


def test_agent_collector_telemetry_empty_agent_fails_validate() -> None:
    """CollectorEvent with empty agent_id fails validate() — agent-safety enforced."""
    evt = CollectorEvent(
        collector_name=COLLECTOR_NAME,
        event_type=EVENT_TYPE,
        tenant_id="t1",
        agent_id="",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        payload=_FIXED_SNAPSHOT,
    )
    with pytest.raises(ValueError, match="agent_id"):
        evt.validate()


# ---------------------------------------------------------------------------
# Sensitive data minimization
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_default_snapshot_no_raw_hostname() -> None:
    """Default snapshot provider does not emit a 'hostname' key (only hash)."""
    snapshot = _default_snapshot()
    assert "hostname" not in snapshot, "raw hostname must not be emitted"
    assert "hostname_hash" in snapshot, "hashed hostname must be present"


def test_agent_collector_telemetry_default_snapshot_no_cmdline() -> None:
    """Default snapshot provider does not emit command-line fields."""
    snapshot = _default_snapshot()
    for key in snapshot:
        assert "cmd" not in key.lower(), f"cmdline-like key found: {key!r}"
        assert "command" not in key.lower(), f"command-like key found: {key!r}"
        assert "argv" not in key.lower(), f"argv-like key found: {key!r}"


def test_agent_collector_telemetry_default_snapshot_no_env_vars() -> None:
    """Default snapshot provider does not emit environment variable fields."""
    snapshot = _default_snapshot()
    assert "env" not in snapshot
    assert "environ" not in snapshot


def test_agent_collector_telemetry_default_snapshot_no_secrets() -> None:
    """Default snapshot keys do not include known secret field names."""
    snapshot = _default_snapshot()
    forbidden = {"token", "secret", "password", "key", "credential", "api_key"}
    for k in snapshot:
        assert k.lower() not in forbidden, f"potential secret field emitted: {k!r}"


def test_agent_collector_telemetry_hostname_hash_is_hex_prefix() -> None:
    """Default snapshot hostname_hash is a 16-char lowercase hex string."""
    snapshot = _default_snapshot()
    h = snapshot["hostname_hash"]
    assert isinstance(h, str)
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# Failure behavior
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_broken_provider_raises() -> None:
    """Broken snapshot provider exception propagates from collect()."""
    c = ProcessInventoryCollector(snapshot_provider=_raising_provider)
    with pytest.raises(RuntimeError, match="snapshot provider unavailable"):
        c.collect(tenant_id="t1", agent_id="a1")


def test_agent_collector_telemetry_broken_provider_fails_via_scheduler() -> None:
    """Broken collector produces outcome='failed' through scheduler result path."""
    c = ProcessInventoryCollector(
        cadence_seconds=1.0, snapshot_provider=_raising_provider
    )
    scheduler, _ = _scheduler_with(c)
    results = scheduler.tick("t1", "a1")
    assert len(results) == 1
    assert results[0].outcome == "failed"
    assert results[0].error is not None
    assert "snapshot provider unavailable" in results[0].error


class _SiblingCollector(_CollectorBase):
    """Minimal valid sibling collector for isolation tests."""

    @property
    def name(self) -> str:
        return "sibling"

    @property
    def cadence_seconds(self) -> float:
        return 1.0

    def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
        return [
            CollectorEvent(
                collector_name="sibling",
                event_type="sibling.event",
                tenant_id=tenant_id,
                agent_id=agent_id,
                occurred_at=datetime.now(timezone.utc).isoformat(),
                payload={"ok": True},
            )
        ]


def test_agent_collector_telemetry_broken_collector_does_not_stop_others() -> None:
    """Broken inventory collector does not prevent sibling collectors from running."""
    broken = ProcessInventoryCollector(
        cadence_seconds=1.0, snapshot_provider=_raising_provider
    )
    good = _SiblingCollector()
    reg = CollectorRegistry()
    reg.register(broken)
    reg.register(good)
    clock: list[float] = [0.0]
    scheduler = CollectorScheduler(reg, clock=lambda: clock[0])
    results = scheduler.tick("t1", "a1")
    by_name = {r.collector_name: r for r in results}
    assert by_name["process_inventory"].outcome == "failed"
    assert by_name["sibling"].outcome == "ran"


# ---------------------------------------------------------------------------
# Empty telemetry — distinguishable from failure
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_empty_snapshot_is_not_failure() -> None:
    """Collector returning empty snapshot dict produces outcome='ran', not 'failed'."""
    c = ProcessInventoryCollector(
        cadence_seconds=1.0, snapshot_provider=_empty_provider
    )
    scheduler, _ = _scheduler_with(c)
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "ran"
    assert results[0].events[0].payload == {}


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_registers_through_supported_registry() -> None:
    """ProcessInventoryCollector registers via CollectorRegistry without error."""
    reg = CollectorRegistry()
    c = ProcessInventoryCollector(snapshot_provider=_fixed_provider)
    reg.register(c)
    assert reg.get(COLLECTOR_NAME) is c


def test_agent_collector_telemetry_duplicate_registration_raises() -> None:
    """Duplicate registration of ProcessInventoryCollector raises ValueError."""
    reg = CollectorRegistry()
    reg.register(ProcessInventoryCollector(snapshot_provider=_fixed_provider))
    with pytest.raises(ValueError, match="Duplicate"):
        reg.register(ProcessInventoryCollector(snapshot_provider=_fixed_provider))


# ---------------------------------------------------------------------------
# Scheduler cadence integration
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_scheduler_runs_on_first_tick() -> None:
    """Scheduler runs inventory collector on first tick (no prior last_run)."""
    c = ProcessInventoryCollector(
        cadence_seconds=60.0, snapshot_provider=_fixed_provider
    )
    scheduler, _ = _scheduler_with(c)
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "ran"
    assert len(results[0].events) == 1


def test_agent_collector_telemetry_scheduler_skips_before_cadence() -> None:
    """Scheduler skips inventory collector before cadence has elapsed."""
    c = ProcessInventoryCollector(
        cadence_seconds=60.0, snapshot_provider=_fixed_provider
    )
    scheduler, clock = _scheduler_with(c)
    scheduler.tick("t1", "a1")
    clock[0] = 30.0
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "skipped"


def test_agent_collector_telemetry_scheduler_runs_after_cadence_elapsed() -> None:
    """Scheduler runs inventory collector again after cadence has elapsed."""
    c = ProcessInventoryCollector(
        cadence_seconds=60.0, snapshot_provider=_fixed_provider
    )
    scheduler, clock = _scheduler_with(c)
    scheduler.tick("t1", "a1")
    clock[0] = 60.0
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "ran"


def test_agent_collector_telemetry_scheduler_events_carry_tenant_id() -> None:
    """Events returned by scheduler carry the tenant_id from tick()."""
    c = ProcessInventoryCollector(
        cadence_seconds=1.0, snapshot_provider=_fixed_provider
    )
    scheduler, _ = _scheduler_with(c)
    results = scheduler.tick("expected-tenant", "expected-agent")
    for evt in results[0].events:
        assert evt.tenant_id == "expected-tenant"
        assert evt.agent_id == "expected-agent"


# ---------------------------------------------------------------------------
# Default snapshot shape (structural, not host-state-dependent)
# ---------------------------------------------------------------------------


def test_agent_collector_telemetry_default_snapshot_has_required_keys() -> None:
    """Default snapshot provider returns all required structural keys."""
    snapshot = _default_snapshot()
    required = {
        "schema_version",
        "platform",
        "os_release",
        "os_version",
        "machine",
        "hostname_hash",
        "cpu_count",
    }
    assert required.issubset(snapshot.keys())


def test_agent_collector_telemetry_default_snapshot_schema_version_matches() -> None:
    """Default snapshot schema_version matches PAYLOAD_SCHEMA_VERSION."""
    snapshot = _default_snapshot()
    assert snapshot["schema_version"] == PAYLOAD_SCHEMA_VERSION


def test_agent_collector_telemetry_default_snapshot_cpu_count_is_int() -> None:
    """Default snapshot cpu_count is a non-negative integer."""
    snapshot = _default_snapshot()
    assert isinstance(snapshot["cpu_count"], int)
    assert snapshot["cpu_count"] >= 0
