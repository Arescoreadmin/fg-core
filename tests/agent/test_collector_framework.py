"""
tests/agent/test_collector_framework.py

Tests for the agent collector framework (task 17.1).

Coverage:
- Collector interface contract: ABC prevents unimplemented instantiation
- CollectorEvent schema: required fields, validation, tenant-safety
- CollectorRegistry: registration, duplicate rejection, unknown reference
- CollectorScheduler: cadence gating, failure isolation, event propagation,
  deterministic clock injection
- Tenant-safety: events must carry explicit tenant_id and agent_id
- Edge cases: empty registry, multiple collectors, malformed events

All tests are offline and deterministic. No real-time sleeps.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from agent.app.collector.base import (
    COLLECTOR_EVENT_SCHEMA_VERSION,
    Collector,
    CollectorEvent,
)
from agent.app.collector.registry import CollectorRegistry
from agent.app.collector.scheduler import CollectorScheduler, SchedulerResult


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(
    collector_name: str = "test_collector",
    event_type: str = "test.event",
    tenant_id: str = "tenant-1",
    agent_id: str = "agent-1",
    payload: dict[str, Any] | None = None,
) -> CollectorEvent:
    return CollectorEvent(
        collector_name=collector_name,
        event_type=event_type,
        tenant_id=tenant_id,
        agent_id=agent_id,
        occurred_at=_now_iso(),
        payload=payload if payload is not None else {"ok": True},
    )


class _GoodCollector(Collector):
    """Minimal valid collector for tests."""

    def __init__(
        self,
        name: str = "good",
        cadence: float = 60.0,
        events: list[CollectorEvent] | None = None,
    ) -> None:
        self._name = name
        self._cadence = cadence
        self._events = events or []

    @property
    def name(self) -> str:
        return self._name

    @property
    def cadence_seconds(self) -> float:
        return self._cadence

    def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
        return [
            CollectorEvent(
                collector_name=self._name,
                event_type="test.snapshot",
                tenant_id=tenant_id,
                agent_id=agent_id,
                occurred_at=_now_iso(),
                payload={"collected": True},
            )
        ] + self._events


class _CrashyCollector(Collector):
    """Collector that always raises."""

    def __init__(self, name: str = "crashy") -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def cadence_seconds(self) -> float:
        return 30.0

    def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
        raise RuntimeError("collection failed: environment unavailable")


class _EmptyCollector(Collector):
    """Collector that returns no events (valid; nothing to report)."""

    @property
    def name(self) -> str:
        return "empty"

    @property
    def cadence_seconds(self) -> float:
        return 10.0

    def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
        return []


# ---------------------------------------------------------------------------
# CollectorEvent — schema and validation
# ---------------------------------------------------------------------------


def test_agent_collector_framework_event_schema_version_constant() -> None:
    """Schema version constant is defined and non-empty."""
    assert COLLECTOR_EVENT_SCHEMA_VERSION
    assert isinstance(COLLECTOR_EVENT_SCHEMA_VERSION, str)


def test_agent_collector_framework_event_valid_passes_validate() -> None:
    """A fully-populated CollectorEvent passes validate() without error."""
    evt = _event()
    evt.validate()  # must not raise


def test_agent_collector_framework_event_default_schema_version() -> None:
    """CollectorEvent defaults schema_version to the module constant."""
    evt = _event()
    assert evt.schema_version == COLLECTOR_EVENT_SCHEMA_VERSION


def test_agent_collector_framework_event_is_immutable() -> None:
    """CollectorEvent is frozen; mutation raises FrozenInstanceError."""
    evt = _event()
    with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
        evt.tenant_id = "other"  # type: ignore[misc]


def test_agent_collector_framework_event_empty_tenant_id_fails_validate() -> None:
    """CollectorEvent.validate() rejects empty tenant_id."""
    evt = CollectorEvent(
        collector_name="c",
        event_type="t",
        tenant_id="",  # empty
        agent_id="a",
        occurred_at=_now_iso(),
        payload={},
    )
    with pytest.raises(ValueError, match="tenant_id"):
        evt.validate()


def test_agent_collector_framework_event_empty_agent_id_fails_validate() -> None:
    """CollectorEvent.validate() rejects empty agent_id."""
    evt = CollectorEvent(
        collector_name="c",
        event_type="t",
        tenant_id="tenant-1",
        agent_id="",  # empty
        occurred_at=_now_iso(),
        payload={},
    )
    with pytest.raises(ValueError, match="agent_id"):
        evt.validate()


def test_agent_collector_framework_event_empty_collector_name_fails_validate() -> None:
    """CollectorEvent.validate() rejects empty collector_name."""
    evt = CollectorEvent(
        collector_name="",
        event_type="t",
        tenant_id="tenant-1",
        agent_id="a",
        occurred_at=_now_iso(),
        payload={},
    )
    with pytest.raises(ValueError, match="collector_name"):
        evt.validate()


def test_agent_collector_framework_event_empty_event_type_fails_validate() -> None:
    """CollectorEvent.validate() rejects empty event_type."""
    evt = CollectorEvent(
        collector_name="c",
        event_type="",
        tenant_id="tenant-1",
        agent_id="a",
        occurred_at=_now_iso(),
        payload={},
    )
    with pytest.raises(ValueError, match="event_type"):
        evt.validate()


def test_agent_collector_framework_event_non_dict_payload_fails_validate() -> None:
    """CollectorEvent.validate() rejects non-dict payload."""
    evt = CollectorEvent(
        collector_name="c",
        event_type="t",
        tenant_id="tenant-1",
        agent_id="a",
        occurred_at=_now_iso(),
        payload="not-a-dict",  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="payload"):
        evt.validate()


def test_agent_collector_framework_event_whitespace_only_tenant_fails_validate() -> (
    None
):
    """CollectorEvent.validate() rejects whitespace-only tenant_id."""
    evt = CollectorEvent(
        collector_name="c",
        event_type="t",
        tenant_id="   ",
        agent_id="a",
        occurred_at=_now_iso(),
        payload={},
    )
    with pytest.raises(ValueError, match="tenant_id"):
        evt.validate()


def test_agent_collector_framework_event_tenant_safety_explicit_binding() -> None:
    """Events carry explicit tenant_id; cross-tenant construction is structurally distinct."""
    evt_t1 = _event(tenant_id="tenant-1", agent_id="agent-1")
    evt_t2 = _event(tenant_id="tenant-2", agent_id="agent-2")
    # Tenant isolation is structural: two events cannot share field references.
    assert evt_t1.tenant_id != evt_t2.tenant_id


# ---------------------------------------------------------------------------
# Collector ABC — interface contract
# ---------------------------------------------------------------------------


def test_agent_collector_framework_abstract_collector_cannot_be_instantiated() -> None:
    """Collector ABC cannot be directly instantiated; name/cadence/collect must be implemented."""
    with pytest.raises(TypeError):
        Collector()  # type: ignore[abstract]


def test_agent_collector_framework_collector_missing_name_cannot_instantiate() -> None:
    """Concrete subclass missing name property cannot be instantiated."""

    class _NoName(Collector):
        @property
        def cadence_seconds(self) -> float:
            return 60.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            return []

    with pytest.raises(TypeError):
        _NoName()  # type: ignore[abstract]


def test_agent_collector_framework_collector_missing_cadence_cannot_instantiate() -> (
    None
):
    """Concrete subclass missing cadence_seconds cannot be instantiated."""

    class _NoCadence(Collector):
        @property
        def name(self) -> str:
            return "no_cadence"

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            return []

    with pytest.raises(TypeError):
        _NoCadence()  # type: ignore[abstract]


def test_agent_collector_framework_collector_missing_collect_cannot_instantiate() -> (
    None
):
    """Concrete subclass missing collect() cannot be instantiated."""

    class _NoCollect(Collector):
        @property
        def name(self) -> str:
            return "no_collect"

        @property
        def cadence_seconds(self) -> float:
            return 60.0

    with pytest.raises(TypeError):
        _NoCollect()  # type: ignore[abstract]


def test_agent_collector_framework_valid_collector_instantiates() -> None:
    """Fully implemented Collector subclass instantiates successfully."""
    c = _GoodCollector()
    assert c.name == "good"
    assert c.cadence_seconds > 0


# ---------------------------------------------------------------------------
# CollectorRegistry — registration and lookup
# ---------------------------------------------------------------------------


def test_agent_collector_framework_registry_register_and_get() -> None:
    """Registered collector is retrievable by name."""
    reg = CollectorRegistry()
    c = _GoodCollector(name="inv")
    reg.register(c)
    assert reg.get("inv") is c


def test_agent_collector_framework_registry_duplicate_id_raises() -> None:
    """Registering two collectors with the same name raises ValueError."""
    reg = CollectorRegistry()
    reg.register(_GoodCollector(name="hb"))
    with pytest.raises(ValueError, match="Duplicate"):
        reg.register(_GoodCollector(name="hb"))


def test_agent_collector_framework_registry_unknown_name_raises() -> None:
    """Getting an unregistered name raises KeyError."""
    reg = CollectorRegistry()
    with pytest.raises(KeyError, match="Unknown collector"):
        reg.get("nonexistent")


def test_agent_collector_framework_registry_empty_name_raises() -> None:
    """Registering a collector with empty name raises ValueError."""

    class _EmptyNameCollector(Collector):
        @property
        def name(self) -> str:
            return ""

        @property
        def cadence_seconds(self) -> float:
            return 10.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            return []

    reg = CollectorRegistry()
    with pytest.raises(ValueError, match="non-empty"):
        reg.register(_EmptyNameCollector())


def test_agent_collector_framework_registry_empty_returns_empty_list() -> None:
    """Empty registry returns empty list from all()."""
    reg = CollectorRegistry()
    assert reg.all() == []
    assert len(reg) == 0


def test_agent_collector_framework_registry_all_returns_in_registration_order() -> None:
    """all() returns collectors in the order they were registered."""
    reg = CollectorRegistry()
    names = ["alpha", "beta", "gamma"]
    for n in names:
        reg.register(_GoodCollector(name=n))
    assert [c.name for c in reg.all()] == names


def test_agent_collector_framework_registry_contains_check() -> None:
    """__contains__ works for registered and unregistered names."""
    reg = CollectorRegistry()
    reg.register(_GoodCollector(name="hb"))
    assert "hb" in reg
    assert "missing" not in reg


def test_agent_collector_framework_registry_len_grows_with_registrations() -> None:
    """len(registry) reflects the number of registered collectors."""
    reg = CollectorRegistry()
    assert len(reg) == 0
    reg.register(_GoodCollector(name="a"))
    assert len(reg) == 1
    reg.register(_GoodCollector(name="b"))
    assert len(reg) == 2


# ---------------------------------------------------------------------------
# CollectorScheduler — cadence, failure isolation, determinism
# ---------------------------------------------------------------------------


def _scheduler_with_clock(
    *collectors: Collector,
    t: float = 0.0,
) -> tuple[CollectorScheduler, list[float]]:
    """Build a scheduler with a fake monotonic clock and register collectors."""
    reg = CollectorRegistry()
    for c in collectors:
        reg.register(c)
    clock_val: list[float] = [t]
    scheduler = CollectorScheduler(reg, clock=lambda: clock_val[0])
    return scheduler, clock_val


def test_agent_collector_framework_scheduler_tick_returns_scheduler_results() -> None:
    """tick() returns a list of SchedulerResult instances."""
    scheduler, _ = _scheduler_with_clock(_GoodCollector(name="inv", cadence=60.0))
    results = scheduler.tick("t1", "a1")
    assert all(isinstance(r, SchedulerResult) for r in results)


def test_agent_collector_framework_scheduler_runs_due_collector() -> None:
    """Scheduler runs collector when it has never run before (no last_run)."""
    scheduler, _ = _scheduler_with_clock(_GoodCollector(name="inv", cadence=60.0))
    results = scheduler.tick("t1", "a1")
    assert len(results) == 1
    assert results[0].outcome == "ran"
    assert results[0].collector_name == "inv"


def test_agent_collector_framework_scheduler_skips_collector_before_cadence() -> None:
    """Scheduler skips a collector that ran less than cadence_seconds ago."""
    scheduler, clock = _scheduler_with_clock(_GoodCollector(name="inv", cadence=60.0))
    # First tick: runs.
    scheduler.tick("t1", "a1")
    # Advance clock by less than cadence (30s < 60s).
    clock[0] = 30.0
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "skipped"


def test_agent_collector_framework_scheduler_runs_collector_when_cadence_elapsed() -> (
    None
):
    """Scheduler runs collector again after cadence has fully elapsed."""
    scheduler, clock = _scheduler_with_clock(_GoodCollector(name="inv", cadence=60.0))
    # First tick at t=0.
    scheduler.tick("t1", "a1")
    # Advance to exactly cadence.
    clock[0] = 60.0
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "ran"


def test_agent_collector_framework_scheduler_records_collector_failure() -> None:
    """Collector exception produces outcome='failed' with error detail."""
    scheduler, _ = _scheduler_with_clock(_CrashyCollector())
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "failed"
    assert results[0].error is not None
    assert "collection failed" in results[0].error


def test_agent_collector_framework_scheduler_failure_does_not_crash_other_collectors() -> (
    None
):
    """Crashy collector failure does not prevent other collectors from running."""
    scheduler, _ = _scheduler_with_clock(
        _CrashyCollector(name="crashy"),
        _GoodCollector(name="good"),
    )
    results = scheduler.tick("t1", "a1")
    by_name = {r.collector_name: r for r in results}
    assert by_name["crashy"].outcome == "failed"
    assert by_name["good"].outcome == "ran"


def test_agent_collector_framework_scheduler_returns_events_from_successful_collector() -> (
    None
):
    """Successful collector's events appear in SchedulerResult.events."""
    scheduler, _ = _scheduler_with_clock(_GoodCollector(name="inv"))
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "ran"
    assert len(results[0].events) >= 1
    for evt in results[0].events:
        assert evt.tenant_id == "t1"
        assert evt.agent_id == "a1"


def test_agent_collector_framework_scheduler_empty_registry_returns_empty() -> None:
    """tick() on empty registry returns empty list."""
    reg = CollectorRegistry()
    scheduler = CollectorScheduler(reg)
    assert scheduler.tick("t1", "a1") == []


def test_agent_collector_framework_scheduler_events_carry_tenant_id() -> None:
    """Every event returned by scheduler carries the tenant_id passed to tick()."""
    scheduler, _ = _scheduler_with_clock(_GoodCollector(name="inv"))
    results = scheduler.tick("expected-tenant", "expected-agent")
    for r in results:
        for evt in r.events:
            assert evt.tenant_id == "expected-tenant"
            assert evt.agent_id == "expected-agent"


def test_agent_collector_framework_scheduler_failed_collector_advances_last_run() -> (
    None
):
    """Failed collector still advances last_run so it doesn't spin on every tick."""
    scheduler, clock = _scheduler_with_clock(_CrashyCollector(name="crashy"))
    # First tick: failed.
    r1 = scheduler.tick("t1", "a1")
    assert r1[0].outcome == "failed"
    # Advance clock but less than cadence (30s).
    clock[0] = 10.0
    r2 = scheduler.tick("t1", "a1")
    # Must be skipped (not failed again immediately).
    assert r2[0].outcome == "skipped"


def test_agent_collector_framework_scheduler_multiple_collectors_all_run_first_tick() -> (
    None
):
    """All registered collectors run on first tick (no last_run state)."""
    scheduler, _ = _scheduler_with_clock(
        _GoodCollector(name="a"),
        _GoodCollector(name="b"),
        _GoodCollector(name="c"),
    )
    results = scheduler.tick("t1", "a1")
    assert len(results) == 3
    assert all(r.outcome == "ran" for r in results)


def test_agent_collector_framework_scheduler_results_in_registration_order() -> None:
    """Scheduler results appear in the same order as collector registration."""
    names = ["z", "m", "a"]
    scheduler, _ = _scheduler_with_clock(*[_GoodCollector(name=n) for n in names])
    results = scheduler.tick("t1", "a1")
    assert [r.collector_name for r in results] == names


def test_agent_collector_framework_scheduler_empty_collector_runs_with_no_events() -> (
    None
):
    """Collector returning empty list produces outcome='ran' with no events."""
    scheduler, _ = _scheduler_with_clock(_EmptyCollector())
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "ran"
    assert results[0].events == []


def test_agent_collector_framework_scheduler_malformed_event_fails_run() -> None:
    """Collector returning an event with empty tenant_id produces outcome='failed'."""

    class _MalformedTenantCollector(Collector):
        @property
        def name(self) -> str:
            return "malformed"

        @property
        def cadence_seconds(self) -> float:
            return 1.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            # Deliberately omit tenant_id to simulate a bad collector.
            return [
                CollectorEvent(
                    collector_name="malformed",
                    event_type="bad.event",
                    tenant_id="",  # empty — should be rejected
                    agent_id=agent_id,
                    occurred_at=_now_iso(),
                    payload={},
                )
            ]

    scheduler, _ = _scheduler_with_clock(_MalformedTenantCollector())
    results = scheduler.tick("t1", "a1")
    assert results[0].outcome == "failed"
    assert results[0].error is not None


def test_agent_collector_framework_scheduler_is_deterministic_with_injected_clock() -> (
    None
):
    """Two schedulers with identical injected clocks produce identical run/skip decisions."""
    cadence = 45.0
    reg1, reg2 = CollectorRegistry(), CollectorRegistry()
    reg1.register(_GoodCollector(name="x", cadence=cadence))
    reg2.register(_GoodCollector(name="x", cadence=cadence))

    clock_val: list[float] = [0.0]
    s1 = CollectorScheduler(reg1, clock=lambda: clock_val[0])
    s2 = CollectorScheduler(reg2, clock=lambda: clock_val[0])

    # Both run at t=0.
    r1 = s1.tick("t1", "a1")
    r2 = s2.tick("t1", "a1")
    assert r1[0].outcome == r2[0].outcome == "ran"

    # Advance to t=20 (< cadence) — both skip.
    clock_val[0] = 20.0
    r1 = s1.tick("t1", "a1")
    r2 = s2.tick("t1", "a1")
    assert r1[0].outcome == r2[0].outcome == "skipped"


# ---------------------------------------------------------------------------
# Tenant-safety invariants
# ---------------------------------------------------------------------------


def test_agent_collector_framework_tenant_safety_no_global_state_inference() -> None:
    """
    Collector cannot infer tenant_id from global state.
    tick() passes tenant_id explicitly; collector receives it as an argument.
    """
    captured: list[tuple[str, str]] = []

    class _CapturingCollector(Collector):
        @property
        def name(self) -> str:
            return "capture"

        @property
        def cadence_seconds(self) -> float:
            return 1.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            captured.append((tenant_id, agent_id))
            return []

    scheduler, _ = _scheduler_with_clock(_CapturingCollector())
    scheduler.tick("explicit-tenant", "explicit-agent")
    assert captured == [("explicit-tenant", "explicit-agent")]


def test_agent_collector_framework_tenant_safety_different_tenants_produce_distinct_events() -> (
    None
):
    """
    Two tick() calls with different tenant_ids produce events scoped to each tenant.
    No cross-tenant sharing.
    """
    reg = CollectorRegistry()
    reg.register(_GoodCollector(name="inv", cadence=1.0))
    t_val: list[float] = [0.0]
    scheduler = CollectorScheduler(reg, clock=lambda: t_val[0])

    results_t1 = scheduler.tick("tenant-A", "agent-1")
    t_val[0] = 2.0  # advance past cadence
    results_t2 = scheduler.tick("tenant-B", "agent-2")

    events_t1 = results_t1[0].events
    events_t2 = results_t2[0].events
    assert all(e.tenant_id == "tenant-A" for e in events_t1)
    assert all(e.tenant_id == "tenant-B" for e in events_t2)


# ---------------------------------------------------------------------------
# Regression: P1 — malformed return type must not escape _run_one
# ---------------------------------------------------------------------------


def test_agent_collector_framework_scheduler_none_return_fails_not_crashes() -> None:
    """
    P1 regression: collector returning None instead of list[CollectorEvent] raises
    TypeError during iteration. This must produce outcome='failed', not propagate
    out of _run_one, so subsequent collectors still run.
    """

    class _NoneReturnCollector(Collector):
        @property
        def name(self) -> str:
            return "none_return"

        @property
        def cadence_seconds(self) -> float:
            return 1.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            return None  # type: ignore[return-value]

    scheduler, _ = _scheduler_with_clock(
        _NoneReturnCollector(),
        _GoodCollector(name="after"),
    )
    results = scheduler.tick("t1", "a1")
    by_name = {r.collector_name: r for r in results}
    assert by_name["none_return"].outcome == "failed"
    assert by_name["none_return"].error is not None
    # Failure isolation: subsequent collector still ran.
    assert by_name["after"].outcome == "ran"


def test_agent_collector_framework_scheduler_dict_events_fail_not_crash() -> None:
    """
    P1 regression: collector returning list[dict] (missing .validate) raises
    AttributeError. Must produce outcome='failed', not break subsequent collectors.
    """

    class _DictEventsCollector(Collector):
        @property
        def name(self) -> str:
            return "dict_events"

        @property
        def cadence_seconds(self) -> float:
            return 1.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            return [{"bad": "event"}]  # type: ignore[return-value]

    scheduler, _ = _scheduler_with_clock(
        _DictEventsCollector(),
        _GoodCollector(name="after"),
    )
    results = scheduler.tick("t1", "a1")
    by_name = {r.collector_name: r for r in results}
    assert by_name["dict_events"].outcome == "failed"
    assert by_name["dict_events"].error is not None
    assert by_name["after"].outcome == "ran"


# ---------------------------------------------------------------------------
# Regression: P2 — zero/negative cadence must be rejected at registration
# ---------------------------------------------------------------------------


def test_agent_collector_framework_registry_zero_cadence_raises() -> None:
    """P2 regression: cadence_seconds=0 is rejected by register()."""

    class _ZeroCadence(Collector):
        @property
        def name(self) -> str:
            return "zero_cadence"

        @property
        def cadence_seconds(self) -> float:
            return 0.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            return []

    reg = CollectorRegistry()
    with pytest.raises(ValueError, match="cadence_seconds"):
        reg.register(_ZeroCadence())


def test_agent_collector_framework_registry_negative_cadence_raises() -> None:
    """P2 regression: cadence_seconds=-1 is rejected by register()."""

    class _NegCadence(Collector):
        @property
        def name(self) -> str:
            return "neg_cadence"

        @property
        def cadence_seconds(self) -> float:
            return -1.0

        def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
            return []

    reg = CollectorRegistry()
    with pytest.raises(ValueError, match="cadence_seconds"):
        reg.register(_NegCadence())
