"""
agent.app.collector.scheduler — Deterministic collector scheduler.

Design invariants:
- Clock is injected; tests never sleep in real time.
- Collector failures are recorded as outcome='failed', not swallowed.
- Unrelated collectors continue after one collector fails.
- Events are validated before being accepted into SchedulerResult.
- No events are silently dropped; all outcomes are reported.
- State (last_run timestamps) is per-scheduler-instance; no global mutable state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from agent.app.collector.base import Collector, CollectorEvent
from agent.app.collector.registry import CollectorRegistry

log = logging.getLogger("frostgate.agent.collector.scheduler")

# Type alias for the injected clock function.
ClockFn = Callable[[], float]


@dataclass
class SchedulerResult:
    """
    Result of a single collector execution attempt.

    Fields:
        collector_name  Name of the collector that was attempted.
        outcome         One of:
                          "ran"     — collector executed, events validated and accepted.
                          "skipped" — cadence not yet elapsed; collector not run.
                          "failed"  — collector raised an exception; error contains detail.
        events          Validated CollectorEvent instances from a successful run.
                        Empty for "skipped" and "failed" outcomes.
        error           Human-readable error description for "failed" outcome.
                        None for "ran" and "skipped".
    """

    collector_name: str
    outcome: str  # "ran" | "skipped" | "failed"
    events: list[CollectorEvent] = field(default_factory=list)
    error: str | None = None


class CollectorScheduler:
    """
    Executes registered collectors on their declared cadence.

    The scheduler is deterministic under test via an injected clock function.
    By default uses time.monotonic().

    Usage::

        import time
        scheduler = CollectorScheduler(registry)

        # In a test with a controllable clock:
        fake_time = 0.0
        scheduler = CollectorScheduler(registry, clock=lambda: fake_time)

    The scheduler does NOT flush events to a queue or network.
    Callers receive all SchedulerResult objects and decide how to handle events.
    """

    def __init__(
        self,
        registry: CollectorRegistry,
        clock: ClockFn | None = None,
    ) -> None:
        self._registry = registry
        self._clock: ClockFn = (
            clock if clock is not None else __import__("time").monotonic
        )
        # Per-collector last successful run timestamp (monotonic seconds).
        self._last_run: dict[str, float] = {}

    def tick(self, tenant_id: str, agent_id: str) -> list[SchedulerResult]:
        """
        Attempt to run all registered collectors.

        Returns one SchedulerResult per registered collector, in registration order.
        Due collectors are run; not-yet-due collectors produce outcome='skipped'.
        Collector exceptions produce outcome='failed' and do not affect other collectors.

        Args:
            tenant_id: Tenant context for all collectors in this tick.
            agent_id:  Agent identity for all collectors in this tick.

        Returns:
            list[SchedulerResult], one entry per registered collector.
        """
        now = self._clock()
        results: list[SchedulerResult] = []
        for collector in self._registry.all():
            result = self._run_one(collector, tenant_id, agent_id, now)
            results.append(result)
        return results

    def _run_one(
        self,
        collector: Collector,
        tenant_id: str,
        agent_id: str,
        now: float,
    ) -> SchedulerResult:
        """
        Execute one collector if its cadence is due, or return skipped.

        Post-condition: _last_run[collector.name] is updated for both
        'ran' and 'failed' outcomes, so a broken collector does not spin
        at full tick rate.
        """
        last = self._last_run.get(collector.name)
        if last is not None and (now - last) < collector.cadence_seconds:
            return SchedulerResult(
                collector_name=collector.name,
                outcome="skipped",
            )

        try:
            raw_events = collector.collect(tenant_id, agent_id)
        except Exception as exc:
            log.error(
                "collector_failed collector=%s error=%s",
                collector.name,
                exc,
                exc_info=True,
            )
            # Advance last_run even on failure to prevent unbounded retry spin.
            self._last_run[collector.name] = now
            return SchedulerResult(
                collector_name=collector.name,
                outcome="failed",
                error=str(exc),
            )

        # Validate events before accepting; any invalid event surfaces as 'failed'.
        # Wraps the entire loop in except Exception so that TypeError (non-iterable
        # return value) and AttributeError (e.g. list of dicts) are also caught and
        # reported as 'failed' rather than escaping _run_one and breaking isolation.
        validated: list[CollectorEvent] = []
        try:
            for evt in raw_events:
                evt.validate()
                validated.append(evt)
        except Exception as exc:
            log.error(
                "collector_event_invalid collector=%s error=%s",
                collector.name,
                exc,
            )
            self._last_run[collector.name] = now
            return SchedulerResult(
                collector_name=collector.name,
                outcome="failed",
                error=f"invalid event: {exc}",
            )

        self._last_run[collector.name] = now
        return SchedulerResult(
            collector_name=collector.name,
            outcome="ran",
            events=validated,
        )
