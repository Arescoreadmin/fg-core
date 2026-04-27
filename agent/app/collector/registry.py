"""
agent.app.collector.registry — Collector registration and lookup.

Invariants:
- Duplicate collector names are rejected deterministically (ValueError).
- Unknown collector references fail clearly (KeyError).
- Registry is not thread-safe by default; use external locking if shared
  across threads.
"""

from __future__ import annotations

from agent.app.collector.base import Collector


class CollectorRegistry:
    """
    Registry of supported collectors indexed by stable name.

    Usage::

        registry = CollectorRegistry()
        registry.register(HeartbeatCollector())
        registry.register(InventoryCollector())

        collector = registry.get("heartbeat")
        all_collectors = registry.all()
    """

    def __init__(self) -> None:
        self._collectors: dict[str, Collector] = {}

    def register(self, collector: Collector) -> None:
        """
        Register a collector by its name.

        Raises:
            ValueError: If a collector with the same name is already registered.
            ValueError: If collector.name is empty or not a string.
            ValueError: If collector.cadence_seconds is not a positive number.
        """
        if not isinstance(collector.name, str) or not collector.name.strip():
            raise ValueError(
                f"Collector name must be a non-empty string; got {collector.name!r}"
            )
        if (
            not isinstance(collector.cadence_seconds, (int, float))
            or collector.cadence_seconds <= 0
        ):
            raise ValueError(
                f"Collector cadence_seconds must be > 0; got {collector.cadence_seconds!r}"
            )
        if collector.name in self._collectors:
            raise ValueError(
                f"Duplicate collector ID: {collector.name!r} is already registered"
            )
        self._collectors[collector.name] = collector

    def get(self, name: str) -> Collector:
        """
        Return the collector registered under `name`.

        Raises:
            KeyError: If no collector with that name is registered.
        """
        if name not in self._collectors:
            raise KeyError(f"Unknown collector: {name!r}")
        return self._collectors[name]

    def all(self) -> list[Collector]:
        """Return all registered collectors in registration order."""
        return list(self._collectors.values())

    def __len__(self) -> int:
        return len(self._collectors)

    def __contains__(self, name: object) -> bool:
        return name in self._collectors
