"""
agent.app.collector — Supported collector framework.

Public surface:
  CollectorEvent           — typed event schema (tenant-safe, schema-versioned)
  Collector                — abstract base class for all supported collectors
  CollectorRegistry        — register/lookup with duplicate rejection
  CollectorScheduler       — deterministic scheduler with injected clock
  SchedulerResult          — per-collector execution result
  ProcessInventoryCollector — host inventory snapshot collector (task 17.2)
"""

from agent.app.collector.base import (
    COLLECTOR_EVENT_SCHEMA_VERSION,
    Collector,
    CollectorEvent,
)
from agent.app.collector.process_inventory import ProcessInventoryCollector
from agent.app.collector.registry import CollectorRegistry
from agent.app.collector.scheduler import CollectorScheduler, SchedulerResult

__all__ = [
    "COLLECTOR_EVENT_SCHEMA_VERSION",
    "Collector",
    "CollectorEvent",
    "CollectorRegistry",
    "CollectorScheduler",
    "SchedulerResult",
    "ProcessInventoryCollector",
]
