"""
agent.app.collector.base — Collector interface and event schema.

Design invariants:
- CollectorEvent is immutable (frozen dataclass).
- Every event carries explicit tenant_id and agent_id; never inferred from global state.
- validate() fails deterministically on missing or malformed fields.
- Collector is an abstract base class; concrete implementations must declare
  a stable name, a cadence, and a collect() method.
- Cross-tenant leakage is structurally impossible: tenant_id and agent_id are
  required parameters on every collect() call and every CollectorEvent.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any

COLLECTOR_EVENT_SCHEMA_VERSION: str = "1.0"

# Required non-empty string fields on CollectorEvent.
_REQUIRED_STRING_FIELDS: tuple[str, ...] = (
    "collector_name",
    "event_type",
    "tenant_id",
    "agent_id",
    "occurred_at",
    "schema_version",
)


@dataclass(frozen=True)
class CollectorEvent:
    """
    Explicit schema for a collector-emitted event.

    Tenant-safety guarantees:
    - tenant_id and agent_id are required, non-empty, and explicit on every event.
    - They must be provided by the caller (never inferred from global state).
    - validate() enforces this structurally — malformed events fail before use.

    Fields:
        collector_name  Stable name of the collector that produced this event.
        event_type      Semantic event type (e.g. "inventory.snapshot").
        tenant_id       Tenant that owns this event. Must not be empty.
        agent_id        Agent identity that produced this event. Must not be empty.
        occurred_at     ISO 8601 UTC timestamp of event occurrence.
        payload         Arbitrary collector-specific data dict.
        schema_version  Schema version for forward/backward compat (default "1.0").
    """

    collector_name: str
    event_type: str
    tenant_id: str
    agent_id: str
    occurred_at: str
    payload: dict[str, Any]
    schema_version: str = COLLECTOR_EVENT_SCHEMA_VERSION

    def validate(self) -> None:
        """
        Raise ValueError if any required field is missing, empty, or wrong type.

        Called by the scheduler before accepting events from collectors.
        Ensures malformed collector output is surfaced, not silently passed.
        """
        for fname in _REQUIRED_STRING_FIELDS:
            val = getattr(self, fname)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(
                    f"CollectorEvent.{fname} must be a non-empty string; got {val!r}"
                )
        if not isinstance(self.payload, dict):
            raise ValueError(
                f"CollectorEvent.payload must be a dict; got {type(self.payload).__name__}"
            )


class Collector(abc.ABC):
    """
    Abstract base class for all supported collectors.

    Subclasses MUST implement:
        name            — stable unique identifier (str property)
        cadence_seconds — minimum interval between runs (float property)
        collect()       — returns list[CollectorEvent]

    Contract:
        - name must be a non-empty, stable string that does not change at runtime.
        - cadence_seconds must be > 0.
        - collect() receives tenant_id and agent_id explicitly; must not infer
          them from global mutable state.
        - Every returned CollectorEvent must include the provided tenant_id and
          agent_id; the scheduler validates this via CollectorEvent.validate().
        - collect() should not swallow exceptions that indicate structural failure.
          Transient environment failures should propagate so the scheduler can
          record them as 'failed' and surface the error.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Stable unique name for this collector (e.g. 'heartbeat', 'inventory')."""

    @property
    @abc.abstractmethod
    def cadence_seconds(self) -> float:
        """Minimum interval between collections, in seconds. Must be > 0."""

    @abc.abstractmethod
    def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
        """
        Execute the collection for the given tenant and agent.

        Args:
            tenant_id: Tenant that owns the collected data. Must be non-empty.
            agent_id:  Agent performing the collection. Must be non-empty.

        Returns:
            List of CollectorEvent instances.  May be empty if nothing to report.
            Each event's tenant_id and agent_id must match the arguments.

        Raises:
            Any exception on unrecoverable collection failure.
            The scheduler will catch and record it; callers should not swallow.
        """
