"""
agent.app.collector.process_inventory — Host inventory snapshot collector.

Collects platform/OS metadata once per cadence cycle and emits a single
CollectorEvent of type "inventory.process_snapshot".

Design invariants:
- Snapshot provider is injectable; tests never depend on live host state.
- Hostname is hashed (sha256 prefix) — raw hostname is not emitted.
- No command lines, env vars, secrets, tokens, or process-owner info emitted.
- Missing tenant/agent context fails explicitly via CollectorEvent.validate().
- Collector exceptions propagate; no broad except/pass.
- Empty snapshot is distinguishable from collector failure (empty dict ≠ exception).
"""

from __future__ import annotations

import hashlib
import os
import platform
from datetime import datetime, timezone
from typing import Any, Callable

from agent.app.collector.base import Collector, CollectorEvent

# Stable collector identity.
COLLECTOR_NAME: str = "process_inventory"
EVENT_TYPE: str = "inventory.process_snapshot"
PAYLOAD_SCHEMA_VERSION: str = "1.0"

# Default collection cadence: 5 minutes.
DEFAULT_CADENCE_SECONDS: float = 300.0

# Type alias for the injected snapshot provider.
SnapshotProvider = Callable[[], dict[str, Any]]


def _default_snapshot() -> dict[str, Any]:
    """
    Collect host inventory metadata using stdlib only.

    Sensitive data minimization:
    - Hostname is SHA-256 hashed (16 hex chars); raw hostname is NOT emitted.
    - No process list, command lines, env vars, secrets, or user identities.
    - cpu_count may be None on some platforms; normalized to 0.
    """
    raw_hostname = platform.node()
    hostname_hash = hashlib.sha256(raw_hostname.encode("utf-8")).hexdigest()[:16]
    return {
        "schema_version": PAYLOAD_SCHEMA_VERSION,
        "platform": platform.system().lower(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "hostname_hash": hostname_hash,
        "cpu_count": os.cpu_count() or 0,
    }


class ProcessInventoryCollector(Collector):
    """
    Collector that emits a host inventory snapshot on each cadence cycle.

    The snapshot provider is injectable for deterministic testing.
    The default provider uses stdlib platform/os; no third-party deps required.

    Tenant-safety guarantees:
    - tenant_id and agent_id are passed explicitly by the scheduler.
    - No global mutable tenant/agent state.
    - CollectorEvent.validate() enforces non-empty tenant_id and agent_id before
      the event is accepted by the scheduler.

    Sensitive data minimization:
    - Hostname is SHA-256 hashed; raw hostname is never emitted.
    - No command lines, env vars, secrets, tokens, or process-owner info.

    Failure behavior:
    - Exceptions from the snapshot provider propagate; they are not swallowed.
    - The scheduler catches them and records outcome='failed'.
    - Empty snapshot (empty dict) is valid and produces outcome='ran' with
      empty payload — distinguishable from exception-based failure.
    """

    def __init__(
        self,
        cadence_seconds: float = DEFAULT_CADENCE_SECONDS,
        snapshot_provider: SnapshotProvider | None = None,
    ) -> None:
        self._cadence = cadence_seconds
        self._provider: SnapshotProvider = (
            snapshot_provider if snapshot_provider is not None else _default_snapshot
        )

    @property
    def name(self) -> str:
        return COLLECTOR_NAME

    @property
    def cadence_seconds(self) -> float:
        return self._cadence

    def collect(self, tenant_id: str, agent_id: str) -> list[CollectorEvent]:
        """
        Execute one inventory snapshot collection.

        Args:
            tenant_id: Tenant that owns this event. Must be non-empty.
            agent_id:  Agent performing the collection. Must be non-empty.

        Returns:
            A single-element list containing the inventory CollectorEvent.

        Raises:
            Any exception raised by the snapshot provider propagates here.
            The caller (scheduler) catches and records it as outcome='failed'.
        """
        snapshot = self._provider()
        return [
            CollectorEvent(
                collector_name=COLLECTOR_NAME,
                event_type=EVENT_TYPE,
                tenant_id=tenant_id,
                agent_id=agent_id,
                occurred_at=datetime.now(timezone.utc).isoformat(),
                payload=snapshot,
            )
        ]
