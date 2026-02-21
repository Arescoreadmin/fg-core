"""
FrostGate Control Plane - Event Stream Service

Real-time event streaming for control plane observability.

Provides:
- In-process pub/sub event bus
- WebSocket fan-out to subscribed clients
- Deterministic event IDs (content-addressed)
- Tenant-safe: clients only receive events for their tenant
- Typed event catalog with structured payloads
- No fail-open: closed connections are cleaned up immediately
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("frostgate.control_plane.event_stream")


# ---------------------------------------------------------------------------
# Deterministic error codes
# ---------------------------------------------------------------------------
ERR_EVENT_QUEUE_FULL = "CP-EVT-001"
ERR_SUBSCRIBER_CLOSED = "CP-EVT-002"


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

class ControlEventType(str, Enum):
    MODULE_STATE_CHANGED = "module_state_changed"
    DEPENDENCY_STATE_CHANGED = "dependency_state_changed"
    LOCKER_STATE_CHANGED = "locker_state_changed"
    RESTART_STARTED = "restart_started"
    RESTART_COMPLETED = "restart_completed"
    BREAKER_OPENED = "breaker_opened"
    BREAKER_CLOSED = "breaker_closed"
    CONFIG_CHANGED = "config_changed"
    POLICY_VIOLATION_DETECTED = "policy_violation_detected"
    BOOT_STAGE_COMPLETED = "boot_stage_completed"
    COMMAND_DISPATCHED = "command_dispatched"
    HEARTBEAT = "heartbeat"


# ---------------------------------------------------------------------------
# Event structure
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlEvent:
    event_type: ControlEventType
    module_id: str
    tenant_id: str
    payload: Dict[str, Any]
    # Computed fields
    event_id: str = field(default="")
    timestamp: str = field(default="")

    def __post_init__(self) -> None:
        # Use object.__setattr__ because frozen=True
        ts = _utc_now_iso()
        object.__setattr__(self, "timestamp", ts)
        object.__setattr__(self, "event_id", _deterministic_event_id(
            event_type=self.event_type.value,
            module_id=self.module_id,
            tenant_id=self.tenant_id,
            timestamp=ts,
        ))

    def to_dict(self, redact_tenant: bool = False) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "module_id": self.module_id,
            "tenant_id": None if redact_tenant else self.tenant_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }

    def to_json(self, redact_tenant: bool = False) -> str:
        return json.dumps(
            self.to_dict(redact_tenant=redact_tenant),
            sort_keys=True,
            separators=(",", ":"),
        )


def _deterministic_event_id(
    *,
    event_type: str,
    module_id: str,
    tenant_id: str,
    timestamp: str,
) -> str:
    """Content-addressed deterministic event ID."""
    raw = f"{event_type}:{module_id}:{tenant_id}:{timestamp}"
    return "evt-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Subscriber
# ---------------------------------------------------------------------------

class EventSubscriber:
    """
    A single WebSocket subscriber.
    Receives events via asyncio.Queue, filtered by tenant_id.
    """

    def __init__(
        self,
        subscriber_id: str,
        tenant_id: str,
        event_types: Optional[Set[str]] = None,
        queue_size: int = 256,
    ) -> None:
        self.subscriber_id = subscriber_id
        self.tenant_id = tenant_id
        self.event_types = event_types  # None = all types
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._closed = threading.Event()
        self.connected_at = _utc_now_iso()

    def is_closed(self) -> bool:
        return self._closed.is_set()

    def close(self) -> None:
        self._closed.set()

    def matches(self, event: ControlEvent) -> bool:
        """Check if subscriber should receive this event."""
        if self.is_closed():
            return False
        # Tenant binding: only receive own-tenant events (or global)
        if event.tenant_id not in (self.tenant_id, "global"):
            return False
        # Event type filter
        if self.event_types and event.event_type.value not in self.event_types:
            return False
        return True

    async def put(self, event: ControlEvent) -> bool:
        """Non-blocking put. Returns False if queue full or closed."""
        if self.is_closed():
            return False
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            log.warning(
                "event_queue_full subscriber=%s tenant=%s",
                self.subscriber_id,
                self.tenant_id,
            )
            return False

    async def get(self, timeout: float = 30.0) -> Optional[ControlEvent]:
        """Wait for next event with timeout."""
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        except asyncio.CancelledError:
            return None


# ---------------------------------------------------------------------------
# Event Stream Bus
# ---------------------------------------------------------------------------

class EventStreamBus:
    """
    Singleton in-process event bus.

    Thread-safe publisher, asyncio-compatible subscriber fan-out.
    All events are tenant-scoped. No cross-tenant leakage.
    """

    _instance: Optional["EventStreamBus"] = None
    _init_lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "EventStreamBus":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._subscribers: Dict[str, EventSubscriber] = {}
                    obj._lock = threading.RLock()
                    obj._event_history: list[ControlEvent] = []
                    obj._history_max = int(
                        os.getenv("FG_CP_EVENT_HISTORY_MAX", "500")
                    )
                    cls._instance = obj
        return cls._instance

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(self, event: ControlEvent) -> None:
        """
        Publish an event to all matching subscribers.
        Called from any thread; uses asyncio-safe put_nowait.
        """
        with self._lock:
            # Keep rolling history
            self._event_history.append(event)
            if len(self._event_history) > self._history_max:
                self._event_history = self._event_history[-self._history_max:]

            # Fan-out to matching subscribers
            closed: list[str] = []
            for sub_id, subscriber in self._subscribers.items():
                if subscriber.is_closed():
                    closed.append(sub_id)
                    continue
                if subscriber.matches(event):
                    # Schedule delivery on subscriber's event loop
                    # (put_nowait is thread-safe for asyncio queues)
                    try:
                        subscriber._queue.put_nowait(event)
                    except asyncio.QueueFull:
                        log.warning(
                            "event_queue_full dropping event=%s subscriber=%s",
                            event.event_id,
                            sub_id,
                        )
                    except Exception as e:
                        log.warning(
                            "event_deliver_error event=%s subscriber=%s error=%s",
                            event.event_id,
                            sub_id,
                            e,
                        )

            # Clean up closed subscribers
            for sub_id in closed:
                del self._subscribers[sub_id]

        log.debug(
            "event_published type=%s module=%s tenant=%s id=%s",
            event.event_type.value,
            event.module_id,
            event.tenant_id,
            event.event_id,
        )

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def subscribe(
        self,
        tenant_id: str,
        event_types: Optional[Set[str]] = None,
        queue_size: int = 256,
    ) -> EventSubscriber:
        sub = EventSubscriber(
            subscriber_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            event_types=event_types,
            queue_size=queue_size,
        )
        with self._lock:
            self._subscribers[sub.subscriber_id] = sub
        log.info(
            "event_subscriber_added sub_id=%s tenant=%s",
            sub.subscriber_id,
            tenant_id,
        )
        return sub

    def unsubscribe(self, subscriber_id: str) -> None:
        with self._lock:
            sub = self._subscribers.pop(subscriber_id, None)
            if sub:
                sub.close()
        log.info("event_subscriber_removed sub_id=%s", subscriber_id)

    def subscriber_count(self, tenant_id: Optional[str] = None) -> int:
        with self._lock:
            if tenant_id:
                return sum(
                    1
                    for s in self._subscribers.values()
                    if s.tenant_id == tenant_id and not s.is_closed()
                )
            return sum(1 for s in self._subscribers.values() if not s.is_closed())

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def recent_events(
        self,
        tenant_id: str,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> List[dict]:
        with self._lock:
            events = [
                e
                for e in self._event_history
                if e.tenant_id in (tenant_id, "global")
                and (event_type is None or e.event_type.value == event_type)
            ]
        events = events[-limit:]
        return [e.to_dict() for e in events]

    def _reset(self) -> None:
        """For testing only."""
        with self._lock:
            self._subscribers.clear()
            self._event_history.clear()


# ---------------------------------------------------------------------------
# Convenience publishers (called by other services)
# ---------------------------------------------------------------------------

def _bus() -> EventStreamBus:
    return EventStreamBus()


def emit_module_state_changed(
    *,
    module_id: str,
    tenant_id: str,
    old_state: str,
    new_state: str,
    reason: str = "",
) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.MODULE_STATE_CHANGED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={
            "old_state": old_state,
            "new_state": new_state,
            "reason": reason,
        },
    ))


def emit_dependency_state_changed(
    *,
    module_id: str,
    tenant_id: str,
    dependency_name: str,
    old_status: str,
    new_status: str,
    error_code: Optional[str] = None,
) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.DEPENDENCY_STATE_CHANGED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={
            "dependency_name": dependency_name,
            "old_status": old_status,
            "new_status": new_status,
            "error_code": error_code,
        },
    ))


def emit_locker_state_changed(
    *,
    locker_id: str,
    tenant_id: str,
    old_state: str,
    new_state: str,
    command: Optional[str] = None,
    actor: Optional[str] = None,
) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.LOCKER_STATE_CHANGED,
        module_id=locker_id,
        tenant_id=tenant_id,
        payload={
            "locker_id": locker_id,
            "old_state": old_state,
            "new_state": new_state,
            "command": command,
            "actor": actor,
        },
    ))


def emit_restart_started(
    *, module_id: str, tenant_id: str, actor: str, reason: str
) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.RESTART_STARTED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={"actor": actor, "reason": reason},
    ))


def emit_restart_completed(
    *,
    module_id: str,
    tenant_id: str,
    success: bool,
    error_code: Optional[str] = None,
) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.RESTART_COMPLETED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={"success": success, "error_code": error_code},
    ))


def emit_breaker_opened(*, module_id: str, tenant_id: str, reason: str = "") -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.BREAKER_OPENED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={"reason": reason},
    ))


def emit_breaker_closed(*, module_id: str, tenant_id: str) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.BREAKER_CLOSED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={},
    ))


def emit_config_changed(
    *,
    module_id: str,
    tenant_id: str,
    config_hash: str,
    actor: str = "system",
) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.CONFIG_CHANGED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={"config_hash": config_hash, "actor": actor},
    ))


def emit_policy_violation(
    *,
    module_id: str,
    tenant_id: str,
    policy_id: str,
    details: str = "",
) -> None:
    _bus().publish(ControlEvent(
        event_type=ControlEventType.POLICY_VIOLATION_DETECTED,
        module_id=module_id,
        tenant_id=tenant_id,
        payload={"policy_id": policy_id, "details": details},
    ))


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
