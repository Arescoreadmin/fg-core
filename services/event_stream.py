"""
FrostGate Control Plane - Event Stream Service

Real-time event streaming for control plane observability.

Provides:
- In-process pub/sub event bus
- WebSocket fan-out to subscribed clients
- Dual event identity: content_hash (dedupe) + event_instance_id (anti-replay)
- Tenant-safe: clients only receive events for their tenant
- Typed event catalog with structured payloads
- No fail-open: closed connections are cleaned up immediately

P0: event_instance_id (unique per publish, ULID-style) for anti-replay.
    content_hash (deterministic SHA-256) for deduplication. Both kept.
P1: Max subscribers per tenant enforced. Backpressure: consecutive queue-full
    events trigger slow-consumer disconnect.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
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
ERR_MAX_SUBSCRIBERS = "CP-EVT-003"


# ---------------------------------------------------------------------------
# Limits (configurable via env)
# ---------------------------------------------------------------------------

def _max_subscribers_per_tenant() -> int:
    return int(os.getenv("FG_CP_MAX_SUBSCRIBERS_PER_TENANT", "10"))


def _slow_consumer_drop_threshold() -> int:
    """Number of consecutive queue-full drops before disconnecting subscriber."""
    return int(os.getenv("FG_CP_SLOW_CONSUMER_DROP_THRESHOLD", "5"))


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
# Exception for subscriber cap exceeded
# ---------------------------------------------------------------------------

class MaxSubscribersExceededError(Exception):
    """
    Raised by EventStreamBus.subscribe() when a tenant has reached the
    maximum concurrent subscriber limit (FG_CP_MAX_SUBSCRIBERS_PER_TENANT).
    """
    pass


# ---------------------------------------------------------------------------
# Instance ID generation (P0: unique per publish, anti-replay)
# ---------------------------------------------------------------------------

_seq_lock = threading.Lock()
_seq_counter: int = 0


def _next_seq() -> int:
    global _seq_counter
    with _seq_lock:
        _seq_counter += 1
        return _seq_counter


def _generate_instance_id(content_hash: str) -> str:
    """
    Generate a unique-per-publish event instance ID.

    Structure: evti-{ts_ms_hex}-{seq_hex}-{content_prefix}
      - ts_ms_hex: millisecond timestamp (13 hex chars, sortable)
      - seq_hex:   monotonic in-process sequence (6 hex chars, unique within ms)
      - content_prefix: first 8 chars of content_hash (links to content for debug)

    This is NOT a HMAC (no shared secret required at this layer). The content_hash
    field provides integrity; the instance_id provides uniqueness and anti-replay.
    """
    ts_ms = int(time.time() * 1000)
    seq = _next_seq()
    return f"evti-{ts_ms:013x}-{seq:06x}-{content_hash[:8]}"


# ---------------------------------------------------------------------------
# Event structure
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlEvent:
    """
    An immutable control plane event.

    P0 Dual identity:
      - event_id (content_hash):  SHA-256 of {type}:{module}:{tenant}:{ts}
                                  Deterministic; use for deduplication.
      - event_instance_id:        Unique per publish (ts + seq + content prefix).
                                  Use for anti-replay and downstream ingestion.
    """
    event_type: ControlEventType
    module_id: str
    tenant_id: str
    payload: Dict[str, Any]

    # Computed in __post_init__ — frozen so we use object.__setattr__
    event_id: str = field(default="")          # content_hash (deterministic)
    event_instance_id: str = field(default="") # unique per publish (anti-replay)
    timestamp: str = field(default="")

    def __post_init__(self) -> None:
        ts = _utc_now_iso()
        content_hash = _deterministic_event_id(
            event_type=self.event_type.value,
            module_id=self.module_id,
            tenant_id=self.tenant_id,
            timestamp=ts,
        )
        instance_id = _generate_instance_id(content_hash)
        object.__setattr__(self, "timestamp", ts)
        object.__setattr__(self, "event_id", content_hash)
        object.__setattr__(self, "event_instance_id", instance_id)

    def to_dict(self, redact_tenant: bool = False) -> dict:
        return {
            "event_id": self.event_id,               # content hash (dedupe)
            "event_instance_id": self.event_instance_id,  # unique per publish
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
    """
    Compute deterministic content-addressed event ID (SHA-256).
    Use for deduplication; NOT for uniqueness (two identical events share this hash).
    """
    raw = f"{event_type}:{module_id}:{tenant_id}:{timestamp}"
    return "evt-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Subscriber
# ---------------------------------------------------------------------------

class EventSubscriber:
    """
    A single WebSocket subscriber.
    Receives events via asyncio.Queue, filtered by tenant_id.

    P1 Backpressure: tracks consecutive queue-full drops. After
    FG_CP_SLOW_CONSUMER_DROP_THRESHOLD consecutive drops, the subscriber
    is automatically closed (slow consumer disconnect).
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
        self._consecutive_drops: int = 0  # P1 backpressure counter

    def is_closed(self) -> bool:
        return self._closed.is_set()

    def close(self) -> None:
        self._closed.set()

    def matches(self, event: ControlEvent) -> bool:
        """Check if subscriber should receive this event."""
        if self.is_closed():
            return False
        # P0 Tenant binding: only receive own-tenant events (or global)
        if event.tenant_id not in (self.tenant_id, "global"):
            return False
        # Event type filter
        if self.event_types and event.event_type.value not in self.event_types:
            return False
        return True

    def try_put(self, event: ControlEvent) -> bool:
        """
        Non-blocking put. Returns False if queue full or closed.

        P1 Backpressure: after _slow_consumer_drop_threshold() consecutive
        queue-full failures, marks this subscriber as closed (disconnect).
        """
        if self.is_closed():
            return False
        try:
            self._queue.put_nowait(event)
            self._consecutive_drops = 0  # reset on success
            return True
        except asyncio.QueueFull:
            self._consecutive_drops += 1
            threshold = _slow_consumer_drop_threshold()
            if self._consecutive_drops >= threshold:
                log.warning(
                    "slow_consumer_disconnect sub=%s tenant=%s "
                    "consecutive_drops=%d >= threshold=%d",
                    self.subscriber_id,
                    self.tenant_id,
                    self._consecutive_drops,
                    threshold,
                )
                self.close()
            else:
                log.warning(
                    "event_queue_full sub=%s tenant=%s drop=%d/%d event=%s",
                    self.subscriber_id,
                    self.tenant_id,
                    self._consecutive_drops,
                    threshold,
                    event.event_instance_id,
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

    P0: Both content_hash (event_id) and event_instance_id are set on publish.
    P1: Per-tenant subscriber cap enforced. Slow consumers disconnected.
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
                    subscriber.try_put(event)
                    if subscriber.is_closed():
                        # Slow consumer disconnect triggered by try_put
                        closed.append(sub_id)

            # Clean up closed subscribers
            for sub_id in closed:
                sub = self._subscribers.pop(sub_id, None)
                if sub:
                    sub.close()

        log.debug(
            "event_published type=%s module=%s tenant=%s id=%s instance=%s",
            event.event_type.value,
            event.module_id,
            event.tenant_id,
            event.event_id,
            event.event_instance_id,
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
        """
        Create a new subscriber for the given tenant.

        P1: Raises MaxSubscribersExceededError if tenant has reached
        FG_CP_MAX_SUBSCRIBERS_PER_TENANT concurrent subscribers.
        Caller (WS endpoint) must close the connection with 4029.
        """
        with self._lock:
            # P1: Per-tenant subscriber cap
            tenant_count = sum(
                1
                for s in self._subscribers.values()
                if s.tenant_id == tenant_id and not s.is_closed()
            )
            max_subs = _max_subscribers_per_tenant()
            if tenant_count >= max_subs:
                log.warning(
                    "max_subscribers_exceeded tenant=%s count=%d limit=%d",
                    tenant_id,
                    tenant_count,
                    max_subs,
                )
                raise MaxSubscribersExceededError(
                    f"tenant {tenant_id!r} has reached the max of {max_subs} "
                    "concurrent event subscribers"
                )

            sub = EventSubscriber(
                subscriber_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                event_types=event_types,
                queue_size=queue_size,
            )
            self._subscribers[sub.subscriber_id] = sub

        log.info(
            "event_subscriber_added sub_id=%s tenant=%s total_for_tenant=%d",
            sub.subscriber_id,
            tenant_id,
            tenant_count + 1,
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
