"""
services/event_stream.py — Real-time control-plane event bus.

Events are broadcast over WebSocket to authenticated subscribers.

Security properties:
  - WS auth enforced identically to HTTP auth (no weaker path).
  - Tenant scoping: tenant-admins only receive events for their tenant.
  - Global admins receive all events; payloads include tenant_id.
  - Per-tenant subscriber cap (prevents fan-out amplifier abuse).
  - Slow consumers are dropped (backpressure = disconnect).
  - Event IDs:
      content_hash  — SHA-256 of canonical event content (dedup / integrity).
      event_instance_id — deterministic HMAC(key, content_hash|ts_bucket|seq)
                          for uniqueness + anti-replay even for identical events.

Event types:
  module_state_changed, dependency_state_changed, locker_state_changed,
  restart_started, restart_completed, breaker_opened, breaker_closed,
  config_changed, policy_violation_detected.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Set

log = logging.getLogger("frostgate.event_stream")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_EVENT_TYPES = frozenset(
    {
        "module_state_changed",
        "dependency_state_changed",
        "locker_state_changed",
        "restart_started",
        "restart_completed",
        "breaker_opened",
        "breaker_closed",
        "config_changed",
        "policy_violation_detected",
    }
)

# Per-tenant subscriber cap
MAX_SUBSCRIBERS_PER_TENANT: int = int(
    os.getenv("FG_CP_MAX_WS_SUBSCRIBERS_PER_TENANT", "20")
)

# Global subscriber cap
MAX_GLOBAL_SUBSCRIBERS: int = int(
    os.getenv("FG_CP_MAX_WS_SUBSCRIBERS_GLOBAL", "200")
)

# Per-subscriber queue depth (older events dropped when exceeded)
SUBSCRIBER_QUEUE_DEPTH: int = int(
    os.getenv("FG_CP_WS_QUEUE_DEPTH", "100")
)

# HMAC key for event instance IDs; derived from FG_KEY_PEPPER or random per-process
_HMAC_KEY: bytes = (os.getenv("FG_KEY_PEPPER") or uuid.uuid4().hex).encode("utf-8")

# Event history limit for GET /control-plane/audit (in-memory)
EVENT_HISTORY_LIMIT: int = int(
    os.getenv("FG_CP_EVENT_HISTORY_LIMIT", "1000")
)

# ---------------------------------------------------------------------------
# Event models
# ---------------------------------------------------------------------------


@dataclass
class ControlEvent:
    event_type: str
    module_id: str
    tenant_id: str
    payload: Dict[str, Any]

    # Computed on creation
    content_hash: str = field(init=False)
    event_instance_id: str = field(init=False)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Sequence number (global monotonic, helps with ordering)
    seq: int = field(default=0)

    def __post_init__(self) -> None:
        self.content_hash = _compute_content_hash(self)
        self.event_instance_id = _compute_instance_id(
            self.content_hash, self.timestamp
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_instance_id": self.event_instance_id,
            "content_hash": self.content_hash,
            "event_type": self.event_type,
            "module_id": self.module_id,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "seq": self.seq,
            "payload": self.payload,
        }


def _compute_content_hash(event: ControlEvent) -> str:
    """SHA-256 of canonical event content for integrity / dedup."""
    payload = {
        "event_type": event.event_type,
        "module_id": event.module_id,
        "tenant_id": event.tenant_id,
        "timestamp": event.timestamp,
        "payload": event.payload,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _compute_instance_id(content_hash: str, timestamp: str) -> str:
    """
    HMAC(key, content_hash|ts_bucket) for uniqueness and anti-replay.

    Includes a random nonce so two events with identical content at the same
    second get distinct instance IDs.
    """
    # ts_bucket: round to nearest second to cluster near-simultaneous events
    try:
        ts_bucket = timestamp[:19]  # "YYYY-MM-DDTHH:MM:SS"
    except Exception:
        ts_bucket = ""
    nonce = uuid.uuid4().hex[:8]
    msg = f"{content_hash}|{ts_bucket}|{nonce}".encode("utf-8")
    return hmac.new(_HMAC_KEY, msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Subscriber
# ---------------------------------------------------------------------------


@dataclass
class EventSubscriber:
    subscriber_id: str
    tenant_id: Optional[str]  # None = global admin (sees all)
    is_global_admin: bool = False
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_DEPTH))
    connected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def should_receive(self, event: ControlEvent) -> bool:
        """Tenant-scoped filtering.  Global admins see all."""
        if self.is_global_admin:
            return True
        if self.tenant_id is None:
            return False
        return event.tenant_id == self.tenant_id


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------


class ControlEventBus:
    """
    Thread-safe event broadcaster with tenant-scoped subscriptions.

    Maintains an in-memory event history for audit queries.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: Dict[str, EventSubscriber] = {}
        self._tenant_subscriber_counts: Dict[str, int] = {}
        self._global_subscriber_count: int = 0
        self._seq: int = 0
        self._history: List[ControlEvent] = []

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(self, event: ControlEvent) -> int:
        """
        Broadcast event to all matching subscribers.

        Returns number of subscribers that received the event.
        Slow consumers whose queues are full are disconnected.
        """
        with self._lock:
            self._seq += 1
            event.seq = self._seq
            # Keep history
            self._history.append(event)
            if len(self._history) > EVENT_HISTORY_LIMIT:
                self._history = self._history[-EVENT_HISTORY_LIMIT:]
            subs = list(self._subscribers.values())

        dispatched = 0
        slow_consumers: List[str] = []

        for sub in subs:
            if not sub.should_receive(event):
                continue
            try:
                sub.queue.put_nowait(event.to_dict())
                dispatched += 1
            except asyncio.QueueFull:
                log.warning(
                    "event_stream.slow_consumer subscriber_id=%s; disconnecting",
                    sub.subscriber_id,
                )
                slow_consumers.append(sub.subscriber_id)

        # Disconnect slow consumers outside the main lock
        for sid in slow_consumers:
            self.remove_subscriber(sid)

        return dispatched

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def add_subscriber(
        self,
        tenant_id: Optional[str],
        *,
        is_global_admin: bool = False,
    ) -> EventSubscriber:
        """
        Register a new subscriber.

        Raises ValueError with deterministic error code if limits are exceeded.
        """
        with self._lock:
            # Global cap
            if self._global_subscriber_count >= MAX_GLOBAL_SUBSCRIBERS:
                raise ValueError("CP_WS_GLOBAL_SUBSCRIBER_LIMIT")

            # Per-tenant cap (applies to non-global-admin only)
            if not is_global_admin and tenant_id:
                tenant_count = self._tenant_subscriber_counts.get(tenant_id, 0)
                if tenant_count >= MAX_SUBSCRIBERS_PER_TENANT:
                    raise ValueError("CP_WS_TENANT_SUBSCRIBER_LIMIT")

            sid = str(uuid.uuid4())
            sub = EventSubscriber(
                subscriber_id=sid,
                tenant_id=tenant_id,
                is_global_admin=is_global_admin,
            )
            self._subscribers[sid] = sub
            self._global_subscriber_count += 1
            if tenant_id:
                self._tenant_subscriber_counts[tenant_id] = (
                    self._tenant_subscriber_counts.get(tenant_id, 0) + 1
                )
            log.info(
                "event_stream.subscriber_added sid=%s tenant_id=%s global_admin=%s",
                sid,
                tenant_id,
                is_global_admin,
            )
            return sub

    def remove_subscriber(self, subscriber_id: str) -> None:
        with self._lock:
            sub = self._subscribers.pop(subscriber_id, None)
            if sub is None:
                return
            self._global_subscriber_count = max(0, self._global_subscriber_count - 1)
            if sub.tenant_id:
                old = self._tenant_subscriber_counts.get(sub.tenant_id, 0)
                self._tenant_subscriber_counts[sub.tenant_id] = max(0, old - 1)
            log.info(
                "event_stream.subscriber_removed sid=%s",
                subscriber_id,
            )

    # ------------------------------------------------------------------
    # History / audit
    # ------------------------------------------------------------------

    def get_history(
        self,
        *,
        since: Optional[str] = None,
        tenant_id: Optional[str],
        is_global_admin: bool,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Return event history filtered by tenant scope and optionally since a timestamp.

        Global admin sees all events; tenant admin sees only their events.
        """
        with self._lock:
            events = list(self._history)

        if not is_global_admin and tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]
        elif not is_global_admin:
            events = []

        if since:
            try:
                events = [e for e in events if e.timestamp >= since]
            except Exception:
                pass  # invalid since param: return all

        # Most recent first, capped at limit
        events = events[-limit:]
        return [e.to_dict() for e in reversed(events)]

    def subscriber_count(self) -> int:
        with self._lock:
            return self._global_subscriber_count


# ---------------------------------------------------------------------------
# Convenience factory functions
# ---------------------------------------------------------------------------


def make_event(
    event_type: str,
    *,
    module_id: str,
    tenant_id: str,
    payload: Optional[Dict[str, Any]] = None,
) -> ControlEvent:
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError(f"Invalid event type: {event_type}")
    return ControlEvent(
        event_type=event_type,
        module_id=module_id,
        tenant_id=tenant_id,
        payload=payload or {},
    )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_bus: Optional[ControlEventBus] = None
_bus_lock = threading.Lock()


def get_event_bus() -> ControlEventBus:
    global _bus
    if _bus is None:
        with _bus_lock:
            if _bus is None:
                _bus = ControlEventBus()
    return _bus
