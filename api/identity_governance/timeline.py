"""api/identity_governance/timeline.py — Hash-chained identity event timeline.

In-memory Phase 1 implementation. Events are immutable and stored in a
list; every event carries the SHA-256 hash of the previous event's
``event_hash`` in ``previous_hash``. This gives forward-only tamper
evidence identical in shape to ``api.identity_authority.audit`` so the
timeline can be persisted later with the same guarantees.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional

from api.identity_governance.models import (
    IdentityTimelineEvent,
    IdentityTimelineEventType,
)


def _sha256(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode())
        h.update(b"|")
    return h.hexdigest()


_REDACTED_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "key",
    "authorization",
    "cookie",
    "credential",
    "private",
    "session",
)


def _is_secret_key(k: str) -> bool:
    """Return True if the key name contains any secret-shaped substring."""
    lower = k.lower()
    return any(sub in lower for sub in _REDACTED_SUBSTRINGS)


def _sanitize_details(details: dict[str, object]) -> tuple[tuple[str, str], ...]:
    """Sort details deterministically and redact secret-shaped keys."""
    items: list[tuple[str, str]] = []
    for k in sorted(details.keys()):
        v = details[k]
        if _is_secret_key(k):
            items.append((k, "[REDACTED]"))
        else:
            items.append((k, str(v)))
    return tuple(items)


class IdentityTimeline:
    """In-memory, hash-chained identity event timeline.

    A single ``IdentityTimeline`` instance represents one chain. Multiple
    tenants share the chain — the chain is over event ordering, not
    tenant isolation. Cross-tenant queries are rejected by the query API.
    """

    def __init__(self) -> None:
        self._events: list[IdentityTimelineEvent] = []
        self._prev_hash: str = "genesis"
        self._lock = threading.Lock()

    def emit(
        self,
        event_type: IdentityTimelineEventType,
        subject: str,
        tenant_id: str,
        actor: str,
        details: Optional[dict[str, object]] = None,
        correlation_id: Optional[str] = None,
    ) -> IdentityTimelineEvent:
        """Append a new event to the chain and return it."""
        if not subject:
            raise ValueError("subject is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not actor:
            raise ValueError("actor is required")

        event_id = secrets.token_hex(16)
        now = datetime.now(tz=timezone.utc)
        safe_details = _sanitize_details(details or {})

        with self._lock:
            prev = self._prev_hash
            event_hash = _sha256(
                prev,
                event_id,
                event_type.value,
                subject,
                tenant_id,
                actor,
                now.isoformat(),
                *(f"{k}={v}" for k, v in safe_details),
            )
            event = IdentityTimelineEvent(
                event_id=event_id,
                event_type=event_type,
                subject=subject,
                tenant_id=tenant_id,
                actor=actor,
                occurred_at=now,
                details=safe_details,
                correlation_id=correlation_id,
                previous_hash=prev,
                event_hash=event_hash,
            )
            self._events.append(event)
            self._prev_hash = event_hash
            return event

    def query(
        self,
        tenant_id: str,
        subject: Optional[str] = None,
        event_types: Optional[list[IdentityTimelineEventType]] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[IdentityTimelineEvent]:
        """Return events matching the filter. Tenant-scoped.

        Results preserve chronological insertion order and are capped at
        ``limit`` from the tail (most-recent events).
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")
        type_set = set(event_types) if event_types else None
        with self._lock:
            candidates = [e for e in self._events if e.tenant_id == tenant_id]
        if subject is not None:
            candidates = [e for e in candidates if e.subject == subject]
        if type_set is not None:
            candidates = [e for e in candidates if e.event_type in type_set]
        if since is not None:
            candidates = [e for e in candidates if e.occurred_at >= since]
        if until is not None:
            candidates = [e for e in candidates if e.occurred_at <= until]
        if limit <= 0:
            return []
        return candidates[-limit:]

    def verify_chain(self) -> bool:
        """Recompute the hash chain from genesis and return True if intact."""
        prev = "genesis"
        with self._lock:
            for e in self._events:
                if e.previous_hash != prev:
                    return False
                expected = _sha256(
                    prev,
                    e.event_id,
                    e.event_type.value,
                    e.subject,
                    e.tenant_id,
                    e.actor,
                    e.occurred_at.isoformat(),
                    *(f"{k}={v}" for k, v in e.details),
                )
                if e.event_hash != expected:
                    return False
                prev = e.event_hash
        return True
