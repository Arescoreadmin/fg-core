"""api/identity_governance/repositories/memory.py — In-memory repositories.

Default repository backend. Data lives in per-instance dicts guarded by a
lock so tests (or an unconfigured deployment) can use governance services
without a database.

Every repository is tenant-scoped by construction: keys are
``(tenant_id, id)`` tuples so cross-tenant lookups return ``None`` even
when the id collides between tenants.
"""

from __future__ import annotations

import threading
from typing import Optional

from api.identity_governance.models import (
    BreakGlassRequest,
    BreakGlassStatus,
    DeviceRecord,
    IdentityLifecycleRecord,
    IdentityTimelineEvent,
)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class InMemoryLifecycleRepository:
    """In-memory repository for lifecycle transition records."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], IdentityLifecycleRecord] = {}
        self._by_subject: dict[tuple[str, str], list[IdentityLifecycleRecord]] = {}
        self._lock = threading.Lock()

    def create(self, record: IdentityLifecycleRecord) -> IdentityLifecycleRecord:
        if not record.tenant_id:
            raise ValueError("tenant_id is required")
        key = (record.tenant_id, record.record_id)
        skey = (record.tenant_id, record.subject)
        with self._lock:
            self._records[key] = record
            self._by_subject.setdefault(skey, []).append(record)
        return record

    def get(self, tenant_id: str, record_id: str) -> Optional[IdentityLifecycleRecord]:
        with self._lock:
            return self._records.get((tenant_id, record_id))

    def list_for_subject(
        self, tenant_id: str, subject: str, limit: int = 100
    ) -> list[IdentityLifecycleRecord]:
        with self._lock:
            events = list(self._by_subject.get((tenant_id, subject), []))
        if limit <= 0:
            return []
        return events[-limit:]


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


class InMemoryDeviceRepository:
    """In-memory repository for device trust records."""

    def __init__(self) -> None:
        self._devices: dict[tuple[str, str], DeviceRecord] = {}
        self._lock = threading.Lock()

    def upsert(self, record: DeviceRecord) -> DeviceRecord:
        if not record.tenant_id:
            raise ValueError("tenant_id is required")
        with self._lock:
            self._devices[(record.tenant_id, record.device_id)] = record
        return record

    def get(self, tenant_id: str, device_id: str) -> Optional[DeviceRecord]:
        with self._lock:
            return self._devices.get((tenant_id, device_id))

    def list_for_subject(self, tenant_id: str, subject: str) -> list[DeviceRecord]:
        with self._lock:
            devices = [
                r
                for (tid, _), r in self._devices.items()
                if tid == tenant_id and r.subject == subject
            ]
        return sorted(devices, key=lambda r: r.device_id)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class InMemoryTimelineRepository:
    """In-memory append-only timeline repository."""

    def __init__(self) -> None:
        self._events: list[IdentityTimelineEvent] = []
        self._lock = threading.Lock()

    def append(self, event: IdentityTimelineEvent) -> IdentityTimelineEvent:
        if not event.tenant_id:
            raise ValueError("tenant_id is required")
        with self._lock:
            self._events.append(event)
        return event

    def list_events(
        self,
        tenant_id: str,
        subject: Optional[str] = None,
        limit: int = 100,
    ) -> list[IdentityTimelineEvent]:
        with self._lock:
            candidates = [e for e in self._events if e.tenant_id == tenant_id]
        if subject is not None:
            candidates = [e for e in candidates if e.subject == subject]
        if limit <= 0:
            return []
        return candidates[-limit:]


# ---------------------------------------------------------------------------
# Break-glass
# ---------------------------------------------------------------------------


class InMemoryBreakGlassRepository:
    """In-memory repository for break-glass requests."""

    def __init__(self) -> None:
        self._requests: dict[tuple[str, str], BreakGlassRequest] = {}
        self._lock = threading.Lock()

    def create(self, request: BreakGlassRequest) -> BreakGlassRequest:
        if not request.tenant_id:
            raise ValueError("tenant_id is required")
        with self._lock:
            self._requests[(request.tenant_id, request.request_id)] = request
        return request

    def update(self, request: BreakGlassRequest) -> BreakGlassRequest:
        if not request.tenant_id:
            raise ValueError("tenant_id is required")
        key = (request.tenant_id, request.request_id)
        with self._lock:
            if key not in self._requests:
                raise ValueError(
                    f"break-glass request {request.request_id!r} not found for tenant"
                )
            self._requests[key] = request
        return request

    def get(self, tenant_id: str, request_id: str) -> Optional[BreakGlassRequest]:
        with self._lock:
            return self._requests.get((tenant_id, request_id))

    def list_active_for_subject(
        self, tenant_id: str, subject: str
    ) -> list[BreakGlassRequest]:
        with self._lock:
            candidates = [
                r
                for (tid, _rid), r in self._requests.items()
                if tid == tenant_id
                and r.subject == subject
                and r.status == BreakGlassStatus.ACTIVE
            ]
        return sorted(candidates, key=lambda r: r.request_id)


__all__ = [
    "InMemoryBreakGlassRepository",
    "InMemoryDeviceRepository",
    "InMemoryLifecycleRepository",
    "InMemoryTimelineRepository",
]
