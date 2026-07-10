"""api/identity_governance/repositories/base.py — Repository protocols.

Thin persistence Protocols. Every repository is tenant-scoped: the
``tenant_id`` parameter is required on every read/write and cross-tenant
access is rejected by construction.

The in-memory implementation lives in ``memory.py``; the SQLAlchemy
implementation lives in ``db.py``. Runtime code paths depend only on the
Protocols here so that the backend is swappable.
"""

from __future__ import annotations

from typing import Optional, Protocol

from api.identity_governance.models import (
    BreakGlassRequest,
    DeviceRecord,
    IdentityLifecycleRecord,
    IdentityTimelineEvent,
)


class LifecycleRepository(Protocol):
    """Persistence for lifecycle transition records."""

    def create(self, record: IdentityLifecycleRecord) -> IdentityLifecycleRecord: ...

    def get(
        self, tenant_id: str, record_id: str
    ) -> Optional[IdentityLifecycleRecord]: ...

    def list_for_subject(
        self, tenant_id: str, subject: str, limit: int = 100
    ) -> list[IdentityLifecycleRecord]: ...


class DeviceRepository(Protocol):
    """Persistence for device trust records."""

    def upsert(self, record: DeviceRecord) -> DeviceRecord: ...

    def get(self, tenant_id: str, device_id: str) -> Optional[DeviceRecord]: ...

    def list_for_subject(self, tenant_id: str, subject: str) -> list[DeviceRecord]: ...


class TimelineRepository(Protocol):
    """Persistence for hash-chained timeline events."""

    def append(self, event: IdentityTimelineEvent) -> IdentityTimelineEvent: ...

    def list_events(
        self,
        tenant_id: str,
        subject: Optional[str] = None,
        limit: int = 100,
    ) -> list[IdentityTimelineEvent]: ...


class BreakGlassRepository(Protocol):
    """Persistence for break-glass requests."""

    def create(self, request: BreakGlassRequest) -> BreakGlassRequest: ...

    def update(self, request: BreakGlassRequest) -> BreakGlassRequest: ...

    def get(self, tenant_id: str, request_id: str) -> Optional[BreakGlassRequest]: ...

    def list_active_for_subject(
        self, tenant_id: str, subject: str
    ) -> list[BreakGlassRequest]: ...


__all__ = [
    "BreakGlassRepository",
    "DeviceRepository",
    "LifecycleRepository",
    "TimelineRepository",
]
