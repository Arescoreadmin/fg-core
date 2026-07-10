"""api/identity_governance/repositories/ — Persistence abstraction for governance.

The runtime code paths always interact with one of the ``Repository`` protocol
implementations here. The in-memory implementation is the default and is
used by tests and when :env:`FG_IDENTITY_PERSISTENCE_ENABLED` is false. The
SQLAlchemy implementation is opt-in and backs writes into the tables created
by ``migrations/postgres/0148_identity_governance.sql``.
"""

from api.identity_governance.repositories.base import (
    BreakGlassRepository,
    DeviceRepository,
    LifecycleRepository,
    TimelineRepository,
)
from api.identity_governance.repositories.memory import (
    InMemoryBreakGlassRepository,
    InMemoryDeviceRepository,
    InMemoryLifecycleRepository,
    InMemoryTimelineRepository,
)

__all__ = [
    "BreakGlassRepository",
    "DeviceRepository",
    "InMemoryBreakGlassRepository",
    "InMemoryDeviceRepository",
    "InMemoryLifecycleRepository",
    "InMemoryTimelineRepository",
    "LifecycleRepository",
    "TimelineRepository",
]
