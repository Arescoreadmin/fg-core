"""Engagement-scoped report version management.

Every query includes both tenant_id and engagement_id predicates.
No cross-tenant reads. Version history is preserved — prior versions
are never deleted or made inaccessible.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_report import GovernanceReportRecord

# Per-(tenant_id, engagement_id) mutex.  Serialises version allocation within
# a single process so two concurrent requests never read the same max and
# claim the same slot.  The DB-level unique constraint on
# (tenant_id, engagement_id, version) remains the correctness guarantee for
# multi-process / multi-node deployments.
_version_lock_registry: dict[tuple[str, str], threading.Lock] = {}
_registry_guard = threading.Lock()


def _allocation_lock(tenant_id: str, engagement_id: str) -> threading.Lock:
    key = (tenant_id, engagement_id)
    with _registry_guard:
        if key not in _version_lock_registry:
            _version_lock_registry[key] = threading.Lock()
        return _version_lock_registry[key]


@contextmanager
def acquire_next_version(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> Generator[int, None, None]:
    """Yield the next version number while holding a per-(tenant, engagement) mutex.

    The caller must flush or commit the new record before the context exits.
    The lock is held for the entire duration, so no concurrent allocator in
    the same process can claim the same version number.
    """
    lock = _allocation_lock(tenant_id, engagement_id)
    with lock:
        stmt = (
            select(GovernanceReportRecord.version)
            .where(
                GovernanceReportRecord.tenant_id == tenant_id,
                GovernanceReportRecord.engagement_id == engagement_id,
            )
            .order_by(GovernanceReportRecord.version.desc())
            .limit(1)
        )
        current_max = db.execute(stmt).scalar_one_or_none()
        yield (current_max or 0) + 1


def get_next_version(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> int:
    """Return the next logical version number for a tenant+engagement report sequence."""
    stmt = (
        select(GovernanceReportRecord.version)
        .where(
            GovernanceReportRecord.tenant_id == tenant_id,
            GovernanceReportRecord.engagement_id == engagement_id,
        )
        .order_by(GovernanceReportRecord.version.desc())
        .limit(1)
    )
    current_max = db.execute(stmt).scalar_one_or_none()
    return (current_max or 0) + 1


def list_versions(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> list[GovernanceReportRecord]:
    """Return all report versions for a tenant+engagement in ascending version order."""
    stmt = (
        select(GovernanceReportRecord)
        .where(
            GovernanceReportRecord.tenant_id == tenant_id,
            GovernanceReportRecord.engagement_id == engagement_id,
        )
        .order_by(GovernanceReportRecord.version.asc())
    )
    return list(db.execute(stmt).scalars().all())


def get_version(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    version: int,
) -> GovernanceReportRecord | None:
    """Return a specific report version; None if not found or cross-tenant."""
    stmt = select(GovernanceReportRecord).where(
        GovernanceReportRecord.tenant_id == tenant_id,
        GovernanceReportRecord.engagement_id == engagement_id,
        GovernanceReportRecord.version == version,
    )
    return db.execute(stmt).scalar_one_or_none()
