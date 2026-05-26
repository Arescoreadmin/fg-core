"""Engagement-scoped report version management.

Every query includes both tenant_id and engagement_id predicates.
No cross-tenant reads. Version history is preserved — prior versions
are never deleted or made inaccessible.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_report import GovernanceReportRecord


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
