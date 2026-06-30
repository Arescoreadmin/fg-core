"""Statistics aggregation for the Engagement Portal.

Computes counts from portal-owned tables only; cross-authority reads happen
in engine.py and are intentionally kept out of this module to preserve a
single responsibility (no business-logic duplication).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from api.db_models_engagement_portal import (
    PortalEngagementActivity,
    PortalEngagementNotification,
    PortalEngagementPreferences,
)


def compute_portal_statistics(db: Session, *, tenant_id: str) -> dict[str, Any]:
    """Return aggregate counts for a tenant's portal usage.

    All counts are non-negative integers. ``preferences_set`` is True only when
    a preference row exists for the tenant.
    """
    total_activities = (
        db.query(PortalEngagementActivity)
        .filter(PortalEngagementActivity.tenant_id == tenant_id)
        .count()
    )

    total_reports_viewed = (
        db.query(PortalEngagementActivity)
        .filter(
            PortalEngagementActivity.tenant_id == tenant_id,
            PortalEngagementActivity.event_type == "report_viewed",
        )
        .count()
    )

    total_evidence_viewed = (
        db.query(PortalEngagementActivity)
        .filter(
            PortalEngagementActivity.tenant_id == tenant_id,
            PortalEngagementActivity.event_type == "evidence_viewed",
        )
        .count()
    )

    total_searches = (
        db.query(PortalEngagementActivity)
        .filter(
            PortalEngagementActivity.tenant_id == tenant_id,
            PortalEngagementActivity.event_type == "search_performed",
        )
        .count()
    )

    active_notifications = (
        db.query(PortalEngagementNotification)
        .filter(
            PortalEngagementNotification.tenant_id == tenant_id,
            PortalEngagementNotification.status == "PENDING",
        )
        .count()
    )

    preferences_set = (
        db.query(PortalEngagementPreferences)
        .filter(PortalEngagementPreferences.tenant_id == tenant_id)
        .first()
        is not None
    )

    return {
        "total_activities": int(total_activities),
        "total_reports_viewed": int(total_reports_viewed),
        "total_evidence_viewed": int(total_evidence_viewed),
        "total_searches": int(total_searches),
        "active_notifications": int(active_notifications),
        "preferences_set": bool(preferences_set),
    }
