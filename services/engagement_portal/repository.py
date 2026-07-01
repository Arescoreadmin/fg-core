"""Data access layer for the Engagement Portal (PR 18.2).

All queries are tenant-scoped. Caller owns db.commit().
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from api.db_models_engagement_portal import (
    PortalEngagementActivity,
    PortalEngagementNotification,
    PortalEngagementPreferences,
)
from services.canonical import utc_iso8601_z_now


# ---------------------------------------------------------------------------
# Preferences (tenant-scoped upsert)
# ---------------------------------------------------------------------------


def fetch_preferences(
    db: Session, *, tenant_id: str
) -> PortalEngagementPreferences | None:
    return (
        db.query(PortalEngagementPreferences)
        .filter(PortalEngagementPreferences.tenant_id == tenant_id)
        .first()
    )


def upsert_preferences(
    db: Session,
    *,
    tenant_id: str,
    theme: str | None,
    notification_email: bool,
    timezone: str | None,
    language: str | None,
) -> PortalEngagementPreferences:
    """Insert-or-update the preference row for the given tenant."""
    now = utc_iso8601_z_now()
    existing = fetch_preferences(db, tenant_id=tenant_id)
    if existing is None:
        row = PortalEngagementPreferences(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            theme=theme,
            notification_email=1 if notification_email else 0,
            timezone=timezone,
            language=language,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        db.flush()
        return row
    existing.theme = theme
    existing.notification_email = 1 if notification_email else 0
    existing.timezone = timezone
    existing.language = language
    existing.updated_at = now
    db.flush()
    return existing


# ---------------------------------------------------------------------------
# Activity (append-only)
# ---------------------------------------------------------------------------


def insert_activity(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    workspace: str | None = None,
    entity_id: str | None = None,
    actor_id: str | None = None,
    summary: str | None = None,
    metadata_json: str | None = None,
) -> PortalEngagementActivity:
    row = PortalEngagementActivity(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        event_type=event_type,
        workspace=workspace,
        entity_id=entity_id,
        actor_id=actor_id,
        summary=summary,
        metadata_json=metadata_json,
        created_at=utc_iso8601_z_now(),
    )
    db.add(row)
    db.flush()
    return row


def list_activities(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
    workspace: str | None = None,
) -> tuple[list[PortalEngagementActivity], int]:
    q = db.query(PortalEngagementActivity).filter(
        PortalEngagementActivity.tenant_id == tenant_id
    )
    if workspace is not None:
        q = q.filter(PortalEngagementActivity.workspace == workspace)
    total = q.count()
    items = (
        q.order_by(PortalEngagementActivity.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return items, total


def count_activities(
    db: Session,
    *,
    tenant_id: str,
    event_type: str | None = None,
) -> int:
    q = db.query(PortalEngagementActivity).filter(
        PortalEngagementActivity.tenant_id == tenant_id
    )
    if event_type is not None:
        q = q.filter(PortalEngagementActivity.event_type == event_type)
    return q.count()


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def insert_notification(
    db: Session,
    *,
    tenant_id: str,
    notification_type: str,
    subject: str | None = None,
    body: str | None = None,
) -> PortalEngagementNotification:
    now = utc_iso8601_z_now()
    row = PortalEngagementNotification(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        notification_type=notification_type,
        status="PENDING",
        subject=subject,
        body=body,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    return row


def list_notifications(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> tuple[list[PortalEngagementNotification], int]:
    q = db.query(PortalEngagementNotification).filter(
        PortalEngagementNotification.tenant_id == tenant_id
    )
    if status is not None:
        q = q.filter(PortalEngagementNotification.status == status)
    total = q.count()
    items = (
        q.order_by(PortalEngagementNotification.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return items, total


def count_notifications(
    db: Session,
    *,
    tenant_id: str,
    status: str | None = None,
) -> int:
    q = db.query(PortalEngagementNotification).filter(
        PortalEngagementNotification.tenant_id == tenant_id
    )
    if status is not None:
        q = q.filter(PortalEngagementNotification.status == status)
    return q.count()


def mark_notification_delivered(
    db: Session, *, tenant_id: str, notification_id: str
) -> PortalEngagementNotification | None:
    row = (
        db.query(PortalEngagementNotification)
        .filter(
            PortalEngagementNotification.tenant_id == tenant_id,
            PortalEngagementNotification.id == notification_id,
        )
        .first()
    )
    if row is None:
        return None
    now = utc_iso8601_z_now()
    row.status = "DELIVERED"
    row.delivered_at = now
    row.updated_at = now
    db.flush()
    return row
