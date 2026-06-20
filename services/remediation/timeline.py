# services/remediation/timeline.py
"""Unified Timeline Engine for the Remediation subsystem.

PR 13.7 — Remediation Audit History & Notification Authority.

Merges events from three sources into one chronological list:
  - remediation_task_audits     (source="remediation")
  - portal_remediation_audit_events (source="portal")
  - notifications               (source="notification", only non-pending)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_notifications import Notification
from api.db_models_portal_remediation import PortalRemediationAuditEvent
from api.db_models_remediation import RemediationTask, RemediationTaskAudit
from api.observability.metrics import TIMELINE_EVENTS_TOTAL
from services.remediation.schemas import (
    RemediationNotFound,
    TimelineEventResponse,
    TimelineListResponse,
)


@dataclass
class TimelineEvent:
    id: str
    task_id: str
    event_type: str
    source: str  # "remediation" | "portal" | "notification"
    actor: str
    event_at: str  # ISO 8601
    metadata: dict[str, Any]


class UnifiedTimelineEngine:
    """Tenant-scoped unified timeline service.

    Merges events from all three audit sources and returns a paginated,
    filtered, chronologically sorted response.
    """

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    def get_timeline(
        self,
        *,
        task_id: str,
        limit: int = 50,
        offset: int = 0,
        event_type: str | None = None,
        source: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> TimelineListResponse:
        """Fetch events from all three sources, merge, filter, sort by event_at ASC, paginate.

        Raises RemediationNotFound if task doesn't belong to tenant.
        Increments TIMELINE_EVENTS_TOTAL.
        """
        # Verify task belongs to tenant
        task = (
            self._db.query(RemediationTask)
            .filter(
                RemediationTask.id == task_id,
                RemediationTask.tenant_id == self._tenant_id,
            )
            .first()
        )
        if task is None:
            raise RemediationNotFound(
                f"Task {task_id!r} not found or does not belong to tenant."
            )

        events: list[TimelineEvent] = []

        # Source 1: remediation_task_audits
        if source is None or source == "remediation":
            rem_q = self._db.query(RemediationTaskAudit).filter(
                RemediationTaskAudit.tenant_id == self._tenant_id,
                RemediationTaskAudit.task_id == task_id,
            )
            for remediation_row in rem_q.all():
                metadata: dict[str, Any] = {}
                if remediation_row.old_state is not None:
                    metadata["old_state"] = remediation_row.old_state
                if remediation_row.new_state is not None:
                    metadata["new_state"] = remediation_row.new_state
                if remediation_row.reason is not None:
                    metadata["reason"] = remediation_row.reason
                events.append(
                    TimelineEvent(
                        id=remediation_row.id,
                        task_id=remediation_row.task_id,
                        event_type=remediation_row.event_type,
                        source="remediation",
                        actor=remediation_row.actor,
                        event_at=remediation_row.event_at,
                        metadata=metadata,
                    )
                )

        # Source 2: portal_remediation_audit_events
        if source is None or source == "portal":
            portal_q = self._db.query(PortalRemediationAuditEvent).filter(
                PortalRemediationAuditEvent.tenant_id == self._tenant_id,
                PortalRemediationAuditEvent.task_id == task_id,
            )
            for portal_row in portal_q.all():
                events.append(
                    TimelineEvent(
                        id=portal_row.id,
                        task_id=portal_row.task_id,
                        event_type=portal_row.event_type,
                        source="portal",
                        actor=portal_row.actor,
                        event_at=portal_row.event_at,
                        metadata=portal_row.event_metadata or {},
                    )
                )

        # Source 3: notifications (only non-pending)
        if source is None or source == "notification":
            notif_q = self._db.query(Notification).filter(
                Notification.tenant_id == self._tenant_id,
                Notification.task_id == task_id,
                Notification.delivery_status != "pending",
            )
            for notification_row in notif_q.all():
                events.append(
                    TimelineEvent(
                        id=notification_row.id,
                        task_id=notification_row.task_id,
                        event_type=notification_row.trigger_type,
                        source="notification",
                        actor=notification_row.recipient,
                        event_at=notification_row.sent_at
                        or notification_row.created_at,
                        metadata={
                            "channel": notification_row.channel,
                            "delivery_status": notification_row.delivery_status,
                            "recipient": notification_row.recipient,
                        },
                    )
                )

        # Apply filters
        if event_type is not None:
            events = [e for e in events if e.event_type == event_type]
        if since is not None:
            events = [e for e in events if e.event_at >= since]
        if until is not None:
            events = [e for e in events if e.event_at <= until]

        # Sort chronologically (stable sort)
        events.sort(key=lambda e: e.event_at)

        total = len(events)

        # Paginate
        page = events[offset : offset + limit]

        TIMELINE_EVENTS_TOTAL.inc()

        return TimelineListResponse(
            task_id=task_id,
            events=[
                TimelineEventResponse(
                    id=e.id,
                    task_id=e.task_id,
                    event_type=e.event_type,
                    source=e.source,
                    actor=e.actor,
                    event_at=e.event_at,
                    metadata=e.metadata,
                )
                for e in page
            ],
            total=total,
            limit=limit,
            offset=offset,
        )
