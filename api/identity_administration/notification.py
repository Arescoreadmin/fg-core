"""api/identity_administration/notification.py — In-process notification publisher.

Emits notification events to the identity timeline (best-effort, never raises).
"""

from __future__ import annotations

import logging

from api.identity_administration.models import NotificationEvent
from api.identity_governance.models import IdentityTimelineEventType
from api.identity_governance.timeline import IdentityTimeline

log = logging.getLogger("frostgate.identity_administration.notification")


class NotificationPublisher:
    """Publishes notification events to the identity timeline.

    All emit calls are best-effort — exceptions are caught and logged.
    The main request path should never fail due to notification delivery.
    """

    def __init__(self, timeline: IdentityTimeline) -> None:
        self._timeline = timeline

    def publish(self, event: NotificationEvent) -> None:
        """Emit notification event to timeline (best-effort, never raises)."""
        try:
            self._timeline.emit(
                event_type=IdentityTimelineEventType.ADMIN_ACTION,
                subject=event.subject,
                tenant_id=event.tenant_id,
                actor=event.actor,
                details={
                    "notification_type": event.event_type.value,
                    **dict(event.payload),
                },
                correlation_id=event.correlation_id,
            )
            log.info(
                "identity_administration.notification.published",
                extra={
                    "event_type": event.event_type.value,
                    "subject_prefix": event.subject[:16],
                    "tenant_id": event.tenant_id,
                },
            )
        except Exception as exc:
            log.warning(
                "identity_administration.notification.publish_failed",
                extra={"event_type": event.event_type.value, "exc": str(exc)},
            )


__all__ = ["NotificationPublisher"]
