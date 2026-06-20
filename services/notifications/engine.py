# services/notifications/engine.py
"""Notification Engine for the Notifications bounded context.

PR 13.7 — Remediation Audit History & Notification Authority.

All public methods are tenant-scoped. Caller owns db.commit().

Delivery flow:
  1. Create notification record (PENDING)
  2. Attempt send via channel backend
  3. Update status to SENT or FAILED
  4. Increment Prometheus counter
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_notifications import Notification
from api.observability.metrics import (
    NOTIFICATIONS_ACKNOWLEDGED_TOTAL,
    NOTIFICATIONS_FAILED_TOTAL,
    NOTIFICATIONS_SENT_TOTAL,
    SLA_ESCALATIONS_TOTAL,
)
from services.notifications.channels import get_notification_channel
from services.notifications.schemas import (
    NotificationChannel,
    NotificationDeliveryStatus,
    NotificationNotFound,
    NotificationTrigger,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


class NotificationEngine:
    """Tenant-scoped notification service.

    Caller owns db.commit() — every method prepares the transaction but
    does not commit, enabling atomic route-level commits.
    """

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def notify(
        self,
        *,
        task_id: str,
        trigger: NotificationTrigger,
        recipient: str,
        channel: NotificationChannel = NotificationChannel.EMAIL,
        subject: str | None = None,
        body: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Notification:
        """Create notification record (PENDING), attempt send, update status (SENT/FAILED).

        Increments NOTIFICATIONS_SENT_TOTAL or NOTIFICATIONS_FAILED_TOTAL.
        Caller owns db.commit().
        """
        now = _utcnow()
        notification = Notification(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            trigger_type=trigger.value,
            channel=channel.value,
            recipient=recipient,
            subject=subject,
            delivery_status=NotificationDeliveryStatus.PENDING.value,
            sent_at=None,
            acknowledged_at=None,
            failure_reason=None,
            event_metadata=metadata or {},
            created_at=now,
            updated_at=now,
        )
        self._db.add(notification)
        self._db.flush()

        # Attempt delivery via channel backend
        channel_backend = get_notification_channel()
        try:
            sent = channel_backend.send(
                recipient=recipient,
                subject=subject or "",
                body=body or "",
                metadata=metadata or {},
            )
        except Exception as exc:
            sent = False
            notification.failure_reason = str(exc)

        sent_at = _utcnow()
        if sent:
            notification.delivery_status = NotificationDeliveryStatus.SENT.value
            notification.sent_at = sent_at
            notification.updated_at = sent_at
            NOTIFICATIONS_SENT_TOTAL.inc()
        else:
            notification.delivery_status = NotificationDeliveryStatus.FAILED.value
            notification.updated_at = sent_at
            if not notification.failure_reason:
                notification.failure_reason = "channel returned False"
            NOTIFICATIONS_FAILED_TOTAL.inc()

        return notification

    def acknowledge(self, *, notification_id: str, actor: str) -> Notification:
        """Mark notification as ACKNOWLEDGED. Increments NOTIFICATIONS_ACKNOWLEDGED_TOTAL."""
        notification = (
            self._db.query(Notification)
            .filter(
                Notification.id == notification_id,
                Notification.tenant_id == self._tenant_id,
            )
            .first()
        )
        if notification is None:
            raise NotificationNotFound(
                f"Notification {notification_id!r} not found for tenant."
            )

        now = _utcnow()
        notification.delivery_status = NotificationDeliveryStatus.ACKNOWLEDGED.value
        notification.acknowledged_at = now
        notification.updated_at = now

        NOTIFICATIONS_ACKNOWLEDGED_TOTAL.inc()
        return notification

    def list_notifications(
        self,
        *,
        task_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Notification]:
        """List notifications for a task (tenant-scoped)."""
        return (
            self._db.query(Notification)
            .filter(
                Notification.tenant_id == self._tenant_id,
                Notification.task_id == task_id,
            )
            .order_by(Notification.created_at.asc())
            .limit(limit)
            .offset(offset)
            .all()
        )

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def notify_assignment(
        self,
        *,
        task_id: str,
        recipient: str,
        display_name: str,
        actor: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Notify recipient of task assignment."""
        m = dict(metadata or {})
        m.setdefault("actor", actor)
        m.setdefault("display_name", display_name)
        self.notify(
            task_id=task_id,
            trigger=NotificationTrigger.TASK_ASSIGNED,
            recipient=recipient,
            subject="You have been assigned a remediation task",
            body=f"Hi {display_name},\n\nYou have been assigned remediation task {task_id}.\n\nActor: {actor}",
            metadata=m,
        )

    def notify_unassignment(
        self,
        *,
        task_id: str,
        recipient: str,
        actor: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Notify recipient of task unassignment."""
        m = dict(metadata or {})
        m.setdefault("actor", actor)
        self.notify(
            task_id=task_id,
            trigger=NotificationTrigger.TASK_UNASSIGNED,
            recipient=recipient,
            subject="You have been unassigned from a remediation task",
            body=f"You have been unassigned from remediation task {task_id}.\n\nActor: {actor}",
            metadata=m,
        )

    def notify_closed(
        self,
        *,
        task_id: str,
        recipient: str,
        actor: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Notify recipient that task has been closed."""
        m = dict(metadata or {})
        m.setdefault("actor", actor)
        self.notify(
            task_id=task_id,
            trigger=NotificationTrigger.TASK_CLOSED,
            recipient=recipient,
            subject="Remediation task closed",
            body=f"Remediation task {task_id} has been closed.\n\nActor: {actor}",
            metadata=m,
        )

    def notify_risk_accepted(
        self,
        *,
        task_id: str,
        recipient: str,
        actor: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Notify recipient that risk has been accepted on the task."""
        m = dict(metadata or {})
        m.setdefault("actor", actor)
        if reason:
            m.setdefault("reason", reason)
        self.notify(
            task_id=task_id,
            trigger=NotificationTrigger.TASK_ACCEPTED_RISK,
            recipient=recipient,
            subject="Risk accepted on remediation task",
            body=f"Risk has been accepted on remediation task {task_id}.\n\nReason: {reason or 'not provided'}\nActor: {actor}",
            metadata=m,
        )

    def notify_sla_approaching(
        self,
        *,
        task_id: str,
        recipient: str,
        days_remaining: int,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Notify recipient that SLA is approaching. Increments SLA_ESCALATIONS_TOTAL."""
        m = dict(metadata or {})
        m.setdefault("days_remaining", days_remaining)
        self.notify(
            task_id=task_id,
            trigger=NotificationTrigger.SLA_APPROACHING,
            recipient=recipient,
            subject=f"SLA approaching: {days_remaining} days remaining",
            body=f"Remediation task {task_id} SLA is approaching. {days_remaining} days remaining.",
            metadata=m,
        )
        SLA_ESCALATIONS_TOTAL.inc()

    def notify_sla_breached(
        self,
        *,
        task_id: str,
        recipient: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Notify recipient that SLA has been breached. Increments SLA_ESCALATIONS_TOTAL."""
        m = dict(metadata or {})
        self.notify(
            task_id=task_id,
            trigger=NotificationTrigger.SLA_BREACHED,
            recipient=recipient,
            subject="SLA breached on remediation task",
            body=f"Remediation task {task_id} has breached its SLA.",
            metadata=m,
        )
        SLA_ESCALATIONS_TOTAL.inc()
