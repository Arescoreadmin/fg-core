# services/notifications/schemas.py
"""Domain enums and exceptions for the Notifications bounded context.

PR 13.7 — Remediation Audit History & Notification Authority.
"""

from __future__ import annotations

from enum import Enum


class NotificationChannel(str, Enum):
    PORTAL = "portal"
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationDeliveryStatus(str, Enum):
    """Delivery state machine for notification records.

    Active states (phase 1):
      PENDING      — record created, send not yet attempted
      SENT         — channel backend accepted transmission (returned True)
      FAILED       — channel backend rejected or raised
      ACKNOWLEDGED — recipient explicitly acknowledged via the API

    Reserved (phase 2 — not written by the engine today):
      DELIVERED    — confirmed receipt from transport layer (e.g. SendGrid
                     delivery webhook, websocket ACK from portal client).
                     Until a transport integration provides confirmation,
                     no record will ever enter this state.  Stored in the
                     DB schema now so phase 2 requires no migration.
    """

    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"  # phase 2 — see docstring above
    FAILED = "failed"
    ACKNOWLEDGED = "acknowledged"


class NotificationTrigger(str, Enum):
    TASK_ASSIGNED = "task_assigned"
    TASK_UNASSIGNED = "task_unassigned"
    TASK_DUE_SOON = "task_due_soon"
    TASK_OVERDUE = "task_overdue"
    TASK_CLOSED = "task_closed"
    TASK_ACCEPTED_RISK = "task_accepted_risk"
    EVIDENCE_REQUESTED = "evidence_requested"
    EVIDENCE_VERIFIED = "evidence_verified"
    VERIFICATION_FAILED = "verification_failed"
    SLA_APPROACHING = "sla_approaching"
    SLA_BREACHED = "sla_breached"


class NotificationPreference(str, Enum):
    IMMEDIATE = "immediate"
    DIGEST = "digest"
    DISABLED = "disabled"
    CRITICAL_ONLY = "critical_only"


class NotificationError(Exception):
    pass


class NotificationNotFound(NotificationError):
    pass


class NotificationChannelError(NotificationError):
    pass
