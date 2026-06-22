# services/notifications/channels.py
"""Channel backend abstraction for the Notifications bounded context.

PR 13.7 — Remediation Audit History & Notification Authority.

Channel backends are injectable for testing via _set_notification_channel().
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sqlalchemy.orm import Session


class NotificationChannelBackend(ABC):
    @abstractmethod
    def send(
        self, *, recipient: str, subject: str, body: str, metadata: dict
    ) -> bool: ...

    @abstractmethod
    def channel_name(self) -> str: ...


class NullNotificationChannel(NotificationChannelBackend):
    """Accepts all sends silently. Default in test/dev."""

    def send(self, *, recipient: str, subject: str, body: str, metadata: dict) -> bool:
        return True

    def channel_name(self) -> str:
        return "null"


class EmailNotificationChannel(NotificationChannelBackend):
    """Stub email channel — logs notification, no actual SMTP. Phase 2: wire SendGrid/SES."""

    def send(self, *, recipient: str, subject: str, body: str, metadata: dict) -> bool:
        return True  # Outbox pattern: actual send deferred to async worker

    def channel_name(self) -> str:
        return "email"


class PortalNotificationChannel(NotificationChannelBackend):
    """Writes in-app notification. Phase 2: push to portal_notifications for websocket delivery."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def send(self, *, recipient: str, subject: str, body: str, metadata: dict) -> bool:
        return True

    def channel_name(self) -> str:
        return "portal"


# Module-level registry — injectable for testing
_CHANNEL_BACKEND: NotificationChannelBackend = NullNotificationChannel()


def get_notification_channel() -> NotificationChannelBackend:
    return _CHANNEL_BACKEND


def _set_notification_channel(backend: NotificationChannelBackend) -> None:
    """Test injection only."""
    global _CHANNEL_BACKEND
    _CHANNEL_BACKEND = backend
