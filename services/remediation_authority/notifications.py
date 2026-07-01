"""Notification dispatch helpers.

Attempts to hand a notification to ``services.notifications`` if that
library service is available. Otherwise silently no-ops so remediation
operations don't fail when notifications aren't wired.
"""

from __future__ import annotations

from typing import Any


def dispatch_notification(
    tenant_id: str,
    event_type: str,
    subject: str,
    body: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> bool:
    """Attempt to enqueue a notification; return True on success, False on no-op."""
    if not tenant_id or not event_type:
        return False
    try:
        from services.notifications import enqueue_notification  # type: ignore

        enqueue_notification(
            tenant_id=tenant_id,
            event_type=event_type,
            subject=subject,
            body=body or "",
            metadata=metadata or {},
        )
        return True
    except Exception:
        return False
