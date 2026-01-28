"""Audit Logger.

Stub implementation that logs audit events locally or forwards to core.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Literal, Optional

log = logging.getLogger("admin-gateway.audit")


class AuditLogger:
    """Audit logger that writes to local log or forwards to core API."""

    def __init__(
        self,
        core_base_url: Optional[str] = None,
        enabled: bool = True,
    ):
        self.core_base_url = core_base_url
        self.enabled = enabled
        self._client = None

    async def log(
        self,
        request_id: str,
        action: str,
        outcome: Literal["success", "failure", "error"],
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """Log an audit event."""
        if not self.enabled:
            return

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "action": action,
            "outcome": outcome,
            "actor": actor,
            "resource": resource,
            "resource_id": resource_id,
            "details": details,
            "ip_address": ip_address,
            "user_agent": user_agent,
        }

        # For now, just log locally
        # TODO: Forward to core audit endpoint when available
        log.info(
            "audit",
            extra={"audit_entry": entry},
        )

        # If core URL is configured, we could forward here
        if self.core_base_url:
            # Future: POST to core audit endpoint
            pass
