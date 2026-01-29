"""Audit Logger.

Stub implementation that logs audit events locally or forwards to core.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal, Optional

import httpx

log = logging.getLogger("admin-gateway.audit")


class AuditLogger:
    """Audit logger that writes to local log or forwards to core API."""

    def __init__(
        self,
        core_base_url: Optional[str] = None,
        core_api_key: Optional[str] = None,
        enabled: bool = True,
        forward_enabled: bool = False,
    ):
        self.core_base_url = core_base_url
        self.core_api_key = core_api_key
        self.enabled = enabled
        self.forward_enabled = forward_enabled
        self._client: Optional[httpx.AsyncClient] = None

    async def log_event(self, event: dict) -> None:
        """Log an audit event."""
        if not self.enabled:
            return

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **self._redact_event(event),
        }

        log.info(
            "audit",
            extra={"audit_entry": entry},
        )

        if self.core_base_url and self.forward_enabled and self.core_api_key:
            await self._send_to_core(entry)

    async def _send_to_core(self, entry: dict) -> None:
        if not self.core_base_url or not self.core_api_key:
            return
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.core_base_url, timeout=5.0)
        try:
            await self._client.post(
                "/admin/audit",
                json=entry,
                headers={"X-API-Key": self.core_api_key},
            )
        except httpx.HTTPError:
            log.debug("Failed to forward audit entry to core")

    def _redact_event(self, event: dict) -> dict:
        return self._redact_secrets(event)

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        normalized = key.strip().lower().replace(" ", "").replace("_", "-")
        if normalized in {
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "api_key",
            "apikey",
            "client_secret",
            "client-secret",
            "access_token",
            "refresh_token",
            "id_token",
            "token",
            "secret",
        }:
            return True
        return any(
            fragment in normalized for fragment in ("token", "secret", "api-key")
        )

    @classmethod
    def _redact_secrets(cls, value: Any) -> Any:
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for key, item in value.items():
                if cls._is_sensitive_key(str(key)):
                    redacted[key] = "[REDACTED]"
                else:
                    redacted[key] = cls._redact_secrets(item)
            return redacted
        if isinstance(value, list):
            return [cls._redact_secrets(item) for item in value]
        return value

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
        """Compatibility wrapper for older audit calls."""
        await self.log_event(
            {
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
        )
