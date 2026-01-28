"""Audit middleware for admin-gateway."""

from __future__ import annotations

from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


def _categorize(path: str) -> str:
    if path.startswith("/auth"):
        return "auth"
    if path.startswith("/admin") or path.startswith("/api"):
        return "admin"
    return "system"


class AuditMiddleware(BaseHTTPMiddleware):
    """Emit audit events for every request."""

    async def dispatch(self, request: Request, call_next):
        status_code: Optional[int] = None
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            audit_logger = getattr(request.app.state, "audit_logger", None)
            if not audit_logger:
                return
            user = getattr(request.state, "user", None)
            actor = None
            if user:
                actor = user.email or user.sub
            await audit_logger.log_event(
                {
                    "request_id": getattr(request.state, "request_id", "unknown"),
                    "actor": actor,
                    "path": request.url.path,
                    "method": request.method,
                    "tenant_id": getattr(request.state, "tenant_id", None),
                    "status_code": status_code or 500,
                    "ip": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent"),
                    "category": _categorize(request.url.path),
                }
            )
