"""Audit middleware for admin requests.

Logs all admin API requests with user, action, and outcome.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger("admin-gateway.audit")


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware that emits audit events for all admin requests.

    Records:
    - User identity (from session)
    - Action (HTTP method + path)
    - Outcome (success/failure based on status code)
    - Timing information
    - Request metadata (IP, user agent, request ID)
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request and emit audit event."""
        path = request.url.path
        method = request.method.upper()

        # Skip audit for health/docs endpoints
        if self._skip_audit(path):
            return await call_next(request)

        # Capture timing
        start_time = time.time()

        # Get request metadata
        request_id = getattr(request.state, "request_id", None)
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent", "")

        # Execute request
        response = await call_next(request)

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Get session info if available
        session = getattr(request.state, "session", None)
        user_id = session.user_id if session else None
        tenant_id = None
        if session:
            tenant_id = session.tenant_id or (request.query_params.get("tenant_id"))

        # Determine outcome
        status_code = response.status_code
        if status_code < 400:
            outcome = "success"
        elif status_code < 500:
            outcome = "failure"
        else:
            outcome = "error"

        # Emit structured audit log
        log.info(
            "audit_event",
            extra={
                "audit": {
                    "timestamp": time.time(),
                    "request_id": request_id,
                    "action": f"{method} {path}",
                    "method": method,
                    "path": path,
                    "outcome": outcome,
                    "status_code": status_code,
                    "duration_ms": round(duration_ms, 2),
                    "actor": {
                        "user_id": user_id,
                        "tenant_id": tenant_id,
                        "ip_address": client_ip,
                        "user_agent": user_agent[:256] if user_agent else None,
                    },
                    "resource": self._extract_resource(path),
                }
            },
        )

        return response

    def _skip_audit(self, path: str) -> bool:
        """Check if path should skip audit logging."""
        skip_prefixes = (
            "/health",
            "/docs",
            "/redoc",
            "/openapi",
        )
        return any(path.startswith(p) for p in skip_prefixes)

    def _extract_resource(self, path: str) -> dict:
        """Extract resource type and ID from path."""
        parts = [p for p in path.split("/") if p]

        resource = {
            "type": None,
            "id": None,
        }

        # Parse common patterns like /api/v1/tenants/{id}
        if len(parts) >= 3 and parts[0] == "api":
            resource["type"] = parts[2] if len(parts) > 2 else None
            resource["id"] = parts[3] if len(parts) > 3 else None
        elif len(parts) >= 2 and parts[0] == "admin":
            resource["type"] = parts[1] if len(parts) > 1 else None
            resource["id"] = parts[2] if len(parts) > 2 else None

        return resource
