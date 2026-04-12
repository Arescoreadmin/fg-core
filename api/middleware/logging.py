"""Per-request structured log entry for the core API."""

from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger("frostgate")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Emit one structured log entry per request.

    Captures request_id (set upstream by SecurityHeadersMiddleware), method,
    path, status code, duration, and client IP.  Runs inner-to-SecurityHeaders
    so request.state.request_id is already populated when the log fires.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.time()
        response = await call_next(request)
        log.info(
            "request",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "client_ip": request.client.host if request.client else None,
            },
        )
        return response
