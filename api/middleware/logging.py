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
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            extra: dict = {
                "request_id": getattr(request.state, "request_id", None),
                "trace_id": getattr(request.state, "trace_id", None),
                "span_id": getattr(request.state, "span_id", None),
                "tenant_id": getattr(request.state, "tenant_id", None),
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "client_ip": request.client.host if request.client else None,
            }
            log.info("request", extra=extra)

            try:
                from api.observability.metrics import (
                    HTTP_REQUEST_DURATION,
                    HTTP_5XX_TOTAL,
                )

                status_class = f"{status_code // 100}xx"
                HTTP_REQUEST_DURATION.labels(
                    method=request.method, status_class=status_class
                ).observe(time.time() - start)
                if status_code >= 500:
                    HTTP_5XX_TOTAL.labels(method=request.method).inc()
            except Exception:
                pass
