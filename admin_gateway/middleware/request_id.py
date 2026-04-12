"""Request ID Middleware.

Propagates or generates request IDs for tracing.
"""

from __future__ import annotations

import re
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

REQUEST_ID_HEADER = "X-Request-Id"

# Strict UUID v4 pattern — prevents log injection from attacker-controlled header values.
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _safe_request_id(raw: str | None) -> str:
    """Return raw if it is a valid UUID v4, otherwise generate a fresh one."""
    if raw:
        stripped = raw.strip()
        if _UUID4_RE.match(stripped):
            return stripped.lower()
    return str(uuid.uuid4())


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Middleware to handle request ID propagation."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = _safe_request_id(request.headers.get(REQUEST_ID_HEADER))

        # Store in request state for access by handlers
        request.state.request_id = request_id

        # Process request
        response = await call_next(request)

        # Add request ID to response headers
        response.headers[REQUEST_ID_HEADER] = request_id

        return response
