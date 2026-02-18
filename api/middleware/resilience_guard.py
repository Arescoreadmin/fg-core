from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from services.resilience import current_service_state, allow_in_degraded, is_degraded_mode, shed_non_critical


def _request_id(request) -> str:
    value = request.headers.get("X-Request-Id") or request.headers.get("x-request-id")
    if value is None:
        return "unknown"
    return str(value).strip() or "unknown"


class ResilienceGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = str(request.url.path)
        method = str(request.method).upper()

        if shed_non_critical(path):
            return JSONResponse(
                status_code=503,
                content={"detail": {
                    "error_code": "SERVICE_OVERLOADED_SHED",
                    "request_id": _request_id(request),
                    "service_state": current_service_state(),
                    "retry_after_seconds": 5,
                }},
                headers={"Retry-After": "5"},
            )

        if is_degraded_mode() and not allow_in_degraded(path, method):
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                return JSONResponse(
                    status_code=503,
                    content={"detail": {
                        "error_code": "SERVICE_DEGRADED_READONLY",
                        "request_id": _request_id(request),
                        "service_state": current_service_state(),
                        "retry_after_seconds": 0,
                    }},
                )

        return await call_next(request)
