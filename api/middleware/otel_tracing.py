"""OTel tracing middleware for FrostGate.

Creates a server-side span for every HTTP request, propagates W3C TraceContext
from inbound headers, and stores trace_id / span_id in request.state so that
the request logging middleware and structured log formatter can include them.
"""

from __future__ import annotations

import logging
from typing import Any

from opentelemetry import trace
from opentelemetry.propagate import extract
from opentelemetry.trace import SpanKind, Status, StatusCode

from api.observability.tracing import get_tracer
from api.observability.log_context import set_log_context

log = logging.getLogger("frostgate.tracing")


class OTelTracingMiddleware:
    """Raw ASGI middleware — wraps the full request/response cycle in an OTel span.

    Placed outermost so the span captures total wall time including all inner
    middleware. Does not extend BaseHTTPMiddleware to avoid the asyncio overhead
    of an extra Task per request.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1"): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        parent_ctx = extract(headers)

        method = scope.get("method", "")
        path = scope.get("path", "")
        span_name = f"{method} {path}" if method else path

        tracer = get_tracer("frostgate.http")

        with tracer.start_as_current_span(
            span_name,
            context=parent_ctx,
            kind=SpanKind.SERVER,
        ) as span:
            _attach_request_attributes(span, scope, headers)

            span_ctx = span.get_span_context()
            if span_ctx.is_valid:
                trace_id = format(span_ctx.trace_id, "032x")
                span_id = format(span_ctx.span_id, "016x")
                _set_state(scope, "trace_id", trace_id)
                _set_state(scope, "span_id", span_id)
                set_log_context(request_id=_get_state(scope, "request_id"))

            status_code = 500
            try:

                async def _send(message: Any) -> None:
                    nonlocal status_code
                    if message.get("type") == "http.response.start":
                        status_code = message.get("status", 500)
                        span.set_attribute("http.status_code", status_code)
                        if status_code >= 500:
                            span.set_status(Status(StatusCode.ERROR))
                        else:
                            span.set_status(Status(StatusCode.OK))
                    await send(message)

                await self.app(scope, receive, _send)
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                raise


def _attach_request_attributes(
    span: trace.Span, scope: dict[str, Any], headers: dict[str, str]
) -> None:
    from api.observability.telemetry_policy import get_policy

    attrs: dict[str, str] = {
        "http.method": scope.get("method", ""),
        "http.target": scope.get("path", ""),
        "http.scheme": scope.get("scheme", "http"),
    }
    tenant_id = headers.get("x-tenant-id", "")
    if tenant_id:
        attrs["frostgate.tenant_id"] = tenant_id
    request_id = headers.get("x-request-id", "")
    if request_id:
        attrs["frostgate.request_id"] = request_id

    for k, v in get_policy().filter_span_attributes(attrs).items():
        span.set_attribute(k, v)


def _set_state(scope: dict[str, Any], key: str, value: Any) -> None:
    state = scope.get("state")
    if state is not None:
        try:
            setattr(state, key, value)
        except Exception:
            pass


def _get_state(scope: dict[str, Any], key: str) -> Any:
    state = scope.get("state")
    if state is not None:
        return getattr(state, key, None)
    return None
