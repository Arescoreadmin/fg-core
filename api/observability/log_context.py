"""Structured log context management for FrostGate.

Three mechanisms:
  1. TraceContextFilter  — reads the active OTel span and injects
     trace_id / span_id into every log record automatically.
  2. RequestContextFilter — reads per-request fields (tenant_id, request_id,
     provider_id, policy_version, retrieval_mode) from contextvars and injects
     them into every log record.
  3. SecretRedactionFilter — removes fields whose names match known sensitive
     patterns (authorization, api_key, bearer_token, provider_payload, etc.)
     before they can reach the log sink. Defense-in-depth against accidental
     credential logging.

Usage in configure_logging():
    handler.addFilter(TraceContextFilter())
    handler.addFilter(RequestContextFilter())
    handler.addFilter(SecretRedactionFilter())

Usage in request handlers / middleware:
    set_log_context(tenant_id="acme", provider_id="openai")
    ...
    clear_log_context()
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any, Optional

from opentelemetry import trace

# ---------------------------------------------------------------------------
# Per-request context vars (propagated across async boundaries automatically)
# ---------------------------------------------------------------------------

_ctx_tenant_id: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)
_ctx_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_ctx_provider_id: ContextVar[Optional[str]] = ContextVar("provider_id", default=None)
_ctx_policy_version: ContextVar[Optional[str]] = ContextVar(
    "policy_version", default=None
)
_ctx_retrieval_mode: ContextVar[Optional[str]] = ContextVar(
    "retrieval_mode", default=None
)

_ALL_VARS = (
    ("tenant_id", _ctx_tenant_id),
    ("request_id", _ctx_request_id),
    ("provider_id", _ctx_provider_id),
    ("policy_version", _ctx_policy_version),
    ("retrieval_mode", _ctx_retrieval_mode),
)


def set_log_context(**kwargs: Optional[str]) -> None:
    """Set one or more context fields for the current async context."""
    mapping = {
        "tenant_id": _ctx_tenant_id,
        "request_id": _ctx_request_id,
        "provider_id": _ctx_provider_id,
        "policy_version": _ctx_policy_version,
        "retrieval_mode": _ctx_retrieval_mode,
    }
    for key, value in kwargs.items():
        if key in mapping:
            mapping[key].set(value)


def clear_log_context() -> None:
    """Reset all context fields to None."""
    for _, var in _ALL_VARS:
        var.set(None)


def get_log_context() -> dict[str, Any]:
    """Return current context as a dict (None values omitted)."""
    return {k: v.get() for k, v in _ALL_VARS if v.get() is not None}


class TraceContextFilter(logging.Filter):
    """Inject OTel trace_id and span_id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.is_valid:
            record.trace_id = format(ctx.trace_id, "032x")  # type: ignore[attr-defined]
            record.span_id = format(ctx.span_id, "016x")  # type: ignore[attr-defined]
        else:
            record.trace_id = None  # type: ignore[attr-defined]
            record.span_id = None  # type: ignore[attr-defined]
        return True


class RequestContextFilter(logging.Filter):
    """Inject per-request context fields (tenant_id, provider_id, etc.) into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, var in _ALL_VARS:
            val = var.get()
            if not hasattr(record, key):
                setattr(record, key, val)
        return True


# Fields whose presence in a log record is a security violation. The filter
# deletes them and substitutes a "[REDACTED]" placeholder so the field name
# remains visible in the log structure (alerting on accidental credential
# logging) without the value leaking.
_SECRET_FIELD_FRAGMENTS: frozenset[str] = frozenset(
    {
        "authorization",
        "bearer",
        "api_key",
        "apikey",
        "api-key",
        "token",
        "password",
        "secret",
        "credential",
        "private_key",
        "signing_key",
        "provider_payload",
        "raw_prompt",
        "raw_chunk",
        "x_api_key",
    }
)


def _is_secret_field(name: str) -> bool:
    n = name.lower().replace("-", "_").replace(" ", "_")
    return any(frag in n for frag in _SECRET_FIELD_FRAGMENTS)


class SecretRedactionFilter(logging.Filter):
    """Strip sensitive field values from log records before they reach the sink.

    Fields whose names contain known secret patterns are replaced with the
    literal string "[REDACTED]". The field NAME is preserved so engineers
    can detect accidental credential logging in log search.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key in list(vars(record).keys()):
            if _is_secret_field(key):
                setattr(record, key, "[REDACTED]")
        return True
