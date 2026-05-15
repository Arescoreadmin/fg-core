"""Structured JSON logging configuration for fg-core services.

Provides a stdlib-based JSON formatter so every log record emitted by
logging.getLogger() is machine-parseable with a consistent field set.

Usage (ASGI entry point or job run() — NOT module scope):
    from api.logging_config import configure_logging
    configure_logging()          # service defaults to "fg-core"
    configure_logging(service="my-worker")
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

# Attributes that are part of the stdlib LogRecord — excluded from extra payload
_STDLIB_ATTRS: frozenset[str] = frozenset(
    {
        "args",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object.

    Guaranteed fields: timestamp, level, service, event, logger.
    Any extra={...} keys passed to the logger call are merged in.
    """

    def __init__(self, service: str = "fg-core") -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
        ts += f".{int(record.msecs):03d}Z"

        payload: dict[str, Any] = {
            "timestamp": ts,
            "level": record.levelname,
            "service": self._service,
            "event": record.message,
            "logger": record.name,
        }

        # Merge extra= fields (request_id, tenant_id, subject, etc.)
        for key, val in record.__dict__.items():
            if key not in _STDLIB_ATTRS and not key.startswith("_"):
                payload[key] = val

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(service: str = "fg-core") -> None:
    """Configure root logger to emit JSON to stdout.

    Idempotent — a second call is a no-op if JSON logging is already set up.

    MUST be called from ASGI entry points (asgi.py) or job run() functions,
    NOT at module scope, to avoid replacing pytest's log capture handlers.
    """
    root = logging.getLogger()
    if any(
        isinstance(h.formatter, _JsonFormatter) for h in root.handlers if h.formatter
    ):
        return  # already configured

    level = os.getenv("FG_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter(service=service))

    try:
        from api.observability.log_context import (
            TraceContextFilter,
            RequestContextFilter,
        )

        handler.addFilter(TraceContextFilter())
        handler.addFilter(RequestContextFilter())
    except Exception:
        pass  # observability package unavailable in minimal test environments

    root.handlers = [handler]
    root.setLevel(level)
