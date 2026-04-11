"""Structured JSON logging configuration for Admin Gateway.

See api/logging_config.py for the canonical JsonFormatter implementation.
This module provides the same pattern for the gateway service.

Usage (from admin_gateway/asgi.py — NOT from build_app or module scope):
    from admin_gateway.logging_config import configure_gateway_logging
    configure_gateway_logging()
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

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

    def __init__(self, service: str = "admin-gateway") -> None:
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

        for key, val in record.__dict__.items():
            if key not in _STDLIB_ATTRS and not key.startswith("_"):
                payload[key] = val

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_gateway_logging() -> None:
    """Configure root logger to emit JSON to stdout for Admin Gateway.

    Idempotent — a second call is a no-op if JSON logging is already set up.

    Call from admin_gateway/asgi.py, NOT from build_app() or module scope.
    """
    root = logging.getLogger()
    if any(
        isinstance(h.formatter, _JsonFormatter) for h in root.handlers if h.formatter
    ):
        return

    level = os.getenv("FG_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter(service="admin-gateway"))
    root.handlers = [handler]
    root.setLevel(level)
