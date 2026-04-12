"""Configure loguru for structured JSON output in job processes.

Call configure_job_logging() at the start of each async job() entry point.
This must NOT be called at module scope to avoid affecting test log capture.
"""

from __future__ import annotations

import os
import re
import sys
import uuid

from loguru import logger

_configured = False

# Strict UUID v4 pattern — same rule as admin_gateway.middleware.request_id.
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def resolve_request_id(parent_request_id: str | None) -> str:
    """Return parent_request_id if it is a valid UUID v4, else generate a fresh one.

    Rules:
    - Valid UUID v4 → returned as-is (lowercased)
    - None, empty, or non-UUID v4 → fresh uuid.uuid4() generated
    - No override is possible once a value is returned (callers must not reassign)
    """
    if parent_request_id:
        stripped = parent_request_id.strip()
        if _UUID4_RE.match(stripped):
            return stripped.lower()
    return str(uuid.uuid4())


def configure_job_logging(service: str = "fg-jobs") -> None:
    """Configure loguru to emit JSON logs to stdout.

    Truly idempotent: after the first successful call this function is a
    no-op. logger.remove() is NOT called on repeated invocations, so any
    sinks attached by the host process (test harnesses, runtime monitors)
    are preserved.
    """
    global _configured
    if _configured:
        return
    logger.remove()
    level = os.getenv("FG_LOG_LEVEL", "INFO").upper()
    logger.add(
        sys.stdout,
        level=level,
        serialize=True,
        backtrace=False,
        diagnose=False,
    )
    _configured = True
