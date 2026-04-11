"""Configure loguru for structured JSON output in job processes.

Call configure_job_logging() at the start of each async job() entry point.
This must NOT be called at module scope to avoid affecting test log capture.
"""

from __future__ import annotations

import os
import sys

from loguru import logger

_configured = False


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
