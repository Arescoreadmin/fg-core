"""Configure loguru for structured JSON output in job processes.

Call configure_job_logging() at the start of each async job() entry point.
This must NOT be called at module scope to avoid affecting test log capture.
"""

from __future__ import annotations

import os
import sys

from loguru import logger


def configure_job_logging(service: str = "fg-jobs") -> None:
    """Configure loguru to emit JSON logs to stdout.

    Idempotent — subsequent calls are no-ops.
    """
    logger.remove()
    level = os.getenv("FG_LOG_LEVEL", "INFO").upper()
    logger.add(
        sys.stdout,
        level=level,
        serialize=True,
        backtrace=False,
        diagnose=False,
    )
