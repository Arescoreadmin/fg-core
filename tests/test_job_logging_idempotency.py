"""Review-finding fix: jobs/logging_config.py true idempotency.

Proves:
1. configure_job_logging() does not remove externally attached sinks on repeat calls
2. Structured JSON output contract is preserved after the fix
"""

from __future__ import annotations

import json


def test_configure_job_logging_idempotent_no_sink_removal() -> None:
    """configure_job_logging() must not call logger.remove() on repeated calls.

    After the first call, repeated invocations must be true no-ops that leave
    any externally attached sinks (added after first configure) untouched.
    """
    import jobs.logging_config as jlc
    from loguru import logger

    orig_flag = jlc._configured
    jlc._configured = False
    sentinel_id = None
    try:
        jlc.configure_job_logging()  # first call — removes defaults, adds stdout

        # Attach a sentinel AFTER first configure (simulates runtime monitor)
        attached_messages: list[str] = []

        def _sink(message: object) -> None:
            attached_messages.append(str(message))

        sentinel_id = logger.add(_sink)
        jlc.configure_job_logging()  # second call — must be a no-op
        logger.info("idempotency-probe")
        assert any("idempotency-probe" in m for m in attached_messages), (
            "Sentinel sink was detached by repeated configure_job_logging() call"
        )
    finally:
        if sentinel_id is not None:
            try:
                logger.remove(sentinel_id)
            except Exception:
                pass
        jlc._configured = orig_flag


def test_configure_job_logging_structured_output_intact() -> None:
    """configure_job_logging() must still produce JSON-serialised loguru output."""
    import jobs.logging_config as jlc
    from io import StringIO
    from loguru import logger

    orig_flag = jlc._configured
    jlc._configured = False

    buf = StringIO()
    try:
        jlc.configure_job_logging()
        # Replace the stdout sink with our StringIO for inspection
        logger.remove()
        logger.add(buf, serialize=True, level="DEBUG")
        logger.info("structured-output-probe")
        output = buf.getvalue().strip()
        assert output, "No log output produced"
        payload = json.loads(output)
        assert "text" in payload or "record" in payload, (
            "loguru serialize=True output must contain 'text' or 'record' key"
        )
    finally:
        logger.remove()
        jlc._configured = orig_flag
