from datetime import datetime, timezone
from pathlib import Path
import json

from loguru import logger

from jobs.logging_config import configure_job_logging, resolve_request_id

STATE_DIR = Path(__file__).resolve().parents[2] / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
CHAOS_STATE_FILE = STATE_DIR / "chaos_status.json"


async def job(request_id: str | None = None) -> None:
    """Smoke-test chaos job.

    Args:
        request_id: Optional parent request_id for trace continuity. Must be a
            valid UUID v4; any other value is replaced with a fresh UUID v4.
            Once resolved it is immutable for the duration of this execution.
    """
    configure_job_logging()
    rid = resolve_request_id(request_id)
    with logger.contextualize(request_id=rid):
        payload = {
            "status": "ok",
            "last_run": datetime.now(timezone.utc).isoformat(),
            "detail": "placeholder chaos job",
        }
        try:
            CHAOS_STATE_FILE.write_text(json.dumps(payload))
            logger.info("chaos.job: wrote placeholder status", extra=payload)
        except Exception as exc:
            logger.error(
                "chaos.job: failed placeholder run",
                extra={"error": str(exc)},
            )
            raise
