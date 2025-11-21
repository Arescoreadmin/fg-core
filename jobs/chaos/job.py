from datetime import datetime, timezone
from pathlib import Path
import json

from loguru import logger

STATE_DIR = Path(__file__).resolve().parents[2] / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
CHAOS_STATE_FILE = STATE_DIR / "chaos_status.json"


async def job() -> None:
    """
    Smoke-test chaos job.

    Real implementation should:
      - inject controlled failures / latency
      - validate resilience / recovery
      - write status for /chaos/status
    """
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
