from datetime import datetime, timezone
from pathlib import Path
import json

from loguru import logger

STATE_DIR = Path(__file__).resolve().parents[2] / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
ANCHOR_STATE_FILE = STATE_DIR / "merkle_anchor_status.json"


async def job() -> None:
    """
    Smoke-test Merkle anchor job.

    Real implementation should:
      - compute Merkle root over decisions
      - anchor to external attestation system
      - write status for /anchor/status
    """
    payload = {
        "status": "ok",
        "anchored_at": datetime.now(timezone.utc).isoformat(),
        "detail": "placeholder Merkle anchor job",
    }
    try:
        ANCHOR_STATE_FILE.write_text(json.dumps(payload))
        logger.info("merkle_anchor.job: wrote placeholder status", extra=payload)
    except Exception as exc:
        logger.error(
            "merkle_anchor.job: failed placeholder run",
            extra={"error": str(exc)},
        )
        raise
