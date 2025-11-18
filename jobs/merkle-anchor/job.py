import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from loguru import logger

STATE_DIR = Path(__file__).resolve().parents[2] / "state"
STATE_FILE = STATE_DIR / "merkle_anchor_status.json"


def compute_merkle_root_stub() -> str:
    """
    Placeholder: in real life this takes a batch of log digests and builds a Merkle tree.
    Here we just hash the current UTC timestamp as a stand-in.
    """
    now = datetime.now(timezone.utc).isoformat()
    h = hashlib.sha256(now.encode("utf-8")).hexdigest()
    return h


def build_anchor_payload() -> Dict[str, Any]:
    ts = datetime.now(timezone.utc).isoformat()
    root = compute_merkle_root_stub()

    # Stubbed dual-chain txids
    l2_a_txid = hashlib.sha256(f"{root}:L2_A".encode("utf-8")).hexdigest()[:32]
    l2_b_txid = hashlib.sha256(f"{root}:L2_B".encode("utf-8")).hexdigest()[:32]

    return {
        "ts": ts,
        "merkle_root": root,
        "chains": {
            "L2_A": {
                "txid": l2_a_txid,
                "network": "stub-l2-a",
                "status": "confirmed",
            },
            "L2_B": {
                "txid": l2_b_txid,
                "network": "stub-l2-b",
                "status": "confirmed",
            },
        },
        "status": "ok",
        "version": "mvp-0.1",
    }


def persist_status(payload: Dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(payload, indent=2))
    logger.info("merkle_anchor_status_updated", extra={"state_file": str(STATE_FILE)})


def main():
    logger.info("merkle_anchor_job_start")

    payload = build_anchor_payload()
    persist_status(payload)

    logger.info(
        "merkle_anchor_job_done",
        extra={
            "merkle_root": payload["merkle_root"],
            "l2_a_txid": payload["chains"]["L2_A"]["txid"],
            "l2_b_txid": payload["chains"]["L2_B"]["txid"],
        },
    )


if __name__ == "__main__":
    main()
