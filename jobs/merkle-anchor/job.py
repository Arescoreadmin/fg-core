# jobs/merkle-anchor/job.py
import time
from datetime import datetime, timezone

from loguru import logger


def compute_merkle_root_stub() -> str:
    # Placeholder: later wire to Loki batch & real Merkle tree
    now = datetime.now(timezone.utc).isoformat()
    return f"stub-merkle-root-{now}"


def main():
    logger.info("Starting Merkle anchor job (MVP stub)")
    root = compute_merkle_root_stub()
    # In real version: push to dual L2 chains, handle deferred status, etc.
    logger.info(f"Computed Merkle root (stub)={root}")
    # Simulate anchor txid
    logger.info("Anchor submitted to L2_A/L2_B (stub)")


if __name__ == "__main__":
    main()
