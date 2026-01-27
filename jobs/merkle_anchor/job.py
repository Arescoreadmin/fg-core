"""
Merkle Anchor Job for FrostGate.

Computes Merkle roots over decision records for tamper-evident logging.
Supports periodic anchoring with status tracking for compliance.

Features:
- Incremental Merkle tree construction
- Anchor status persistence
- Chain validation
- Deferred anchor detection
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

# Configuration
STATE_DIR = Path(__file__).resolve().parents[2] / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
ANCHOR_STATE_FILE = STATE_DIR / "merkle_anchor_status.json"
ANCHOR_HISTORY_FILE = STATE_DIR / "merkle_anchor_history.json"

# Anchor interval configuration
ANCHOR_INTERVAL_SECONDS = int(os.getenv("FG_ANCHOR_INTERVAL", "3600"))  # 1 hour default
MAX_DEFERRED_HOURS = int(os.getenv("FG_ANCHOR_MAX_DEFERRED", "2"))


def sha256_hex(data: str) -> str:
    """Compute SHA-256 hash of string data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_leaf_hash(record: Dict[str, Any]) -> str:
    """Compute hash for a single decision record (leaf node)."""
    # Canonical serialization for deterministic hashing
    canonical = json.dumps(
        {
            "id": record.get("id"),
            "event_id": record.get("event_id"),
            "threat_level": record.get("threat_level"),
            "anomaly_score": record.get("anomaly_score"),
            "rules_triggered": record.get("rules_triggered_json", []),
            "created_at": str(record.get("created_at")),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_hex(canonical)


def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """
    Compute Merkle root from leaf hashes.

    Uses binary tree structure with deterministic ordering.
    Empty list returns zero hash.
    """
    if not leaf_hashes:
        return sha256_hex("empty")

    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    # Build tree level by level
    current_level = leaf_hashes.copy()

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # If odd number, duplicate last element
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            # Parent = hash(left || right)
            parent = sha256_hex(left + right)
            next_level.append(parent)
        current_level = next_level

    return current_level[0]


def compute_merkle_proof(
    leaf_hashes: List[str], leaf_index: int
) -> List[Tuple[str, str]]:
    """
    Compute Merkle proof for a specific leaf.

    Returns list of (sibling_hash, direction) tuples for verification.
    """
    if not leaf_hashes or leaf_index >= len(leaf_hashes):
        return []

    proof = []
    current_level = leaf_hashes.copy()
    index = leaf_index

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left

            # Check if our index is in this pair
            if i == index or i + 1 == index:
                if index % 2 == 0:
                    # We're left, sibling is right
                    proof.append((right, "right"))
                else:
                    # We're right, sibling is left
                    proof.append((left, "left"))

            parent = sha256_hex(left + right)
            next_level.append(parent)

        current_level = next_level
        index = index // 2

    return proof


def verify_merkle_proof(
    leaf_hash: str, proof: List[Tuple[str, str]], root: str
) -> bool:
    """Verify a Merkle proof against a known root."""
    current = leaf_hash

    for sibling_hash, direction in proof:
        if direction == "left":
            current = sha256_hex(sibling_hash + current)
        else:
            current = sha256_hex(current + sibling_hash)

    return current == root


class MerkleAnchorState:
    """Manages Merkle anchor state and history."""

    def __init__(self):
        self.last_anchor_time: Optional[datetime] = None
        self.last_anchor_root: Optional[str] = None
        self.last_anchor_count: int = 0
        self.last_record_id: int = 0
        self.chain_root: Optional[str] = None  # Root of all anchors
        self._load_state()

    def _load_state(self) -> None:
        """Load state from disk."""
        if ANCHOR_STATE_FILE.exists():
            try:
                data = json.loads(ANCHOR_STATE_FILE.read_text())
                if data.get("last_anchor_time"):
                    self.last_anchor_time = datetime.fromisoformat(
                        data["last_anchor_time"]
                    )
                self.last_anchor_root = data.get("last_anchor_root")
                self.last_anchor_count = data.get("last_anchor_count", 0)
                self.last_record_id = data.get("last_record_id", 0)
                self.chain_root = data.get("chain_root")
            except Exception as e:
                logger.warning(f"merkle_anchor: failed to load state: {e}")

    def save_state(self) -> None:
        """Persist state to disk."""
        data = {
            "last_anchor_time": (
                self.last_anchor_time.isoformat() if self.last_anchor_time else None
            ),
            "last_anchor_root": self.last_anchor_root,
            "last_anchor_count": self.last_anchor_count,
            "last_record_id": self.last_record_id,
            "chain_root": self.chain_root,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        ANCHOR_STATE_FILE.write_text(json.dumps(data, indent=2))

    def add_anchor(
        self,
        merkle_root: str,
        record_count: int,
        last_record_id: int,
    ) -> Dict[str, Any]:
        """Record a new anchor."""
        now = datetime.now(timezone.utc)

        # Update chain root (hash of previous chain_root + new root)
        if self.chain_root:
            self.chain_root = sha256_hex(self.chain_root + merkle_root)
        else:
            self.chain_root = merkle_root

        self.last_anchor_time = now
        self.last_anchor_root = merkle_root
        self.last_anchor_count = record_count
        self.last_record_id = last_record_id

        anchor_record = {
            "timestamp": now.isoformat(),
            "merkle_root": merkle_root,
            "record_count": record_count,
            "last_record_id": last_record_id,
            "chain_root": self.chain_root,
        }

        # Append to history
        self._append_history(anchor_record)
        self.save_state()

        return anchor_record

    def _append_history(self, record: Dict[str, Any]) -> None:
        """Append anchor to history file."""
        history = []
        if ANCHOR_HISTORY_FILE.exists():
            try:
                history = json.loads(ANCHOR_HISTORY_FILE.read_text())
            except Exception:
                pass

        history.append(record)

        # Keep last 1000 anchors
        if len(history) > 1000:
            history = history[-1000:]

        ANCHOR_HISTORY_FILE.write_text(json.dumps(history, indent=2))

    def is_deferred(self) -> Tuple[bool, float]:
        """Check if anchor is deferred (past max allowed time)."""
        if not self.last_anchor_time:
            return False, 0.0

        elapsed = (datetime.now(timezone.utc) - self.last_anchor_time).total_seconds()
        max_seconds = MAX_DEFERRED_HOURS * 3600

        return elapsed > max_seconds, elapsed / 3600

    def get_status(self) -> Dict[str, Any]:
        """Get current anchor status."""
        is_deferred, hours_since = self.is_deferred()

        return {
            "status": "deferred" if is_deferred else "ok",
            "last_anchor_time": (
                self.last_anchor_time.isoformat() if self.last_anchor_time else None
            ),
            "last_anchor_root": self.last_anchor_root,
            "last_anchor_count": self.last_anchor_count,
            "last_record_id": self.last_record_id,
            "chain_root": self.chain_root,
            "hours_since_anchor": round(hours_since, 2),
            "is_deferred": is_deferred,
            "max_deferred_hours": MAX_DEFERRED_HOURS,
        }


# Global state instance
_state: Optional[MerkleAnchorState] = None


def get_state() -> MerkleAnchorState:
    global _state
    if _state is None:
        _state = MerkleAnchorState()
    return _state


async def fetch_decisions_since(last_id: int) -> List[Dict[str, Any]]:
    """Fetch decision records since last anchored ID."""
    # Import here to avoid circular imports
    from api.db import get_session
    from api.db_models import DecisionRecord

    records = []
    try:
        session = get_session()
        query = session.query(DecisionRecord).filter(DecisionRecord.id > last_id)
        query = query.order_by(DecisionRecord.id.asc())
        query = query.limit(10000)  # Batch limit

        for record in query.all():
            records.append(
                {
                    "id": record.id,
                    "event_id": record.event_id,
                    "threat_level": record.threat_level,
                    "anomaly_score": record.anomaly_score,
                    "rules_triggered_json": record.rules_triggered_json,
                    "created_at": record.created_at,
                }
            )
    except Exception as e:
        logger.error(f"merkle_anchor: failed to fetch decisions: {e}")

    return records


async def job() -> None:
    """
    Merkle anchor job - computes Merkle root over recent decisions.

    This job should be run periodically (hourly by default) to:
    1. Fetch all decisions since last anchor
    2. Compute Merkle root over those decisions
    3. Update chain root
    4. Persist anchor status
    """
    state = get_state()

    logger.info(
        "merkle_anchor.job: starting",
        extra={"last_record_id": state.last_record_id},
    )

    try:
        # Fetch decisions since last anchor
        records = await fetch_decisions_since(state.last_record_id)

        if not records:
            # No new records, just update status
            status = {
                "status": "ok",
                "anchored_at": datetime.now(timezone.utc).isoformat(),
                "detail": "no new decisions to anchor",
                "last_record_id": state.last_record_id,
                "chain_root": state.chain_root,
            }
            ANCHOR_STATE_FILE.write_text(json.dumps(status, indent=2))
            logger.info("merkle_anchor.job: no new decisions", extra=status)
            return

        # Compute leaf hashes
        leaf_hashes = [compute_leaf_hash(r) for r in records]

        # Compute Merkle root
        merkle_root = compute_merkle_root(leaf_hashes)

        # Get last record ID
        last_record_id = max(r["id"] for r in records)

        # Record anchor
        anchor_record = state.add_anchor(
            merkle_root=merkle_root,
            record_count=len(records),
            last_record_id=last_record_id,
        )

        # Write status file for /anchor/status endpoint
        status = {
            "status": "ok",
            "anchored_at": anchor_record["timestamp"],
            "merkle_root": merkle_root,
            "chain_root": state.chain_root,
            "record_count": len(records),
            "last_record_id": last_record_id,
        }
        ANCHOR_STATE_FILE.write_text(json.dumps(status, indent=2))

        logger.info(
            "merkle_anchor.job: anchored successfully",
            extra={
                "merkle_root": merkle_root[:16] + "...",
                "record_count": len(records),
                "last_record_id": last_record_id,
            },
        )

    except Exception as exc:
        logger.error(
            "merkle_anchor.job: failed",
            extra={"error": str(exc)},
        )
        # Write error status
        error_status = {
            "status": "error",
            "error": str(exc),
            "anchored_at": datetime.now(timezone.utc).isoformat(),
        }
        ANCHOR_STATE_FILE.write_text(json.dumps(error_status, indent=2))
        raise


def get_anchor_status() -> Dict[str, Any]:
    """Get current anchor status for API endpoint."""
    state = get_state()
    return state.get_status()


def verify_decision_in_anchor(
    decision_record: Dict[str, Any],
    anchor_root: str,
    proof: List[Tuple[str, str]],
) -> bool:
    """Verify a decision record is included in an anchor."""
    leaf_hash = compute_leaf_hash(decision_record)
    return verify_merkle_proof(leaf_hash, proof, anchor_root)
