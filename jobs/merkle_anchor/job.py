"""
Real Merkle Anchor Job for FrostGate Core.

Computes a Merkle root over audit log entries for a fixed time window,
persists leaf hashes and root, and anchors to an external verifiable log.

External anchoring uses an append-only hash-chained anchor file that can be
verified offline (similar to RFC3161 timestamping but self-contained).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from loguru import logger

# State directory for anchor artifacts
STATE_DIR = Path(os.getenv("FG_STATE_DIR", str(Path(__file__).resolve().parents[2] / "state")))
STATE_DIR.mkdir(parents=True, exist_ok=True)

# Anchor file paths
ANCHOR_STATE_FILE = STATE_DIR / "merkle_anchor_status.json"
ANCHOR_LOG_FILE = STATE_DIR / "merkle_anchor_log.jsonl"
ANCHOR_CHAIN_FILE = STATE_DIR / "merkle_anchor_chain.json"

# Default window: 1 hour
DEFAULT_WINDOW_HOURS = int(os.getenv("FG_ANCHOR_WINDOW_HOURS", "1"))


def sha256_hex(data: str | bytes) -> str:
    """Compute SHA-256 hash of data, return hex string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Produce deterministic JSON representation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class MerkleTree:
    """Simple Merkle tree implementation for audit entries."""

    def __init__(self, leaves: list[str]):
        """Initialize with list of leaf hashes (hex strings)."""
        self.leaves = leaves
        self.levels: list[list[str]] = []
        self._build()

    def _build(self) -> None:
        """Build Merkle tree from leaves up to root."""
        if not self.leaves:
            self.levels = [[sha256_hex("")]]
            return

        # Level 0 = leaves
        current_level = list(self.leaves)
        self.levels.append(current_level)

        # Build upward until we have a single root
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = sha256_hex(left + right)
                next_level.append(parent)
            current_level = next_level
            self.levels.append(current_level)

    @property
    def root(self) -> str:
        """Return the Merkle root hash."""
        return self.levels[-1][0] if self.levels else sha256_hex("")

    def get_proof(self, index: int) -> list[tuple[str, str]]:
        """Get Merkle proof for leaf at index. Returns list of (sibling_hash, direction)."""
        if not self.leaves or index >= len(self.leaves):
            return []

        proof = []
        idx = index
        for level in self.levels[:-1]:
            is_right = idx % 2 == 1
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx < len(level):
                sibling = level[sibling_idx]
                direction = "left" if is_right else "right"
                proof.append((sibling, direction))
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[tuple[str, str]], root: str) -> bool:
        """Verify a Merkle proof."""
        current = leaf_hash
        for sibling, direction in proof:
            if direction == "left":
                current = sha256_hex(sibling + current)
            else:
                current = sha256_hex(current + sibling)
        return current == root


def get_audit_entries_in_window(
    window_start: datetime,
    window_end: datetime,
    db_path: Optional[str] = None,
) -> list[dict[str, Any]]:
    """
    Fetch audit log entries from the database for the given time window.

    Returns entries sorted deterministically by (created_at, id).
    """
    import sqlite3

    db_path = db_path or os.getenv("FG_SQLITE_PATH", str(STATE_DIR / "frostgate.db"))

    if not Path(db_path).exists():
        logger.warning(f"Database not found: {db_path}")
        return []

    entries = []
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if security_audit_log table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='security_audit_log'"
        )
        if not cursor.fetchone():
            # Try decisions table instead
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='decisions'"
            )
            if cursor.fetchone():
                cursor.execute(
                    """
                    SELECT id, created_at, tenant_id, event_type, threat_level,
                           rules_triggered_json, request_json, response_json
                    FROM decisions
                    WHERE created_at >= ? AND created_at < ?
                    ORDER BY created_at ASC, id ASC
                    """,
                    (window_start.isoformat(), window_end.isoformat()),
                )
                for row in cursor.fetchall():
                    entries.append(dict(row))
            conn.close()
            return entries

        cursor.execute(
            """
            SELECT id, created_at, event_type, event_category, severity,
                   tenant_id, key_prefix, client_ip, request_id, request_path,
                   request_method, success, reason, details_json
            FROM security_audit_log
            WHERE created_at >= ? AND created_at < ?
            ORDER BY created_at ASC, id ASC
            """,
            (window_start.isoformat(), window_end.isoformat()),
        )

        for row in cursor.fetchall():
            entries.append(dict(row))

        conn.close()
    except Exception as e:
        logger.error(f"Failed to fetch audit entries: {e}")

    return entries


def compute_leaf_hash(entry: dict[str, Any]) -> str:
    """Compute deterministic hash for a single audit entry."""
    return sha256_hex(canonical_json(entry))


def load_anchor_chain() -> dict[str, Any]:
    """Load the anchor chain state from disk."""
    if ANCHOR_CHAIN_FILE.exists():
        try:
            return json.loads(ANCHOR_CHAIN_FILE.read_text())
        except Exception:
            pass
    return {"prev_anchor_hash": None, "anchor_count": 0}


def save_anchor_chain(state: dict[str, Any]) -> None:
    """Save the anchor chain state to disk."""
    ANCHOR_CHAIN_FILE.write_text(json.dumps(state, indent=2))


def create_anchor_record(
    merkle_root: str,
    window_start: datetime,
    window_end: datetime,
    leaf_count: int,
    leaf_hashes: list[str],
    prev_anchor_hash: Optional[str],
) -> dict[str, Any]:
    """
    Create an anchor record that can be verified later.

    The anchor includes:
    - Merkle root
    - Window metadata
    - Previous anchor hash (for chaining)
    - Computed anchor hash
    """
    anchor_time = datetime.now(timezone.utc)

    record = {
        "anchor_version": "1.0",
        "anchor_time": anchor_time.isoformat(),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "leaf_count": leaf_count,
        "merkle_root": merkle_root,
        "leaf_hashes": leaf_hashes,
        "prev_anchor_hash": prev_anchor_hash,
    }

    # Compute anchor hash over the record (excluding anchor_hash itself)
    anchor_hash = sha256_hex(canonical_json(record))
    record["anchor_hash"] = anchor_hash

    return record


def append_to_anchor_log(record: dict[str, Any]) -> None:
    """Append anchor record to the append-only anchor log."""
    with ANCHOR_LOG_FILE.open("a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def verify_anchor_record(record: dict[str, Any]) -> tuple[bool, str]:
    """
    Verify an anchor record's integrity.

    Returns (is_valid, message).
    """
    # Extract and remove anchor_hash for verification
    expected_hash = record.get("anchor_hash")
    if not expected_hash:
        return False, "Missing anchor_hash"

    record_copy = {k: v for k, v in record.items() if k != "anchor_hash"}
    computed_hash = sha256_hex(canonical_json(record_copy))

    if computed_hash != expected_hash:
        return False, f"Anchor hash mismatch: expected {expected_hash}, got {computed_hash}"

    # Verify Merkle root by recomputing from leaf hashes
    leaf_hashes = record.get("leaf_hashes", [])
    merkle_root = record.get("merkle_root")

    if leaf_hashes:
        tree = MerkleTree(leaf_hashes)
        if tree.root != merkle_root:
            return False, f"Merkle root mismatch: expected {merkle_root}, got {tree.root}"

    return True, "Valid"


def verify_anchor_chain(log_path: Optional[Path] = None) -> tuple[bool, list[str]]:
    """
    Verify the entire anchor chain for integrity.

    Returns (is_valid, list of error messages).
    """
    log_path = log_path or ANCHOR_LOG_FILE
    if not log_path.exists():
        return True, []  # Empty chain is valid

    errors = []
    prev_hash: Optional[str] = None

    with log_path.open("r") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"Line {i+1}: Invalid JSON: {e}")
                continue

            # Verify record integrity
            is_valid, msg = verify_anchor_record(record)
            if not is_valid:
                errors.append(f"Line {i+1}: {msg}")
                continue

            # Verify chain linkage
            record_prev = record.get("prev_anchor_hash")
            if record_prev != prev_hash:
                errors.append(
                    f"Line {i+1}: Chain broken - expected prev_hash {prev_hash}, got {record_prev}"
                )

            prev_hash = record.get("anchor_hash")

    return len(errors) == 0, errors


def verify_entry_in_anchor(
    entry: dict[str, Any],
    anchor_record: dict[str, Any],
) -> tuple[bool, str]:
    """
    Verify that an entry is included in an anchor record.

    Returns (is_valid, message).
    """
    leaf_hash = compute_leaf_hash(entry)
    leaf_hashes = anchor_record.get("leaf_hashes", [])

    if leaf_hash not in leaf_hashes:
        return False, f"Entry hash {leaf_hash} not found in anchor"

    # Rebuild Merkle tree and verify
    tree = MerkleTree(leaf_hashes)
    idx = leaf_hashes.index(leaf_hash)
    proof = tree.get_proof(idx)

    if not MerkleTree.verify_proof(leaf_hash, proof, tree.root):
        return False, "Merkle proof verification failed"

    return True, "Verified"


async def job() -> dict[str, Any]:
    """
    Merkle anchor job - computes and anchors audit entries.

    Workflow:
    1. Determine time window (last N hours)
    2. Fetch audit entries from database
    3. Compute leaf hashes and Merkle root
    4. Create anchor record with chain linkage
    5. Append to anchor log
    6. Update status file

    Returns job result dict.
    """
    window_hours = DEFAULT_WINDOW_HOURS
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=window_hours)

    logger.info(
        f"merkle_anchor.job: starting window {window_start.isoformat()} to {window_end.isoformat()}"
    )

    # Fetch audit entries
    entries = get_audit_entries_in_window(window_start, window_end)
    logger.info(f"merkle_anchor.job: found {len(entries)} entries in window")

    # Compute leaf hashes
    leaf_hashes = [compute_leaf_hash(e) for e in entries]

    # Build Merkle tree
    tree = MerkleTree(leaf_hashes)
    merkle_root = tree.root

    # Load chain state
    chain_state = load_anchor_chain()
    prev_anchor_hash = chain_state.get("prev_anchor_hash")

    # Create anchor record
    anchor_record = create_anchor_record(
        merkle_root=merkle_root,
        window_start=window_start,
        window_end=window_end,
        leaf_count=len(entries),
        leaf_hashes=leaf_hashes,
        prev_anchor_hash=prev_anchor_hash,
    )

    # Append to log
    append_to_anchor_log(anchor_record)

    # Update chain state
    chain_state["prev_anchor_hash"] = anchor_record["anchor_hash"]
    chain_state["anchor_count"] = chain_state.get("anchor_count", 0) + 1
    save_anchor_chain(chain_state)

    # Write status file
    status = {
        "status": "ok",
        "anchored_at": anchor_record["anchor_time"],
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "entry_count": len(entries),
        "merkle_root": merkle_root,
        "anchor_hash": anchor_record["anchor_hash"],
        "anchor_count": chain_state["anchor_count"],
    }
    ANCHOR_STATE_FILE.write_text(json.dumps(status, indent=2))
    logger.info("merkle_anchor.job: anchor created", extra=status)

    return status


# Export verification functions for external use
__all__ = [
    "MerkleTree",
    "sha256_hex",
    "canonical_json",
    "compute_leaf_hash",
    "verify_anchor_record",
    "verify_anchor_chain",
    "verify_entry_in_anchor",
    "get_audit_entries_in_window",
    "job",
]
