"""Merkle tree implementation with domain-separated hashing.

Prevents second-preimage attacks via:
  leaf:     SHA256(0x00 || data)
  interior: SHA256(0x01 || left || right)

For odd number of nodes at a level, the last node is duplicated.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

EMPTY_LEAF = b"\x00" * 32  # 32 zero bytes for empty tree


def _hash_leaf(data: bytes) -> bytes:
    """Hash a leaf with domain separator 0x00."""
    return hashlib.sha256(b"\x00" + data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash an interior node pair with domain separator 0x01."""
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    """Deterministic SHA-256 binary Merkle tree.

    Leaves: raw bytes (NOT pre-hashed). Leaf hashes computed internally.
    Empty tree: root = EMPTY_LEAF, height = 0.
    Single leaf: root = hash_leaf(leaves[0]), height = 1.
    Odd-count levels: last node duplicated to make even.
    """

    def __init__(self, leaves: list[bytes]) -> None:
        """Build the tree from raw leaf bytes."""
        self._leaves = list(leaves)
        self._leaf_hashes: list[bytes] = [_hash_leaf(leaf) for leaf in self._leaves]

    def root(self) -> bytes:
        """Return 32-byte Merkle root. Empty tree returns EMPTY_LEAF."""
        if not self._leaf_hashes:
            return EMPTY_LEAF
        level = list(self._leaf_hashes)
        while len(level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                next_level.append(_hash_pair(left, right))
            level = next_level
        return level[0]

    def height(self) -> int:
        """Tree height. Empty = 0, single leaf = 1, n leaves = ceil(log2(n)) + 1."""
        n = len(self._leaf_hashes)
        if n == 0:
            return 0
        if n == 1:
            return 1
        return math.ceil(math.log2(n)) + 1

    def proof(self, index: int) -> list[tuple[str, str]]:
        """Return membership proof for leaf at index.

        Returns list of (side, hex_hash) tuples where side is 'left' or 'right'.
        Empty list for single-leaf trees.
        Raises IndexError if index is out of range.
        """
        n = len(self._leaf_hashes)
        if n == 0:
            raise IndexError("Empty tree has no leaves")
        if index < 0 or index >= n:
            raise IndexError(f"index {index} out of range for {n} leaves")

        if n == 1:
            return []

        path: list[tuple[str, str]] = []
        level = list(self._leaf_hashes)
        idx = index

        while len(level) > 1:
            # Pad odd level
            padded = list(level)
            if len(padded) % 2 == 1:
                padded.append(padded[-1])

            if idx % 2 == 0:
                # current node is left — sibling is right
                sibling_idx = idx + 1
                path.append(("right", padded[sibling_idx].hex()))
            else:
                # current node is right — sibling is left
                sibling_idx = idx - 1
                path.append(("left", padded[sibling_idx].hex()))

            # Compute next level
            next_level: list[bytes] = []
            for i in range(0, len(padded), 2):
                next_level.append(_hash_pair(padded[i], padded[i + 1]))
            level = next_level
            idx = idx // 2

        return path

    @staticmethod
    def verify_proof(
        leaf_bytes: bytes, proof: list[tuple[str, str]], expected_root_hex: str
    ) -> bool:
        """Verify a membership proof. Never raises. Returns bool."""
        try:
            current = _hash_leaf(leaf_bytes)
            for side, sibling_hex in proof:
                sibling = bytes.fromhex(sibling_hex)
                if side == "right":
                    current = _hash_pair(current, sibling)
                elif side == "left":
                    current = _hash_pair(sibling, current)
                else:
                    return False
            return current.hex() == expected_root_hex
        except Exception:
            return False


@dataclass(frozen=True)
class MembershipProof:
    """Serializable membership proof for a single entry in the Merkle tree."""

    entry_id: str
    entry_index: int
    leaf_hash: str  # hex
    proof_path: list[tuple[str, str]]  # list of (side, hex_hash)
    root_digest: str  # hex — the root this proof is valid for
    root_id: str
    algorithm: str  # "sha256"
    transparency_version: str

    def to_dict(self) -> dict:
        """Serialize for API responses."""
        return {
            "entry_id": self.entry_id,
            "entry_index": self.entry_index,
            "leaf_hash": self.leaf_hash,
            "proof_path": [{"side": s, "hash": h} for s, h in self.proof_path],
            "root_digest": self.root_digest,
            "root_id": self.root_id,
            "algorithm": self.algorithm,
            "transparency_version": self.transparency_version,
        }

    @staticmethod
    def from_dict(d: dict) -> "MembershipProof":
        """Deserialize. Validates required fields."""
        required = {
            "entry_id",
            "entry_index",
            "leaf_hash",
            "proof_path",
            "root_digest",
            "root_id",
            "algorithm",
            "transparency_version",
        }
        missing = required - set(d.keys())
        if missing:
            raise ValueError(f"MembershipProof.from_dict: missing fields {missing}")
        path = [(item["side"], item["hash"]) for item in d["proof_path"]]
        return MembershipProof(
            entry_id=d["entry_id"],
            entry_index=d["entry_index"],
            leaf_hash=d["leaf_hash"],
            proof_path=path,
            root_digest=d["root_digest"],
            root_id=d["root_id"],
            algorithm=d["algorithm"],
            transparency_version=d["transparency_version"],
        )
