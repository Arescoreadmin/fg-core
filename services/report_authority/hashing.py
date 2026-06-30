"""services/report_authority/hashing.py — Deterministic hashing utilities.

All functions are pure, deterministic, and have no side effects.
Canonical hash uses JSON serialization with sorted keys and no extra whitespace
to ensure bit-identical output regardless of dict insertion order.

Algorithm constants should be used rather than magic strings throughout
the rest of the service.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

HASH_ALGORITHM_SHA256 = "sha256"
HASH_ALGORITHM_SHA512 = "sha512"

_SUPPORTED_ALGORITHMS: frozenset[str] = frozenset(
    {HASH_ALGORITHM_SHA256, HASH_ALGORITHM_SHA512}
)


def compute_sha256(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def compute_sha512(data: bytes) -> str:
    """Return the hex-encoded SHA-512 digest of *data*."""
    return hashlib.sha512(data).hexdigest()


def compute_canonical_hash(payload: dict[str, Any]) -> tuple[str, str]:
    """Return (sha256_hex, sha512_hex) of the canonical JSON representation.

    The payload is serialized with sorted keys and no extra whitespace to
    ensure deterministic output regardless of dict insertion order or
    Python runtime version.
    """
    canonical: bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return compute_sha256(canonical), compute_sha512(canonical)


def hash_string(
    value: str,
    algorithm: str = HASH_ALGORITHM_SHA256,
) -> str:
    """Return the hex-encoded digest of *value* using *algorithm*.

    Raises ValueError for unsupported algorithms.
    """
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported hash algorithm: {algorithm!r}. "
            f"Supported: {sorted(_SUPPORTED_ALGORITHMS)}"
        )
    data = value.encode("utf-8")
    if algorithm == HASH_ALGORITHM_SHA256:
        return compute_sha256(data)
    return compute_sha512(data)


def verify_hash(
    data: bytes,
    expected_hash: str,
    algorithm: str = HASH_ALGORITHM_SHA256,
) -> bool:
    """Return True if *data* produces *expected_hash* under *algorithm*.

    Uses direct string equality — acceptable because report hashes are not
    secret material (they are published integrity proofs, not credentials).
    """
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported hash algorithm: {algorithm!r}. "
            f"Supported: {sorted(_SUPPORTED_ALGORITHMS)}"
        )
    if algorithm == HASH_ALGORITHM_SHA256:
        actual = compute_sha256(data)
    else:
        actual = compute_sha512(data)
    return actual == expected_hash
