"""Transparency root data type — frozen, cryptographically signed Merkle root."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TransparencyRoot:
    """Immutable, signed Merkle root over all entries in the transparency log.

    Produced by TransparencyLedger.build_root(). The root_id is computed
    deterministically from the canonical serialization of the root body.
    """

    root_id: str  # SHA-256 hex of canonical(root_digest + entry_count + generation_timestamp)
    root_digest: str  # Merkle root as hex string
    entry_count: int
    generation_timestamp: str
    tree_height: int
    algorithm: str  # "sha256"
    authority_version: str
    schema_version: str
    transparency_version: str
    signature: str  # b64url signature from Key Provider
    signing_algorithm: str  # from provider
    provider_name: str  # from provider
