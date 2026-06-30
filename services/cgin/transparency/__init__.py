"""CGIN Transparency Authority — append-only Merkle-backed transparency log.

PR 17.7D: Provides cryptographic transparency for CGIN governance operations.
"""

from __future__ import annotations

from services.cgin.key_management import ACTIVE_PROVIDER_REGISTRY
from services.cgin.transparency.entry import (
    TRANSPARENCY_SCHEMA_VERSION,
    TRANSPARENCY_VERSION,
    TransparencyEntry,
    _compute_entry_id,
)
from services.cgin.transparency.ledger import TransparencyLedger
from services.cgin.transparency.merkle import MembershipProof, MerkleTree
from services.cgin.transparency.root import TransparencyRoot
from services.cgin.transparency.statistics import IntegrityStatistics
from services.cgin.transparency.store import MemoryTransparencyStore, TransparencyStore
from services.cgin.transparency.verify import TransparencyVerificationResult

_DEFAULT_STORE = MemoryTransparencyStore()
ACTIVE_TRANSPARENCY_LEDGER = TransparencyLedger(
    store=_DEFAULT_STORE,
    key_provider=ACTIVE_PROVIDER_REGISTRY.active(),
)

__all__ = [
    "TransparencyEntry",
    "TransparencyRoot",
    "MerkleTree",
    "MembershipProof",
    "TransparencyLedger",
    "TransparencyStore",
    "MemoryTransparencyStore",
    "TransparencyVerificationResult",
    "IntegrityStatistics",
    "ACTIVE_TRANSPARENCY_LEDGER",
    "TRANSPARENCY_VERSION",
    "TRANSPARENCY_SCHEMA_VERSION",
    "_compute_entry_id",
]
