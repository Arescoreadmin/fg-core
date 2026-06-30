"""Transparency integrity statistics."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from services.cgin.transparency.entry import TRANSPARENCY_VERSION

if TYPE_CHECKING:
    from services.cgin.transparency.ledger import TransparencyLedger
    from services.cgin.transparency.store import TransparencyStore


@dataclass(frozen=True)
class IntegrityStatistics:
    """Snapshot of the current transparency ledger integrity state."""

    entry_count: int
    root_count: int
    tree_height: int
    average_proof_length: float
    algorithm: str
    transparency_version: str
    generated_at: str


def compute_statistics(
    store: "TransparencyStore",
    ledger: "TransparencyLedger",
) -> IntegrityStatistics:
    """Return current integrity statistics for the ledger."""

    entries = store.all_entries()
    n = len(entries)

    if n == 0:
        tree_height = 0
        avg_proof_length = 0.0
    elif n == 1:
        tree_height = 1
        avg_proof_length = 0.0
    else:
        tree_height = math.ceil(math.log2(n)) + 1
        # proof length = tree_height - 1 for any non-trivial tree
        avg_proof_length = float(tree_height - 1)

    return IntegrityStatistics(
        entry_count=n,
        root_count=store.root_count(),
        tree_height=tree_height,
        average_proof_length=avg_proof_length,
        algorithm="sha256",
        transparency_version=TRANSPARENCY_VERSION,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
    )
