"""services/report_authority/trust_appendix.py

Deterministic trust appendix builder.
"""

from __future__ import annotations

from typing import Any


def build_trust_appendix(
    trust_entries: list[dict[str, Any]],
    *,
    root_authority: str = "",
    chain_depth: int = 0,
) -> dict[str, Any]:
    """Build the trust appendix.

    Trust entries are sorted by entry_id for determinism. The returned dict is
    suitable for direct embedding in a report_data payload.
    """
    sorted_entries = sorted(trust_entries, key=lambda x: x.get("entry_id", ""))
    return {
        "root_authority": root_authority,
        "chain_depth": chain_depth,
        "trust_entry_count": len(sorted_entries),
        "entries": sorted_entries,
    }
