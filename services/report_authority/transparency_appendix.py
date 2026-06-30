"""services/report_authority/transparency_appendix.py

Deterministic transparency appendix builder.
"""
from __future__ import annotations

from typing import Any


def build_transparency_appendix(
    log_entries: list[dict[str, Any]],
    *,
    merkle_root: str = "",
    transparency_log_url: str = "",
) -> dict[str, Any]:
    """Build the transparency appendix.

    Log entries are sorted by log_entry_id for determinism. The returned dict
    is suitable for direct embedding in a report_data payload.
    """
    sorted_entries = sorted(log_entries, key=lambda x: x.get("log_entry_id", ""))
    return {
        "merkle_root": merkle_root,
        "transparency_log_url": transparency_log_url,
        "log_entry_count": len(sorted_entries),
        "entries": sorted_entries,
    }
