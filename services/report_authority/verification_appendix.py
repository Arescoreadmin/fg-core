"""services/report_authority/verification_appendix.py

Deterministic verification appendix builder.
"""
from __future__ import annotations

from typing import Any


def build_verification_appendix(
    verification_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the verification appendix.

    Items are sorted by verification_id for determinism. The returned dict is
    suitable for direct embedding in a report_data payload.
    """
    sorted_items = sorted(
        verification_items, key=lambda x: x.get("verification_id", "")
    )
    return {
        "verification_count": len(sorted_items),
        "items": sorted_items,
    }
