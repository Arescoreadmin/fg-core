"""services/report_authority/evidence_appendix.py

Deterministic evidence appendix builder.
"""

from __future__ import annotations

from typing import Any


def build_evidence_appendix(
    evidence_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the evidence appendix.

    Items are sorted by evidence_id for determinism. The returned dict is
    suitable for direct embedding in a report_data payload.
    """
    sorted_items = sorted(evidence_items, key=lambda x: x.get("evidence_id", ""))
    return {
        "evidence_count": len(sorted_items),
        "items": sorted_items,
    }
