"""services/report_authority/remediation_appendix.py

Deterministic remediation appendix builder.
"""

from __future__ import annotations

from typing import Any


def build_remediation_appendix(
    remediation_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the remediation appendix.

    Items are sorted by remediation_id for determinism. The returned dict is
    suitable for direct embedding in a report_data payload.
    """
    sorted_items = sorted(remediation_items, key=lambda x: x.get("remediation_id", ""))
    return {
        "remediation_count": len(sorted_items),
        "items": sorted_items,
    }
