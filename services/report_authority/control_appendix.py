"""services/report_authority/control_appendix.py

Deterministic control appendix builder.
"""

from __future__ import annotations

from typing import Any


def build_control_appendix(
    control_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the control appendix.

    Items are sorted by control_id for determinism. The returned dict is
    suitable for direct embedding in a report_data payload.
    """
    sorted_items = sorted(control_items, key=lambda x: x.get("control_id", ""))
    return {
        "control_count": len(sorted_items),
        "items": sorted_items,
    }
