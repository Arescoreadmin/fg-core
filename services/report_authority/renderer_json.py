"""services/report_authority/renderer_json.py

Deterministic JSON renderer. Same inputs always produce identical bytes.
"""

from __future__ import annotations

import json
from typing import Any


def render_json(report_data: dict[str, Any]) -> bytes:
    """Render report data as canonical deterministic JSON bytes.

    Uses sort_keys=True, separators=(',', ':'), ensure_ascii=False.
    Returns UTF-8 encoded bytes.
    """
    return json.dumps(
        report_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def render_json_pretty(report_data: dict[str, Any]) -> bytes:
    """Human-readable JSON with stable ordering."""
    return json.dumps(
        report_data,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")
