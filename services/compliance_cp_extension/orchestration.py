from __future__ import annotations

from datetime import datetime, timezone


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
