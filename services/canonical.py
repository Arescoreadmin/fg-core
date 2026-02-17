from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def utc_iso8601_z_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def parse_utc_iso8601_z(value: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must end with Z")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value
