from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ParsedKey:
    key_id: str
    key: bytes
    created_at_utc: str
    retired_at_utc: str | None = None


def _parse_utc_iso8601_z(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeError(f"{field} must be UTC ISO8601 with Z suffix")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def _decode_key_material(item: dict[str, Any]) -> bytes:
    if "key_b64" in item:
        try:
            raw = base64.b64decode(str(item["key_b64"]), validate=True)
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("invalid base64 key material") from exc
    elif "key_hex" in item:
        try:
            raw = binascii.unhexlify(str(item["key_hex"]))
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("invalid hex key material") from exc
    else:
        raise RuntimeError("key entry must include key_b64 or key_hex")
    if len(raw) < 32:
        raise RuntimeError("hmac key material must be at least 32 bytes")
    return raw


def _parse_json_keyring(raw: str) -> dict[str, bytes]:
    parsed = json.loads(raw)
    if isinstance(parsed, dict) and isinstance(parsed.get("keys"), list):
        key_items = parsed["keys"]
    elif isinstance(parsed, list):
        key_items = parsed
    else:
        raise RuntimeError("*_HMAC_KEYS_JSON must be list or {'keys': [...]} schema")

    out: dict[str, bytes] = {}
    seen: set[str] = set()
    for item in key_items:
        if not isinstance(item, dict):
            raise RuntimeError("key entry must be object")
        key_id = str(item.get("key_id") or "").strip()
        if not key_id:
            raise RuntimeError("key entry missing key_id")
        if key_id in seen:
            raise RuntimeError("duplicate key_id in keyring")
        seen.add(key_id)
        created = _parse_utc_iso8601_z(
            str(item.get("created_at_utc") or ""), "created_at_utc"
        )
        retired = item.get("retired_at_utc")
        if retired is not None:
            retired_v = _parse_utc_iso8601_z(str(retired), "retired_at_utc")
            if datetime.fromisoformat(
                retired_v.replace("Z", "+00:00")
            ) < datetime.fromisoformat(created.replace("Z", "+00:00")):
                raise RuntimeError("retired_at_utc must be >= created_at_utc")
        out[key_id] = _decode_key_material(item)
    if not out:
        raise RuntimeError("keyring must not be empty")
    return out


def load_hmac_keys(
    prefix: str, default_key_id: str = "v1"
) -> tuple[str, dict[str, bytes]]:
    raw_json = (os.getenv(f"{prefix}_HMAC_KEYS_JSON") or "").strip()
    keys: dict[str, bytes] = {}
    if raw_json:
        keys.update(_parse_json_keyring(raw_json))

    current = (
        os.getenv(f"{prefix}_HMAC_KEY_CURRENT") or os.getenv(f"{prefix}_HMAC_KEY") or ""
    ).strip()
    current_id = (
        os.getenv(f"{prefix}_HMAC_KEY_ID_CURRENT")
        or os.getenv(f"{prefix}_HMAC_KEY_ID")
        or default_key_id
    ).strip()
    if current:
        current_bytes = current.encode("utf-8")
        if len(current_bytes) < 32:
            raise RuntimeError(f"{prefix} current key must be at least 32 bytes")
        keys[current_id] = current_bytes

    prev = (os.getenv(f"{prefix}_HMAC_KEY_PREV") or "").strip()
    prev_id = (os.getenv(f"{prefix}_HMAC_KEY_ID_PREV") or "prev").strip()
    if prev:
        prev_bytes = prev.encode("utf-8")
        if len(prev_bytes) < 32:
            raise RuntimeError(f"{prefix} previous key must be at least 32 bytes")
        keys[prev_id] = prev_bytes

    if not keys:
        raise RuntimeError(f"no {prefix} hmac keys configured")
    if current_id not in keys:
        current_id = sorted(keys.keys())[0]
    return current_id, keys
