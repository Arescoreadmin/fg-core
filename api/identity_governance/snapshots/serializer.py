"""api/identity_governance/snapshots/serializer.py — Canonical snapshot serialization."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import typing
from datetime import datetime, timezone
from enum import Enum
from typing import Any, get_type_hints, get_origin, get_args


# ---------------------------------------------------------------------------
# Datetime helpers
# ---------------------------------------------------------------------------


def _format_dt(dt: datetime) -> str:
    """Format datetime as UTC ISO 8601 with Z suffix and microsecond precision."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _parse_dt(s: str) -> datetime:
    """Parse ISO 8601 datetime string (handles Z and +00:00 suffixes)."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


# ---------------------------------------------------------------------------
# Canonical serialization (dict conversion)
# ---------------------------------------------------------------------------


def _to_serializable(obj: Any) -> Any:
    """Recursively convert an object to a JSON-serializable form."""
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, datetime):
        return _format_dt(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (tuple, list)):
        return [_to_serializable(item) for item in obj]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: _to_serializable(getattr(obj, f.name))
            for f in sorted(dataclasses.fields(obj), key=lambda f: f.name)
        }
    return obj


def _data_fields_dict(snapshot: Any) -> dict[str, Any]:
    """Extract all non-meta fields from a snapshot as a sorted serializable dict."""
    if not dataclasses.is_dataclass(snapshot) or isinstance(snapshot, type):
        raise TypeError(f"Expected a dataclass instance, got {type(snapshot)}")
    result = {}
    for f in sorted(dataclasses.fields(snapshot), key=lambda f: f.name):
        if f.name == "meta":
            continue
        result[f.name] = _to_serializable(getattr(snapshot, f.name))
    return result


# ---------------------------------------------------------------------------
# Public API: serialize / fingerprint / replay
# ---------------------------------------------------------------------------


def serialize_snapshot(snapshot: Any) -> str:
    """Return canonical JSON string of the full snapshot (including meta).

    Keys are sorted, no extra whitespace, deterministic across calls.
    """
    if not dataclasses.is_dataclass(snapshot) or isinstance(snapshot, type):
        raise TypeError(f"Expected a dataclass instance, got {type(snapshot)}")
    data = {
        f.name: _to_serializable(getattr(snapshot, f.name))
        for f in sorted(dataclasses.fields(snapshot), key=lambda f: f.name)
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def fingerprint_snapshot(snapshot: Any) -> str:
    """Return SHA-256 hex digest of the canonical DATA fields (non-meta).

    The meta field (including generated_at) is EXCLUDED so two snapshots
    with identical data but different generation timestamps produce the
    same fingerprint.
    """
    data = _data_fields_dict(snapshot)
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_replay_version(*parts: object) -> str:
    """Return SHA-256 hex[:16] of canonical JSON of input parts.

    Identical inputs always produce identical output (stable across calls).
    """
    payload = json.dumps(
        [str(p) for p in parts],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Deserialization helpers
# ---------------------------------------------------------------------------


def _reconstruct(value: Any, hint: Any) -> Any:  # noqa: PLR0911, PLR0912
    """Reconstruct a Python value from JSON-deserialized data using a type hint."""
    if value is None:
        return None

    origin = get_origin(hint)
    args = get_args(hint)

    # Optional[X] / Union[X, None] — unwrap
    if origin is typing.Union:
        inner_args = [a for a in args if a is not type(None)]
        if value is None:
            return None
        if len(inner_args) == 1:
            return _reconstruct(value, inner_args[0])
        # Multi-type union: return as-is (not used in our types)
        return value

    # tuple[X, ...] or tuple[X, Y, ...]
    if origin is tuple:
        if not args:
            return tuple(value)
        if len(args) == 2 and args[1] is Ellipsis:
            # Homogeneous variable-length tuple: tuple[X, ...]
            inner = args[0]
            return tuple(_reconstruct(item, inner) for item in value)
        else:
            # Fixed-length tuple: tuple[str, str] or tuple[str, float]
            return tuple(_reconstruct(v, t) for v, t in zip(value, args))

    # list[X]
    if origin is list:
        inner = args[0] if args else Any
        return [_reconstruct(item, inner) for item in value]

    # Concrete types (no generic origin)
    if isinstance(hint, type):
        if hint is datetime:
            return _parse_dt(value)
        if issubclass(hint, Enum):
            return hint(value)
        if hint is float:
            return float(value)
        if hint is int:
            return int(value)
        if hint is bool:
            return bool(value)
        if hint is str:
            return str(value)
        if dataclasses.is_dataclass(hint):
            return _reconstruct_dataclass(value, hint)

    return value


def _reconstruct_dataclass(data: dict[str, Any], cls: type) -> Any:
    """Reconstruct a dataclass instance from a dict using cls's type hints."""
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        raw = data.get(f.name)
        hint = hints.get(f.name, Any)
        kwargs[f.name] = _reconstruct(raw, hint)
    return cls(**kwargs)


# ---------------------------------------------------------------------------
# Public API: deserialize
# ---------------------------------------------------------------------------


def deserialize_snapshot(raw: str, cls: type) -> Any:
    """Deserialize a canonical JSON string back into a snapshot instance of cls."""
    data: dict[str, Any] = json.loads(raw)
    return _reconstruct_dataclass(data, cls)
