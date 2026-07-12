"""Deterministic JSON serialization for runtime intelligence dataclasses."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any


def to_json(obj: Any) -> str:
    """Serialize a dataclass to deterministic JSON."""
    if hasattr(obj, "__dataclass_fields__"):
        data = _to_dict(obj)
    else:
        data = obj
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _to_dict(obj: Any) -> Any:
    """Recursively convert dataclass to dict, handling tuples as lists."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_dict(v) for k, v in asdict(obj).items()}
    elif isinstance(obj, (list, tuple)):
        return [_to_dict(x) for x in obj]
    return obj


def from_json(text: str) -> Any:
    return json.loads(text)
