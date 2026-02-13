#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any


def normalize_openapi(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a detached, deterministically serializable OpenAPI object."""
    # Deep-copy through json to avoid mutating caller-owned nested structures.
    return json.loads(json.dumps(payload))


def render_openapi(payload: dict[str, Any]) -> str:
    """Canonical rendering shared by generator + gate checks."""
    normalized = normalize_openapi(payload)
    return json.dumps(normalized, indent=2, sort_keys=True) + "\n"


def parse_openapi_text(text: str) -> dict[str, Any]:
    return normalize_openapi(json.loads(text))
