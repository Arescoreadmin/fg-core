"""Resolve test node IDs to plane/module/owner metadata via ownership_map.yaml."""

from __future__ import annotations

import fnmatch
import functools
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
_OWNERSHIP_PATH = REPO_ROOT / "tools/testing/policy/ownership_map.yaml"

_UNRESOLVED = ("", "", "")


@functools.lru_cache(maxsize=1)
def _load_ownership() -> list[dict[str, Any]]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return []
    if not _OWNERSHIP_PATH.exists():
        return []
    data = yaml.safe_load(_OWNERSHIP_PATH.read_text(encoding="utf-8"))
    return data.get("owners", []) if isinstance(data, dict) else []


def node_id_to_path(node_id: str) -> str:
    """Extract the file path portion from a pytest node_id."""
    return node_id.split("::")[0] if "::" in node_id else node_id


def classify_test_path(
    test_path: str,
    owners: list[dict[str, Any]] | None = None,
) -> tuple[str, str, str]:
    """Return (plane, module_id, owner) for a test file path, or ('','','') if unresolved."""
    if owners is None:
        owners = _load_ownership()
    for entry in owners:
        for glob in entry.get("path_globs", []):
            if fnmatch.fnmatch(test_path, glob):
                return (
                    str(entry.get("plane", "")),
                    str(entry.get("module_id", "")),
                    str(entry.get("owner", "")),
                )
    return _UNRESOLVED
