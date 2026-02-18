from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ContractLoadError(RuntimeError):
    pass


def load_json_contract(
    path: Path,
    *,
    root: Path,
    max_bytes: int = 256 * 1024,
    refuse_symlink: bool = True,
    refuse_hardlink: bool = True,
) -> dict[str, Any]:
    if ".." in path.parts:
        raise ContractLoadError(f"path traversal denied: {path}")

    resolved_root = root.resolve()
    resolved_path = path.resolve(strict=True)
    if resolved_root not in resolved_path.parents and resolved_path != resolved_root:
        raise ContractLoadError(f"path outside allowed root: {path}")

    if refuse_symlink and (path.is_symlink() or resolved_path.is_symlink()):
        raise ContractLoadError(f"symlink contract denied: {path}")

    st = resolved_path.stat()
    size = st.st_size
    if size > max_bytes:
        raise ContractLoadError(f"contract too large: {path} ({size} > {max_bytes})")
    if refuse_hardlink and getattr(st, "st_nlink", 1) > 1:
        raise ContractLoadError(f"hardlink contract denied: {path}")

    try:
        return json.loads(resolved_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ContractLoadError(f"invalid json in {path}: {exc}") from exc
