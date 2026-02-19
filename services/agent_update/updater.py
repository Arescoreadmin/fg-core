from __future__ import annotations

import os
from pathlib import Path


def apply_atomic_update(binary: bytes, target_path: str) -> tuple[str, str]:
    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(target_path)
    backup = target.with_suffix(f"{target.suffix}.bak")
    tmp = target.with_suffix(f"{target.suffix}.new")
    tmp.write_bytes(binary)
    os.replace(target, backup)
    os.replace(tmp, target)
    return str(target), str(backup)
