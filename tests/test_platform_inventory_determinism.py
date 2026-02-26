from __future__ import annotations

import hashlib
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


FILES = [
    Path("artifacts/PLATFORM_INVENTORY.md"),
    Path("artifacts/PLATFORM_GAPS.md"),
    Path("artifacts/platform_inventory.json"),
]


@contextmanager
def _preserve_files(paths: list[Path]):
    snapshots: dict[Path, bytes | None] = {}
    for path in paths:
        snapshots[path] = path.read_bytes() if path.exists() else None
    try:
        yield
    finally:
        for path, content in snapshots.items():
            if content is None:
                if path.exists():
                    path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


def _hashes():
    return [hashlib.sha256(p.read_bytes()).hexdigest() for p in FILES]


def test_platform_inventory_deterministic():
    with _preserve_files(FILES):
        subprocess.run(
            [sys.executable, "scripts/generate_platform_inventory.py"], check=True
        )
        h1 = _hashes()
        subprocess.run(
            [sys.executable, "scripts/generate_platform_inventory.py"], check=True
        )
        h2 = _hashes()
    assert h1 == h2


def test_platform_inventory_sections_present():
    with _preserve_files(FILES):
        subprocess.run(
            [sys.executable, "scripts/generate_platform_inventory.py"], check=True
        )
        inv = Path("artifacts/PLATFORM_INVENTORY.md").read_text(encoding="utf-8")
        gaps = Path("artifacts/PLATFORM_GAPS.md").read_text(encoding="utf-8")
    assert "## Planes" in inv
    assert "## Enterprise readiness checklist status" in inv
    assert "# Platform Gaps" in gaps
