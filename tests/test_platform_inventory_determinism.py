from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


FILES = [
    Path("artifacts/PLATFORM_INVENTORY.md"),
    Path("artifacts/PLATFORM_GAPS.md"),
    Path("artifacts/platform_inventory.json"),
]


def _hashes():
    return [hashlib.sha256(p.read_bytes()).hexdigest() for p in FILES]


def test_platform_inventory_deterministic():
    subprocess.run([sys.executable, "scripts/generate_platform_inventory.py"], check=True)
    h1 = _hashes()
    subprocess.run([sys.executable, "scripts/generate_platform_inventory.py"], check=True)
    h2 = _hashes()
    assert h1 == h2


def test_platform_inventory_sections_present():
    subprocess.run([sys.executable, "scripts/generate_platform_inventory.py"], check=True)
    inv = Path("artifacts/PLATFORM_INVENTORY.md").read_text(encoding="utf-8")
    gaps = Path("artifacts/PLATFORM_GAPS.md").read_text(encoding="utf-8")
    assert "## Planes" in inv
    assert "## Enterprise readiness checklist status" in inv
    assert "# Platform Gaps" in gaps
