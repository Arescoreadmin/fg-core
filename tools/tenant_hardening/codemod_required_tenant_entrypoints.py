#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_DIR = ROOT / "api"

TARGET_FILES = [
    "admin.py",
    "control_plane_v2.py",
    "ui_dashboards.py",
    "keys.py",
    "stats.py",
    "decisions.py",
    "ingest.py",
    "schemas.py",
]

REPLACEMENTS = [
    (
        re.compile(r"tenant_id:\s*Optional\[str\]\s*=\s*Query\(default=None,"),
        "tenant_id: str = Query(...,",
    ),
    (
        re.compile(r"tenant_id:\s*Optional\[str\]\s*=\s*Query\(None,"),
        "tenant_id: str = Query(...,",
    ),
    (
        re.compile(r"tenant_id_param:\s*Optional\[str\]\s*=\s*Query\(None,"),
        "tenant_id_param: str = Query(...,",
    ),
    (
        re.compile(r"x_tenant_id:\s*Optional\[str\]\s*=\s*Header\(default=None,"),
        "x_tenant_id: str = Header(...,",
    ),
    (
        re.compile(r"tenant_id:\s*Optional\[str\]\s*=\s*Field\(default=None,"),
        "tenant_id: str = Field(...,",
    ),
]


def process_file(path: Path) -> tuple[int, bool]:
    text = path.read_text(encoding="utf-8")
    original = text
    count = 0

    for pattern, replacement in REPLACEMENTS:
        text, n = pattern.subn(replacement, text)
        count += n

    if text != original:
        path.write_text(text, encoding="utf-8")
        return count, True
    return count, False


def main() -> int:
    changed = 0
    total_replacements = 0

    for rel in TARGET_FILES:
        path = API_DIR / rel
        if not path.exists():
            continue
        count, did_change = process_file(path)
        total_replacements += count
        if did_change:
            changed += 1
            print(f"UPDATED {path.relative_to(ROOT)} replacements={count}")

    print(f"FILES_CHANGED={changed}")
    print(f"TOTAL_REPLACEMENTS={total_replacements}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
