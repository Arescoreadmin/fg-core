#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[2]
API_DIR = ROOT / "api"

PATTERN = re.compile(r"Optional\[[^\]]*tenant_id|tenant_id:\s*Optional")

BUCKETS = [
    (
        "entrypoints",
        [
            "admin.py",
            "control_plane_v2.py",
            "ui_dashboards.py",
            "keys.py",
            "stats.py",
            "decisions.py",
            "ingest.py",
        ],
    ),
    (
        "helpers",
        [
            "auth_scopes/resolution.py",
            "auth_scopes/validation.py",
            "control_plane_v2.py",
            "ui_dashboards.py",
        ],
    ),
    ("internals", []),
]


def classify(rel_path: str) -> str:
    for bucket, members in BUCKETS:
        if any(rel_path.endswith(m) for m in members):
            return bucket
    return "internals"


def main() -> int:
    hits = defaultdict(list)

    for path in sorted(API_DIR.rglob("*.py")):
        rel = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if PATTERN.search(line):
                bucket = classify(rel)
                hits[bucket].append((rel, lineno, line.rstrip()))

    total = 0
    for bucket in ("entrypoints", "helpers", "internals"):
        print(f"\n## {bucket.upper()}")
        for rel, lineno, line in hits[bucket]:
            total += 1
            print(f"{rel}:{lineno}: {line}")

    print(f"\nTOTAL_MATCHES={total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
