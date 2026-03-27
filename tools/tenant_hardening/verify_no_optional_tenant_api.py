#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_DIR = ROOT / "api"

PATTERN = re.compile(r"Optional\[[^\]]*tenant_id|tenant_id:\s*Optional")

def main() -> int:
    remaining = []
    for path in sorted(API_DIR.rglob("*.py")):
        rel = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if PATTERN.search(line):
                remaining.append((rel, lineno, line.rstrip()))

    if not remaining:
        print("NO_OPTIONAL_TENANT_ID_REMAINS_IN_API")
        return 0

    for rel, lineno, line in remaining:
        print(f"{rel}:{lineno}: {line}")

    print(f"\nREMAINING_COUNT={len(remaining)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())