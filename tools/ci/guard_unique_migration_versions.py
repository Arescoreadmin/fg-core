#!/usr/bin/env python3
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations" / "postgres"


def main() -> int:
    if not MIGRATIONS.exists():
        print(f"SKIP: {MIGRATIONS} not found", file=sys.stderr)
        return 0

    versions: dict[str, list[str]] = defaultdict(list)
    for path in sorted(MIGRATIONS.glob("*.sql")):
        if path.name.endswith(".rollback.sql"):
            continue
        version = path.name.split("_", 1)[0]
        versions[version].append(path.name)

    duplicates = {v: names for v, names in versions.items() if len(names) > 1}
    if duplicates:
        print("ERROR: duplicate migration version prefixes detected:", file=sys.stderr)
        for version, names in sorted(duplicates.items()):
            joined = ", ".join(sorted(names))
            print(f"  {version}: {joined}", file=sys.stderr)
        return 2

    print("unique-migration-versions: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
