#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations" / "postgres"

# psycopg3 can interpret %X tokens in some execution paths.
# In SQL migrations we only allow:
#   - escaped format() placeholders like %%I, %%L, %%s, etc.
#   - percent inside a double-percent sequence
#
# Disallow any single '%' followed by an ASCII letter (A-Z/a-z).
RAW_PERCENT_TOKEN = re.compile(r"(?<!%)%[A-Za-z]")  # not preceded by %, i.e. not %%X
# Also disallow a bare '%' at end of file/line which is typically accidental.
BARE_PERCENT = re.compile(r"(?<!%)%(\s|$)")


def main() -> int:
    if not MIGRATIONS.exists():
        print(f"SKIP: {MIGRATIONS} not found", file=sys.stderr)
        return 0

    bad: list[tuple[str, int, str]] = []
    for path in sorted(MIGRATIONS.glob("*.sql")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), start=1):
            if RAW_PERCENT_TOKEN.search(line) or BARE_PERCENT.search(line):
                bad.append((str(path.relative_to(ROOT)), i, line.rstrip()))

    if bad:
        print(
            "ERROR: raw percent tokens found in SQL migrations (psycopg3 hazard):",
            file=sys.stderr,
        )
        for p, line_no, line in bad:
            print(f"  {p}:{line_no}: {line}", file=sys.stderr)
        print(
            "\nFix: remove percent-letter sequences in comments/SQL, or escape as '%%' if intentional.",
            file=sys.stderr,
        )
        return 2

    print("sql-migration-percent-guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
