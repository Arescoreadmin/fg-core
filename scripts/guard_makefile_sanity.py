from __future__ import annotations

from pathlib import Path
import re
import sys

p = Path("Makefile")
if not p.exists():
    print("ERROR: Makefile not found", file=sys.stderr)
    raise SystemExit(1)

s = p.read_text("utf-8", errors="replace")

# Indented "target:" lines are almost always paste accidents inside recipes.
bad = re.findall(r"(?m)^[ \t]+[A-Za-z0-9_.-]+::?:\s*$", s)
bad = [b for b in bad if not b.strip().startswith((".PHONY",))]

if bad:
    print("ERROR: Makefile contains indented target-like lines:", file=sys.stderr)
    for b in bad[:50]:
        print(f"  {b.rstrip()}", file=sys.stderr)
    raise SystemExit(2)

print("Makefile sanity: OK")
