#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'PY'
from __future__ import annotations
from pathlib import Path

p = Path("api/auth_scopes/resolution.py")
lines = p.read_text(encoding="utf-8").splitlines(True)

def find_block(start_idx: int) -> int:
    # find closing paren line at column 0: ")"
    for j in range(start_idx + 1, len(lines)):
        if lines[j].startswith(")"):
            return j
    return -1

moved = []
i = 0
while i < len(lines):
    if lines[i].startswith("from .validation import ("):
        end = find_block(i)
        if end == -1:
            raise SystemExit("ERROR: could not find end of 'from .validation import (' block")
        # pull out illegal inserted imports that appear inside the block
        j = i + 1
        while j < end:
            stripped = lines[j].strip()
            if stripped in ("from fastapi import HTTPException", "import os"):
                moved.append(lines.pop(j))
                end -= 1
                continue
            j += 1
        # insert moved imports right after the block closes
        insert_at = end + 1
        for imp in moved:
            # avoid duplicates if already present elsewhere
            if any(imp.strip() == ln.strip() for ln in lines):
                continue
            lines.insert(insert_at, imp if imp.endswith("\n") else imp + "\n")
            insert_at += 1
        moved.clear()
        i = insert_at
        continue
    i += 1

p.write_text("".join(lines), encoding="utf-8")
print("OK: repaired imports in api/auth_scopes/resolution.py")
PY
