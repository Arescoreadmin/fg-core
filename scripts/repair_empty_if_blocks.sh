#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'INNER'
from __future__ import annotations
from pathlib import Path
import ast
import re

p = Path("api/auth_scopes/resolution.py")
lines = p.read_text(encoding="utf-8").splitlines(True)

def is_blank_or_comment(s: str) -> bool:
    t = s.strip()
    return t == "" or t.startswith("#")

def indent_len(s: str) -> int:
    return len(s) - len(s.lstrip(" "))

out: list[str] = []
i = 0
patched = 0

while i < len(lines):
    ln = lines[i]
    out.append(ln)

    m = re.match(r"^(\s*)if\b.*:\s*$", ln)
    if m:
        base_indent = indent_len(ln)

        j = i + 1
        while j < len(lines) and is_blank_or_comment(lines[j]):
            out.append(lines[j])
            j += 1

        if j >= len(lines):
            out.append(" " * (base_indent + 4) + "pass\n")
            patched += 1
            i = j
            continue

        next_indent = indent_len(lines[j])
        if next_indent <= base_indent:
            out.append(" " * (base_indent + 4) + "pass\n")
            patched += 1
            i += 1
            continue

        i = j
        continue

    i += 1

new_src = "".join(out)
ast.parse(new_src)
p.write_text(new_src, encoding="utf-8")
print(f"OK: inserted pass into {patched} empty if-block(s)")
INNER

ruff format api/auth_scopes/resolution.py
ruff check api/auth_scopes/resolution.py
