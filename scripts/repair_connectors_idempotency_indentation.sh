#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TARGET="services/connectors/idempotency.py"

if [[ ! -f "$TARGET" ]]; then
  echo "ERROR: missing $TARGET"
  exit 1
fi

echo "== Repair indentation in $TARGET (context-aware) =="

python - <<'PY'
from __future__ import annotations

from pathlib import Path
import re

p = Path("services/connectors/idempotency.py")
lines = p.read_text(encoding="utf-8").splitlines(True)

# Lines we may have inserted with wrong indentation.
NEEDLE_PATTERNS = [
    re.compile(r"^\s*now\s*=\s*_now_utc_naive\(\)\s*$"),
    re.compile(r"^\s*expires_at\s*=\s*_now_utc_naive\(\)\s*\+\s*timedelta\(.*$"),
    re.compile(r"^\s*coerced_expires_at\s*=\s*_coerce_sqlite_dt\(.+\)\s*$"),
    re.compile(r"^\s*# If we can't parse/normalize, fail closed: do not reclaim\.\s*$"),
]

def indent_of(s: str) -> int:
    return len(s) - len(s.lstrip(" "))

def is_blank(s: str) -> bool:
    return s.strip() == ""

def prev_nonblank_index(i: int) -> int | None:
    j = i - 1
    while j >= 0:
        if not is_blank(lines[j]):
            return j
        j -= 1
    return None

def compute_expected_indent(i: int) -> int:
    """
    Heuristic:
    - If previous nonblank line ends with ':', indent = prev_indent + 4
    - Else indent = prev_indent
    This matches typical Python block indentation.
    """
    j = prev_nonblank_index(i)
    if j is None:
        return 0
    prev = lines[j].rstrip("\n")
    base = indent_of(prev)
    if prev.rstrip().endswith(":"):
        return base + 4
    return base

changed = False

for i, line in enumerate(lines):
    raw = line.rstrip("\n")
    if any(pat.match(raw) for pat in NEEDLE_PATTERNS):
        expected = compute_expected_indent(i)
        stripped = raw.lstrip(" ")
        # Only rewrite if the indent is clearly wrong
        if indent_of(raw) != expected:
            lines[i] = (" " * expected) + stripped + "\n"
            changed = True

# Extra safety: fix accidental over-indent of bare returns introduced by bad patching.
# If we find "return True" / "return False" with deeper indent than previous nonblank + 4, clamp it.
RET_PAT = re.compile(r"^\s*return\s+(True|False|None)\s*$")
for i, line in enumerate(lines):
    raw = line.rstrip("\n")
    if RET_PAT.match(raw):
        j = prev_nonblank_index(i)
        if j is None:
            continue
        prev = lines[j].rstrip("\n")
        prev_indent = indent_of(prev)
        # Return should generally be either same as prev indent or prev+4 depending on block.
        # We clamp only if it's wildly deeper (>= prev+8).
        if indent_of(raw) >= prev_indent + 8:
            expected = compute_expected_indent(i)
            stripped = raw.lstrip(" ")
            if indent_of(raw) != expected:
                lines[i] = (" " * expected) + stripped + "\n"
                changed = True

if changed:
    p.write_text("".join(lines), encoding="utf-8")
    print("Patched indentation:", p)
else:
    print("No indentation changes required (file may already be clean).")
PY

echo "== Compile check (must pass) =="
python -m py_compile "$TARGET"

echo "== Format + lint (best effort) =="
ruff format "$TARGET" >/dev/null 2>&1 || true
ruff check "$TARGET" >/dev/null 2>&1 || true

echo "== Run targeted tests =="
pytest -q tests/test_connectors_idempotency.py

echo "== Done =="