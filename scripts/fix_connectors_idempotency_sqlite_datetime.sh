#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TARGET="services/connectors/idempotency.py"

if [[ ! -f "$TARGET" ]]; then
  echo "ERROR: missing $TARGET"
  exit 1
fi

echo "== Patch SQLite datetime handling (name-agnostic) in $TARGET =="

python - <<'PY'
from __future__ import annotations

from pathlib import Path
import re

p = Path("services/connectors/idempotency.py")
src = p.read_text(encoding="utf-8")

# --- Helper injection -------------------------------------------------

helper_block = r'''
def _now_utc_naive() -> datetime:
    """
    SQLite frequently returns naive datetimes for DateTime columns.
    To avoid naive/aware comparison bugs, use naive UTC consistently in SQLite paths.
    """
    return datetime.utcnow().replace(tzinfo=None)


def _coerce_sqlite_dt(value) -> datetime | None:
    """
    Coerce SQLite-returned DateTime values into naive UTC datetime for safe comparison.

    We may see:
    - datetime (naive or tz-aware)
    - string (ISO-ish)
    - None
    """
    if value is None:
        return None

    if isinstance(value, str):
        v = value.strip()
        if v.endswith("Z"):
            v = v[:-1]
        try:
            dt = datetime.fromisoformat(v)
        except Exception:
            # fail closed: treat as non-reclaimable
            return None
        value = dt

    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            value = value.replace(tzinfo=None)
        return value

    return None
'''.lstrip("\n")

if "def _now_utc_naive()" not in src:
    # Insert after existing _now_utc() if present, else after imports.
    m = re.search(r"(?s)(^def _now_utc\(\)\s*->\s*datetime:\s*\n(?:[ \t].*\n)+)", src, re.M)
    if m:
        insert_at = m.end()
        src = src[:insert_at] + "\n\n" + helper_block + "\n" + src[insert_at:]
    else:
        # place after imports block
        lines = src.splitlines(True)
        last_import = None
        for i, line in enumerate(lines[:250]):
            if re.match(r"^\s*(from|import)\s+", line):
                last_import = i
                continue
        if last_import is None:
            src = helper_block + "\n" + src
        else:
            lines.insert(last_import + 1, "\n" + helper_block + "\n")
            src = "".join(lines)

# --- Function-aware patching (without assuming function names) --------

lines = src.splitlines(True)

def is_func_def(line: str) -> bool:
    return bool(re.match(r"^def\s+[A-Za-z_]\w*\s*\(", line))

def func_name(line: str) -> str | None:
    m = re.match(r"^def\s+([A-Za-z_]\w*)\s*\(", line)
    return m.group(1) if m else None

# We'll patch only inside blocks that are likely SQLite / idempotency related.
# Criteria:
# - function name contains "sqlite"
# - OR function body references "connectors_idempotency" or "ConnectorIdempotency"
# - OR function body calls "_reserve_sqlite" / similar
#
# We'll do a two-pass:
# 1) Identify candidate function blocks and mark them.
# 2) Apply safe substitutions inside those blocks only.

# Parse function blocks by indentation (simple but effective for this file style)
func_blocks: list[tuple[int, int, str]] = []  # (start_idx, end_idx, name)
i = 0
while i < len(lines):
    if is_func_def(lines[i]):
        name = func_name(lines[i]) or "unknown"
        start = i
        # function body ends when next top-level def/class or EOF
        j = i + 1
        while j < len(lines):
            if re.match(r"^(def|class)\s+", lines[j]):  # top-level next
                break
            j += 1
        func_blocks.append((start, j, name))
        i = j
    else:
        i += 1

def block_text(start: int, end: int) -> str:
    return "".join(lines[start:end])

def patch_block(text: str) -> str:
    # Replace now = _now_utc() in sqlite contexts
    text = re.sub(r"(?m)^\s*now\s*=\s*_now_utc\(\)\s*$", "    now = _now_utc_naive()", text)

    # Replace expires_at computations that use _now_utc() + timedelta(...) in sqlite contexts
    text = re.sub(
        r"(?m)^\s*expires_at\s*=\s*_now_utc\(\)\s*\+\s*timedelta\(",
        "    expires_at = _now_utc_naive() + timedelta(",
        text,
    )

    # Fix comparisons: existing_expires_at >= now  (or > now, <= now etc.)
    # We do it in a conservative way:
    # - if we see a local variable named existing_expires_at being compared to now,
    #   insert coercion once and replace comparisons to use coerced_expires_at.
    if re.search(r"existing_expires_at\s*[<>]=?\s*now", text):
        # ensure we define coerced_expires_at after assignment line if present
        text = re.sub(
            r"(?m)^(\s*existing_id,\s*existing_expires_at\s*=\s*existing\s*)$",
            r"\1\n        coerced_expires_at = _coerce_sqlite_dt(existing_expires_at)",
            text,
        )
        # If we don't have that exact assignment, we still may have "existing_expires_at =" somewhere
        if "coerced_expires_at" not in text:
            text = re.sub(
                r"(?m)^(\s*existing_expires_at\s*=\s*[^\n]+)$",
                r"\1\n        coerced_expires_at = _coerce_sqlite_dt(existing_expires_at)",
                text,
                count=1,
            )

        # Replace comparisons to use coerced_expires_at
        text = re.sub(r"existing_expires_at", "coerced_expires_at", text)

        # If we accidentally turned assignment into coerced_expires_at = coerced_expires_at, fix it
        text = text.replace("coerced_expires_at = _coerce_sqlite_dt(coerced_expires_at)",
                            "coerced_expires_at = _coerce_sqlite_dt(existing_expires_at)")

        # Fail-closed behavior: if coercion returns None, treat as not reclaimable
        # If there's a condition like: if coerced_expires_at is None or coerced_expires_at >= now:
        # that is fail-closed (no reclaim). We'll enforce it if we can find the common pattern.
        text = re.sub(
            r"(?m)^\s*if\s+coerced_expires_at\s+is\s+None\s+or\s+coerced_expires_at\s*[<>]=?\s*now:\s*$",
            "        # If we can't parse/normalize, fail closed: do not reclaim.\n        if coerced_expires_at is None or coerced_expires_at >= now:",
            text,
        )

    return text

patched_any = False

for start, end, name in func_blocks:
    txt = block_text(start, end)

    looks_sqlite = ("sqlite" in name.lower())
    touches_idem = ("connectors_idempotency" in txt) or ("ConnectorIdempotency" in txt) or ("idempotency_key" in txt and "expires_at" in txt)

    if looks_sqlite or touches_idem:
        new_txt = patch_block(txt)
        if new_txt != txt:
            lines[start:end] = new_txt.splitlines(True)
            patched_any = True

# Also patch any non-function module-level sqlite time usage within idempotency context (rare, but just in case)
src2 = "".join(lines)
src2_new = src2
# Only if module contains connectors_idempotency and naive helper exists
if "connectors_idempotency" in src2_new and "def _now_utc_naive" in src2_new:
    # very conservative: only replace within lines that mention connectors_idempotency
    out_lines = src2_new.splitlines(True)
    for idx, line in enumerate(out_lines):
        if "connectors_idempotency" in line and "_now_utc()" in line:
            out_lines[idx] = line.replace("_now_utc()", "_now_utc_naive()")
    src2_new = "".join(out_lines)

if src2_new != src:
    patched_any = True
    src = src2_new

if not patched_any:
    print("WARNING: no matching SQLite/idempotency blocks were patched. File may already be fixed or patterns differ.")
else:
    p.write_text(src, encoding="utf-8")
    print("Patched:", p)
PY

echo "== Format + lint (best effort) =="
ruff format "$TARGET" >/dev/null 2>&1 || true
ruff check "$TARGET" >/dev/null 2>&1 || true

echo "== Run targeted tests =="
pytest -q tests/test_connectors_idempotency.py

echo "== Done =="