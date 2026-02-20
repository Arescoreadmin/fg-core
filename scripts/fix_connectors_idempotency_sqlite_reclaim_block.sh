#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TARGET="services/connectors/idempotency.py"

if [[ ! -f "$TARGET" ]]; then
  echo "ERROR: missing $TARGET"
  exit 1
fi

echo "== Backup =="
cp -a "$TARGET" "${TARGET}.bak.$(date +%Y%m%d_%H%M%S)"

echo "== Patch: replace 'Best-effort reclaim' function block with a clean implementation =="

python - <<'PY'
from __future__ import annotations

from pathlib import Path
import re
from textwrap import dedent

p = Path("services/connectors/idempotency.py")
src = p.read_text(encoding="utf-8")

needle = "Best-effort reclaim"

idx = src.find(needle)
if idx < 0:
    raise SystemExit(f"ERROR: could not find docstring needle: {needle!r}")

# Find the start of the enclosing function definition (at column 0)
def_start = src.rfind("\ndef ", 0, idx)
if def_start < 0:
    # maybe at file start
    if src.startswith("def "):
        def_start = 0
    else:
        raise SystemExit("ERROR: could not locate function start for reclaim block")

# Advance past the leading newline we found via rfind("\ndef ")
if def_start > 0:
    def_start += 1

# Find end: next top-level "def " after this function
m = re.search(r"\n(?=def\s)", src[def_start + 1 :])
if not m:
    raise SystemExit("ERROR: could not locate next function boundary after reclaim block")
def_end = def_start + 1 + m.start()

old_block = src[def_start:def_end]

# Sanity check: this really is the intended block.
if needle not in old_block:
    raise SystemExit("ERROR: function block boundary did not contain the needle; refusing to patch")

replacement = dedent(
    """
    def _coerce_sqlite_expires_at(value):
        \"\"\"
        SQLite can hand us:
          - a string (TEXT column),
          - a naive datetime,
          - or an aware datetime (depending on SQLAlchemy config).
        Normalize to *naive UTC datetime* for safe comparisons.
        Fail-closed (return None) if we can't interpret it.
        \"\"\"
        from datetime import datetime, timezone

        if value is None:
            return None

        if isinstance(value, datetime):
            # Convert aware -> UTC naive, keep naive as-is (assumed UTC).
            if value.tzinfo is not None:
                return value.astimezone(timezone.utc).replace(tzinfo=None)
            return value

        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            # Try common SQLite formats:
            # - "YYYY-MM-DD HH:MM:SS"
            # - "YYYY-MM-DDTHH:MM:SS"
            # - with optional fractional seconds
            # - with optional trailing 'Z'
            s = s.replace("Z", "")
            try:
                # datetime.fromisoformat handles "YYYY-MM-DD HH:MM:SS[.ffffff]" and "YYYY-MM-DDTHH:MM:SS[.ffffff]"
                dt = datetime.fromisoformat(s)
            except ValueError:
                # last resort: trim fractional seconds to 6 digits if it’s weird
                m = re.match(r"^(\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2})(\\.\\d+)?$", s)
                if not m:
                    return None
                base = m.group(1)
                frac = (m.group(2) or "")
                if frac and len(frac) > 7:
                    frac = frac[:7]
                try:
                    dt = datetime.fromisoformat(base + frac)
                except ValueError:
                    return None

            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt

        return None


    def _now_utc_naive():
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).replace(tzinfo=None)


    def _try_reclaim_expired(
        db,
        *,
        tenant_id: str,
        connector_id: str,
        action: str,
        idempotency_key: str,
    ) -> bool:
        \"\"\"
        Best-effort reclaim: if an existing reservation is expired, delete it so the key can be reused.
        Uses SAVEPOINT, stays bounded (single row).
        SQLite stores timestamps as TEXT by default, so normalize before comparing.
        \"\"\"
        from sqlalchemy import select

        now = _now_utc_naive()

        with db.begin_nested():
            existing = db.execute(
                select(ConnectorIdempotency.id, ConnectorIdempotency.expires_at)
                .where(
                    ConnectorIdempotency.tenant_id == tenant_id,
                    ConnectorIdempotency.connector_id == connector_id,
                    ConnectorIdempotency.action == action,
                    ConnectorIdempotency.idempotency_key == idempotency_key,
                )
                .limit(1)
            ).first()

            if not existing:
                return False

            existing_id, existing_expires_at = existing
            coerced = _coerce_sqlite_expires_at(existing_expires_at)

            # Fail-closed: if we can't parse/normalize, do not reclaim.
            if coerced is None:
                return False

            # Not expired (or expires in the future): don't reclaim.
            if coerced >= now:
                return False

            # Expired: delete and allow reuse.
            db.query(ConnectorIdempotency).filter(ConnectorIdempotency.id == existing_id).delete()
            return True
    """
).lstrip("\n")

# Ensure we have 're' available inside replacement helper.
# If the module doesn't import re already, add it at top-level.
if not re.search(r"^\s*import\s+re\s*$", src, flags=re.M):
    # Add after __future__ line if present, else at top.
    future = re.search(r"^from __future__ import .*$\n", src, flags=re.M)
    if future:
        insert_at = future.end()
        src = src[:insert_at] + "import re\n" + src[insert_at:]
        # Adjust indexes because src changed before old_block slice positions.
        # Recompute positions safely using the needle again.
        idx = src.find(needle)
        def_start = src.rfind("\ndef ", 0, idx)
        if def_start < 0:
            if src.startswith("def "):
                def_start = 0
            else:
                raise SystemExit("ERROR: could not relocate function start after inserting import re")
        if def_start > 0:
            def_start += 1
        m = re.search(r"\n(?=def\s)", src[def_start + 1 :])
        if not m:
            raise SystemExit("ERROR: could not relocate function end after inserting import re")
        def_end = def_start + 1 + m.start()
        old_block = src[def_start:def_end]
        if needle not in old_block:
            raise SystemExit("ERROR: relocated block no longer contains needle; refusing to patch")
    else:
        src = "import re\n" + src

patched = src[:def_start] + replacement + src[def_end:]
p.write_text(patched, encoding="utf-8")
print("Patched reclaim block in:", p)
PY

echo "== Compile check (must pass) =="
python -m py_compile "$TARGET"

echo "== Format + lint (best effort) =="
ruff format "$TARGET" >/dev/null 2>&1 || true
ruff check "$TARGET" >/dev/null 2>&1 || true

echo "== Run targeted tests =="
pytest -q tests/test_connectors_idempotency.py

echo "== Done =="