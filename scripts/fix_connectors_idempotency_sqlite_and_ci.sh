#!/usr/bin/env bash
set -euo pipefail

if ! ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "ERROR: Not inside a git repo. cd into fg-core and rerun."
  exit 1
fi

DBPY="$ROOT/api/db.py"
CI="$ROOT/tools/ci/check_connectors_rls.py"
MIG_0025="$ROOT/migrations/postgres/0025_agent_phase21_hardening.sql"

echo "== Preconditions =="
test -f "$DBPY" || { echo "Missing: $DBPY"; exit 1; }
test -f "$CI" || { echo "Missing: $CI"; exit 1; }
test -f "$MIG_0025" || { echo "Missing: $MIG_0025"; exit 1; }

echo "== 1) Ensure tools/ci/check_connectors_rls.py points at 0025 migration =="
python - <<'PY'
from pathlib import Path
import re
import sys

root = Path.cwd()
# If script is invoked from repo root, great. If not, locate by git root env.
# But we already computed ROOT in shell; simplest is to trust CWD is repo root
# when executing the script. If not, user can run from repo root.
ci = Path("tools/ci/check_connectors_rls.py")
if not ci.exists():
    print(f"ERROR: {ci} not found. Run from repo root.", file=sys.stderr)
    raise SystemExit(1)

s = ci.read_text(encoding="utf-8")
target = 'MIGRATION = Path("migrations/postgres/0025_agent_phase21_hardening.sql")\n'

# Replace existing MIGRATION assignment if present
if re.search(r'^\s*MIGRATION\s*=\s*Path\(', s, flags=re.MULTILINE):
    s2 = re.sub(
        r'^\s*MIGRATION\s*=\s*Path\([\'"][^\'"]+[\'"]\)\s*$',
        target.strip(),
        s,
        flags=re.MULTILINE,
    )
    if not s2.endswith("\n"):
        s2 += "\n"
    ci.write_text(s2, encoding="utf-8")
    print("Updated MIGRATION assignment in:", ci)
    raise SystemExit(0)

# Insert MIGRATION assignment after import block if missing
lines = s.splitlines(True)
insert_at = None
for i, line in enumerate(lines):
    if line.startswith("from ") or line.startswith("import "):
        insert_at = i + 1

if insert_at is None:
    print("ERROR: Could not find import block to insert MIGRATION after.", file=sys.stderr)
    raise SystemExit(1)

lines.insert(insert_at, "\n")
lines.insert(insert_at + 1, target)
lines.insert(insert_at + 2, "\n")
s2 = "".join(lines)
if not s2.endswith("\n"):
    s2 += "\n"
ci.write_text(s2, encoding="utf-8")
print("Inserted MIGRATION assignment into:", ci)
PY

echo "== 2) Ensure SQLite bootstrap creates connectors_idempotency table + indexes in api/db.py =="
# We DO NOT fail the whole script if this block can't pattern-match perfectly,
# because repos differ. But we DO want a loud error.
set +e
python - <<'PY'
from pathlib import Path
import re
import sys

dbpy = Path("api/db.py")
if not dbpy.exists():
    print("ERROR: api/db.py not found. Run from repo root.", file=sys.stderr)
    raise SystemExit(1)

s = dbpy.read_text(encoding="utf-8")

# Must have the table creation in SQLite bootstrap (you already saw it via rg)
if "CREATE TABLE IF NOT EXISTS connectors_idempotency" not in s:
    print("ERROR: api/db.py missing SQLite CREATE TABLE connectors_idempotency block.", file=sys.stderr)
    raise SystemExit(2)

# Ensure unique composite index exists
unique_stmt = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_idempotency_key\n"
    "  ON connectors_idempotency (tenant_id, connector_id, action, idempotency_key);\n"
)

expiry_stmt = (
    "CREATE INDEX IF NOT EXISTS ix_connectors_idempotency_expiry\n"
    "  ON connectors_idempotency(expires_at);\n"
)

changed = False

if "CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_idempotency_key" not in s:
    # Prefer inserting right before the expiry index if present
    m_exp = re.search(r"CREATE INDEX IF NOT EXISTS ix_connectors_idempotency_expiry\b", s)
    if m_exp:
        s = s[:m_exp.start()] + unique_stmt + "\n" + s[m_exp.start():]
        changed = True
    else:
        # Otherwise insert after the table block
        m_tbl = re.search(
            r"(CREATE TABLE IF NOT EXISTS connectors_idempotency\s*\([\s\S]*?\);\s*)",
            s,
            flags=re.MULTILINE,
        )
        if not m_tbl:
            print("ERROR: Could not locate end of connectors_idempotency CREATE TABLE statement.", file=sys.stderr)
            raise SystemExit(3)
        s = s[:m_tbl.end(1)] + "\n" + unique_stmt + s[m_tbl.end(1):]
        changed = True

# Ensure expiry index exists too (SQLite bootstrap should mirror migration)
if "CREATE INDEX IF NOT EXISTS ix_connectors_idempotency_expiry" not in s:
    # If we can find the unique index, insert after it
    m_uq = re.search(r"CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_idempotency_key[\s\S]*?;\s*", s)
    if m_uq:
        s = s[:m_uq.end()] + "\n" + expiry_stmt + s[m_uq.end():]
        changed = True
    else:
        # Fallback: append near the table block
        m_tbl = re.search(
            r"(CREATE TABLE IF NOT EXISTS connectors_idempotency\s*\([\s\S]*?\);\s*)",
            s,
            flags=re.MULTILINE,
        )
        if not m_tbl:
            print("ERROR: Could not locate end of connectors_idempotency CREATE TABLE statement.", file=sys.stderr)
            raise SystemExit(4)
        s = s[:m_tbl.end(1)] + "\n" + expiry_stmt + s[m_tbl.end(1):]
        changed = True

if changed:
    if not s.endswith("\n"):
        s += "\n"
    dbpy.write_text(s, encoding="utf-8")
    print("Patched:", dbpy)
else:
    print("SQLite bootstrap already includes required connectors_idempotency indexes.")
PY
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
  echo "WARNING: api/db.py patch step exited non-zero ($RC). Review output above."
fi

echo "== 3) Quick verification =="
rg -n "MIGRATION\\s*=\\s*Path\\(" "$CI" || true
rg -n "0025_agent_phase21_hardening.sql" "$CI" || true

rg -n "CREATE TABLE IF NOT EXISTS connectors_idempotency" "$DBPY" || true
rg -n "CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_idempotency_key" "$DBPY" || true
rg -n "CREATE INDEX IF NOT EXISTS ix_connectors_idempotency_expiry" "$DBPY" || true

echo "== 4) Run CI check + idempotency unit test (best effort) =="
python "$CI"

if command -v pytest >/dev/null 2>&1; then
  pytest -q tests/test_connectors_idempotency.py
fi

echo "== Done =="