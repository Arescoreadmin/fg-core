#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TARGET="services/connectors/idempotency.py"

echo "== Preconditions =="
test -f "$TARGET"

echo "== Patch prune_expired() using AST line ranges (no regex fragility) =="

python - <<'PY'
from __future__ import annotations

from pathlib import Path
import ast

path = Path("services/connectors/idempotency.py")
src = path.read_text(encoding="utf-8")
lines = src.splitlines(True)

tree = ast.parse(src)

fn = None
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name == "prune_expired":
        fn = node
        break

if fn is None:
    raise SystemExit("ERROR: Could not find top-level function prune_expired in services/connectors/idempotency.py")

# Python 3.12: end_lineno is reliable
start = fn.lineno
end = fn.end_lineno
if not start or not end:
    raise SystemExit("ERROR: AST did not provide lineno/end_lineno for prune_expired (unexpected).")

# Convert to 0-based slice
start_i = start - 1
end_i = end  # end is inclusive lineno, so slice end is end_i

replacement = """def prune_expired(db: Session, *, limit: int = 5000) -> int:
    \"\"\"Delete expired idempotency reservations (best-effort).

    SQLite note:
      - Our SQLite bootstrap stores expires_at as TEXT (ISO-ish).
      - SQLAlchemy bulk deletes can attempt session synchronization via in-Python
        evaluation, which can crash when comparing datetime objects to TEXT.
      - So: on SQLite, use raw SQL delete + synchronize_session=False.

    Args:
        db: SQLAlchemy Session
        limit: retained for API compatibility; SQLite delete is unbounded for correctness

    Returns:
        rows deleted (best-effort)
    \"\"\"
    dialect = _dialect_name(db)

    if dialect == "sqlite":
        now_iso = _sqlite_now_iso()
        res = db.execute(
            text(
                \"\"\"
                DELETE FROM connectors_idempotency
                WHERE expires_at < :now_iso
                \"\"\"
            ),
            {"now_iso": now_iso},
            execution_options={"synchronize_session": False},
        )
        try:
            return int(res.rowcount or 0)
        except Exception:
            return 0

    # Postgres (timestamptz) path
    res = db.execute(
        delete(ConnectorIdempotency).where(ConnectorIdempotency.expires_at < _now_utc()),
        execution_options={"synchronize_session": False},
    )
    try:
        return int(res.rowcount or 0)
    except Exception:
        return 0
"""

new_lines = lines[:start_i] + [replacement + "\n\n"] + lines[end_i:]
path.write_text("".join(new_lines), encoding="utf-8")
print(f"Patched: {path} (lines {start}-{end})")
PY

echo "== Compile check (must pass) =="
python -m py_compile "$TARGET"

echo "== Format + lint (best effort) =="
ruff format "$TARGET" >/dev/null 2>&1 || true
ruff check "$TARGET" >/dev/null 2>&1 || true

echo "== Run targeted tests =="
pytest -q tests/test_connectors_idempotency.py

echo "== Done =="