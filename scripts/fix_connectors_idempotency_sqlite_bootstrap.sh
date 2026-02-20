#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "== 1) Patch api/db.py to use executescript for idempotency indexes =="

python - <<'PY'
from pathlib import Path
import re

p = Path("api/db.py")
body = p.read_text(encoding="utf-8")

# Find the con.execute(""" CREATE UNIQUE INDEX ... CREATE INDEX ... """) block near connectors_idempotency
pattern = re.compile(
    r"""
    con\.execute\(\s*
        """ + '"""' + r"""
        \s*CREATE\s+UNIQUE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+uq_connectors_idempotency_key.*?
        CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+ix_connectors_idempotency_expiry.*?
        """ + '"""' + r"""
    \s*\)
    """,
    re.DOTALL | re.VERBOSE,
)

m = pattern.search(body)
if not m:
    raise SystemExit("ERROR: Could not find multi-statement con.execute block for idempotency indexes in api/db.py")

replacement = """con.executescript(
            \"""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_idempotency_key
                ON connectors_idempotency (tenant_id, connector_id, action, idempotency_key);

            CREATE INDEX IF NOT EXISTS ix_connectors_idempotency_expiry
                ON connectors_idempotency (expires_at);
            \"""
        )"""

new_body = body[: m.start()] + replacement + body[m.end():]
p.write_text(new_body, encoding="utf-8")
print("Patched:", p)
PY

echo "== 2) Fast compile check =="
python -m compileall -q api services tests || true

echo "== 3) Show real traceback if connectors_control_plane import is broken =="
python - <<'PY'
import traceback
try:
    import api.connectors_control_plane as m
    print("Import OK. router present:", hasattr(m, "router"))
except Exception:
    traceback.print_exc()
    raise SystemExit(1)
PY

echo "== 4) Run targeted tests =="
pytest -q tests/test_connectors_idempotency.py

echo "== 5) Lint =="
ruff check .

echo "== Done =="