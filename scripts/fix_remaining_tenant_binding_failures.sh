#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'PY'
from __future__ import annotations
from pathlib import Path
import re

p = Path("api/auth_scopes/resolution.py")
src = p.read_text(encoding="utf-8")

m = re.search(r"(?ms)^def\s+bind_tenant_id\s*\(.*?\)\s*:\n(.*?)(?=^def\s|\Z)", src)
if not m:
    raise SystemExit("ERROR: bind_tenant_id not found")

block = m.group(0)

# 1) Ensure we call _auth_tenant_from_request exactly once per request when cache empty.
# Insert right after _norm_tid helper (which we added previously).
insert_snippet = (
    "    # Populate tenant cache once per request from the shared helper (monkeypatchable).\n"
    "    if getattr(st, \"tenant_id\", None) is None:\n"
    "        try:\n"
    "            st.tenant_id = _norm_tid(_auth_tenant_from_request(request))\n"
    "        except Exception:\n"
    "            st.tenant_id = None\n\n"
)

if "_auth_tenant_from_request(request)" not in block:
    # Find spot after _norm_tid helper ends (blank line after it)
    # We'll insert after the first occurrence of "def _norm_tid" block.
    mm = re.search(r"(?ms)^\s*def\s+_norm_tid\(.*?\n\s*return\s+v\s+or\s+None\s*\n\s*\n", block)
    if not mm:
        raise SystemExit("ERROR: _norm_tid helper not found inside bind_tenant_id (did earlier patch run?)")
    block = block[: mm.end()] + insert_snippet + block[mm.end():]

# 2) Fix error detail string for unscoped explicit requirement.
block = block.replace(
    'redact_detail("tenant_id required", generic="invalid request")',
    'redact_detail("tenant_id required for unscoped keys", generic="invalid request")',
)

# Write back
src_new = src[: m.start()] + block + src[m.end():]
p.write_text(src_new, encoding="utf-8")
print("OK: patched bind_tenant_id: call _auth_tenant_from_request once + correct unscoped detail")
PY

ruff format api/auth_scopes/resolution.py
ruff check api/auth_scopes/resolution.py
python -m compileall -q api/auth_scopes/resolution.py
