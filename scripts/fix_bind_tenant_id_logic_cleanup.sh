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

# 1) Remove the duplicate st = getattr(...) block (you have it twice in a row)
src2 = re.sub(
    r'(?ms)\n\s*st = getattr\(request, "state", None\)\n\s*if st is None:\n\s*st = type\("State", \(\), \{\}\)\(\)\n\s*setattr\(request, "state", st\)\n',
    "\n",
    src,
    count=1,
)
src = src2

# 2) Remove the clobbering "key_tenant = getattr(st, 'tenant_id'...)" block that overwrites auth-first
src = re.sub(
    r'(?ms)\n\s*key_tenant = getattr\(st, "tenant_id", None\)\n\s*key_is_bound = bool\(getattr\(st, "tenant_is_key_bound", False\)\) or bool\(key_tenant\)\n',
    "\n",
    src,
    count=1,
)

# 3) Ensure key_tenant/key_is_bound are computed once, auth-first, and cache fields are set sanely.
# Replace the existing "Determine key binding from auth first." block with a canonical one.
src = re.sub(
    r'(?ms)\n\s*# Determine key binding from auth first\.\n\s*key_tenant = .*?\n\s*key_is_bound = \(\n\s*.*?\n\s*\)\n',
    """
\n    # Determine key binding (auth-first, then cached).
    key_tenant = auth_tenant or getattr(st, "tenant_id", None)
    key_is_bound = bool(key_tenant)
    # Keep the cache consistent (middleware may have set these already).
    st.tenant_id = key_tenant
    st.tenant_is_key_bound = bool(key_tenant)
""",
    src,
    count=1,
)

# 4) Fix require_explicit_for_unscoped: if unscoped and no supplied tenant => 400 (not 403)
# Find the unscoped branch and ensure it fails with 400 when require_explicit_for_unscoped and no tenant supplied.
# We patch by inserting a guard right after supplied is computed.
marker = r"supplied = req_tenant or hdr_tenant"
if marker not in src:
    raise SystemExit("ERROR: could not find supplied assignment marker")

insertion = marker + r"""

    # Unscoped key: require explicit tenant when requested by caller.
    if (not key_is_bound) and require_explicit_for_unscoped and not supplied:
        raise HTTPException(
            status_code=400,
            detail=redact_detail("tenant_id required", generic="invalid request"),
        )
"""
src = src.replace(marker, insertion, 1)

p.write_text(src, encoding="utf-8")
print("OK: cleaned bind_tenant_id (removed clobber + fixed unscoped explicit 400)")
PY

ruff format api/auth_scopes/resolution.py
ruff check api/auth_scopes/resolution.py
python -m compileall -q api/auth_scopes/resolution.py
