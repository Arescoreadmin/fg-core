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

# Locate bind_tenant_id body
m = re.search(r"(?ms)^def\s+bind_tenant_id\s*\(.*?\)\s*:\n", src)
if not m:
    raise SystemExit("ERROR: bind_tenant_id not found")
start = m.end()

# Replace the initial "state/cache" block up to where you set key_tenant/key_is_bound.
# We anchor on the first occurrence of "key_tenant ="
m2 = re.search(r"(?ms)^\s*key_tenant\s*=\s*getattr\(st,\s*\"tenant_id\"", src[start:])
if not m2:
    raise SystemExit("ERROR: could not find key_tenant assignment inside bind_tenant_id")

block_start = start
block_end = start + m2.start()

new_block = r'''
    st = getattr(request, "state", None)
    if st is None:
        st = type("State", (), {})()
        setattr(request, "state", st)

    # Source of truth: auth object (unit tests set st.auth directly; middleware sets st.tenant_id too).
    auth = getattr(st, "auth", None)
    auth_tenant = getattr(auth, "tenant_id", None) if auth is not None else None

    # Cache derived fields for the rest of the request, but never treat cache as authoritative.
    if getattr(st, "tenant_id", None) is None:
        st.tenant_id = auth_tenant
    if not hasattr(st, "tenant_is_key_bound"):
        st.tenant_is_key_bound = bool(auth_tenant)

    # Determine key binding from auth first.
    key_tenant = auth_tenant or getattr(st, "tenant_id", None)
    key_is_bound = bool(auth_tenant) or bool(getattr(st, "tenant_is_key_bound", False)) or bool(key_tenant)
'''

src = src[:block_start] + new_block + src[block_end:]
p.write_text(src, encoding="utf-8")
print("OK: patched bind_tenant_id key tenant resolution (auth-first)")
PY

ruff format api/auth_scopes/resolution.py
ruff check api/auth_scopes/resolution.py
