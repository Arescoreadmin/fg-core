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

# 1) Remove the misplaced cache-population block (wherever it is).
cache_pat = r"""(?ms)^\s*# Populate tenant cache once per request from the shared helper \(monkeypatchable\)\.\n\s*if getattr\(st, "tenant_id", None\) is None:\n\s*try:\n\s*st\.tenant_id = _norm_tid\(_auth_tenant_from_request\(request\)\)\n\s*except Exception:\n\s*st\.tenant_id = None\n\s*\n"""
block2, n = re.subn(cache_pat, "", block)
if n == 0:
    raise SystemExit("ERROR: could not find misplaced cache-population block to remove")

# 2) Find the st initialization block.
st_init_pat = r"""(?ms)^\s*st = getattr\(request, "state", None\)\n\s*if st is None:\n\s*st = type\("State", \(\), \{\}\)\(\)\n\s*setattr\(request, "state", st\)\n"""
m2 = re.search(st_init_pat, block2)
if not m2:
    raise SystemExit("ERROR: could not find st initialization block inside bind_tenant_id")

insert_at = m2.end()

cache_snippet = (
    "\n"
    "    # Populate tenant cache once per request from the shared helper (monkeypatchable).\n"
    "    if getattr(st, \"tenant_id\", None) is None:\n"
    "        try:\n"
    "            st.tenant_id = _norm_tid(_auth_tenant_from_request(request))\n"
    "        except Exception:\n"
    "            st.tenant_id = None\n"
)

block3 = block2[:insert_at] + cache_snippet + block2[insert_at:]

src_new = src[:m.start()] + block3 + src[m.end():]
p.write_text(src_new, encoding="utf-8")
print("OK: moved cache-population block to after st initialization")
PY

ruff format api/auth_scopes/resolution.py
ruff check api/auth_scopes/resolution.py
python -m compileall -q api/auth_scopes/resolution.py
