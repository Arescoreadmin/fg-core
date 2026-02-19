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

# Extract bind_tenant_id block
m = re.search(r"(?ms)^def\s+bind_tenant_id\s*\(.*?\)\s*:\n(.*?)(?=^def\s|\Z)", src)
if not m:
    raise SystemExit("ERROR: bind_tenant_id not found")

block = m.group(0)

# 1) Insert _norm_tid helper right after "import os" inside bind_tenant_id
if "_norm_tid(" not in block:
    block = re.sub(
        r'(?m)^\s*import\s+os\s*\n',
        "    import os\n\n"
        "    def _norm_tid(v):\n"
        "        # MagicMock-safe: only accept real strings.\n"
        "        if not isinstance(v, str):\n"
        "            return None\n"
        "        v = v.strip()\n"
        "        return v or None\n\n",
        block,
        count=1,
    )

# 2) Normalize auth_tenant assignment
block = re.sub(
    r'(?m)^\s*auth_tenant\s*=\s*getattr\(auth,\s*"tenant_id",\s*None\)\s*if\s*auth\s*is\s*not\s*None\s*else\s*None\s*$',
    '    auth_tenant = _norm_tid(getattr(auth, "tenant_id", None)) if auth is not None else None',
    block,
    count=1,
)

# 3) Normalize cached tenant access in key_tenant calculation
block = re.sub(
    r'(?m)^\s*key_tenant\s*=\s*auth_tenant\s*or\s*getattr\(st,\s*"tenant_id",\s*None\)\s*$',
    '    key_tenant = auth_tenant or _norm_tid(getattr(st, "tenant_id", None))',
    block,
    count=1,
)

# 4) Normalize req_tenant / hdr_tenant extraction
block = re.sub(
    r'(?m)^\s*req_tenant\s*=\s*\(requested_tenant\s*or\s*""\)\.strip\(\)\s*or\s*None\s*$',
    '    req_tenant = _norm_tid(requested_tenant)',
    block,
    count=1,
)

block = re.sub(
    r'(?ms)^\s*headers\s*=\s*getattr\(request,\s*"headers",\s*None\)\s*or\s*\{\}\s*\n\s*try:\s*\n\s*hdr_tenant\s*=\s*\(headers\.get\("X-Tenant-Id"\)\s*or\s*""\)\.strip\(\)\s*or\s*None\s*\n\s*except\s*Exception:\s*\n\s*hdr_tenant\s*=\s*None\s*$',
    '    headers = getattr(request, "headers", None) or {}\n'
    '    try:\n'
    '        hdr_tenant = _norm_tid(headers.get("X-Tenant-Id"))\n'
    '    except Exception:\n'
    '        hdr_tenant = None',
    block,
    count=1,
)

# 5) Ensure the cache write uses normalized key_tenant (it already will now)
# No change needed unless you want to avoid storing non-str in st.tenant_id.

# Replace original block in file
src_new = src[: m.start()] + block + src[m.end() :]
p.write_text(src_new, encoding="utf-8")
print("OK: bind_tenant_id now MagicMock-safe via _norm_tid()")
PY

ruff format api/auth_scopes/resolution.py
ruff check api/auth_scopes/resolution.py
python -m compileall -q api/auth_scopes/resolution.py
