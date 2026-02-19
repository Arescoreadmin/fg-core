#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'PY'
from __future__ import annotations

from pathlib import Path

path = Path("api/auth_scopes/resolution.py")
lines = path.read_text(encoding="utf-8").splitlines(True)

def find_top_level_def(name: str) -> int:
    target = f"def {name}"
    for i, ln in enumerate(lines):
        if ln.startswith(target):
            return i
    return -1

def find_next_top_level_def(start: int) -> int:
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("def "):
            return j
    return len(lines)

def ensure_import(module_line: str, after_prefix: str | None = None) -> None:
    # Adds a simple import if missing.
    if any(module_line in ln for ln in lines):
        return
    # Insert after the last import block near top.
    insert_at = 0
    for i, ln in enumerate(lines[:200]):
        if ln.startswith("import ") or ln.startswith("from "):
            insert_at = i + 1
    lines.insert(insert_at, module_line + "\n")

def ensure_from_import(module: str, symbol: str) -> None:
    # Ensure `from module import symbol` exists; if module import exists but symbol missing,
    # we do a simple add line (keep it deterministic, no fancy AST surgery).
    wanted = f"from {module} import {symbol}"
    if any(ln.strip() == wanted for ln in lines):
        return
    # If there is any from {module} import ... line, do nothing complex: just add the wanted line.
    insert_at = 0
    for i, ln in enumerate(lines[:200]):
        if ln.startswith("import ") or ln.startswith("from "):
            insert_at = i + 1
    lines.insert(insert_at, wanted + "\n")

# We reference os + HTTPException in the replacement blocks.
ensure_import("import os")
ensure_from_import("fastapi", "HTTPException")

require_bound_tenant_block = [
    "def require_bound_tenant(request: Request, x_tenant_id: Optional[str] = None) -> str:\n",
    "    \"\"\"Callable helper (NOT a FastAPI Header dependency).\n",
    "    Several routes call this as require_bound_tenant(request), so we must read headers ourselves.\n",
    "    \"\"\"\n",
    "    if x_tenant_id is None:\n",
    "        x_tenant_id = request.headers.get(\"X-Tenant-Id\")\n",
    "    return bind_tenant_id(\n",
    "        request,\n",
    "        x_tenant_id,\n",
    "        require_explicit_for_unscoped=True,\n",
    "    )\n",
]

bind_block = [
    "def bind_tenant_id(\n",
    "    request: Request,\n",
    "    requested_tenant: Optional[str],\n",
    "    *,\n",
    "    require_explicit_for_unscoped: bool = False,\n",
    "    default_unscoped: Optional[str] = None,\n",
    ") -> str:\n",
    "    \"\"\"Tenant binding contract:\n",
    "\n",
    "    - If the API key is tenant-bound: the effective tenant is ALWAYS the key's tenant.\n",
    "      If the client supplies a different tenant (query/header/body/path), deny with 403.\n",
    "\n",
    "    - If the API key is unscoped:\n",
    "      - Any supplied tenant must be valid format; invalid -> 400 invalid tenant_id.\n",
    "      - Only /ai/query may use FG_API_KEY (env) with X-Tenant-Id for dev convenience.\n",
    "      - Otherwise: unscoped keys cannot act on ANY tenant, even if supplied -> 400.\n",
    "    \"\"\"\n",
    "    st = getattr(request, \"state\", None)\n",
    "\n",
    "    # auth_gate sets these from the API key.\n",
    "    key_tenant = getattr(st, \"tenant_id\", None) if st is not None else None\n",
    "    key_is_bound = bool(getattr(st, \"tenant_is_key_bound\", False)) if st is not None else bool(key_tenant)\n",
    "\n",
    "    req_tenant = (requested_tenant or \"\").strip() or None\n",
    "    hdr_tenant = (request.headers.get(\"X-Tenant-Id\") or \"\").strip() or None\n",
    "    supplied = req_tenant or hdr_tenant\n",
    "\n",
    "    # Key-bound: clamp, mismatch -> 403\n",
    "    if key_is_bound and key_tenant:\n",
    "        if supplied and supplied != key_tenant:\n",
    "            tenant_denial(\n",
    "                request,\n",
    "                reason=\"tenant_mismatch\",\n",
    "                tenant_supplied=supplied,\n",
    "                tenant_from_key=key_tenant,\n",
    "            )\n",
    "            raise HTTPException(\n",
    "                status_code=403,\n",
    "                detail=redact_detail(\"tenant mismatch\", generic=\"forbidden\"),\n",
    "            )\n",
    "        if st is not None:\n",
    "            st.tenant_id = key_tenant\n",
    "            st.tenant_is_key_bound = True\n",
    "        return str(key_tenant)\n",
    "\n",
    "    # Unscoped: validate tenant format if supplied\n",
    "    if supplied:\n",
    "        valid, _err = _validate_tenant_id(supplied)\n",
    "        if not valid:\n",
    "            raise HTTPException(\n",
    "                status_code=400,\n",
    "                detail=redact_detail(\"invalid tenant_id\", generic=\"invalid request\"),\n",
    "            )\n",
    "\n",
    "    # Special-case /ai/query + env FG_API_KEY\n",
    "    path = \"\"\n",
    "    try:\n",
    "        path = request.url.path\n",
    "    except Exception:\n",
    "        path = str(getattr(request, \"scope\", {}).get(\"path\", \"\"))\n",
    "\n",
    "    env_key = (os.getenv(\"FG_API_KEY\") or \"\").strip()\n",
    "    presented = (request.headers.get(\"X-API-Key\") or \"\").strip()\n",
    "    if path == \"/ai/query\" and env_key and presented == env_key:\n",
    "        if not supplied:\n",
    "            raise HTTPException(\n",
    "                status_code=400,\n",
    "                detail=redact_detail(\"tenant_id required for unscoped keys\", generic=\"invalid request\"),\n",
    "            )\n",
    "        if st is not None:\n",
    "            st.tenant_id = supplied\n",
    "            st.tenant_is_key_bound = False\n",
    "        return str(supplied)\n",
    "\n",
    "    # Unscoped minted keys cannot act on ANY tenant even if tenant is supplied.\n",
    "    if require_explicit_for_unscoped:\n",
    "        raise HTTPException(\n",
    "            status_code=400,\n",
    "            detail=redact_detail(\"tenant_id required for unscoped keys\", generic=\"invalid request\"),\n",
    "        )\n",
    "\n",
    "    if default_unscoped:\n",
    "        if st is not None:\n",
    "            st.tenant_id = default_unscoped\n",
    "            st.tenant_is_key_bound = False\n",
    "        return str(default_unscoped)\n",
    "\n",
    "    raise HTTPException(\n",
    "        status_code=400,\n",
    "        detail=redact_detail(\"tenant_id required\", generic=\"invalid request\"),\n",
    "    )\n",
]

# Patch require_bound_tenant
req_start = find_top_level_def("require_bound_tenant")
if req_start < 0:
    raise SystemExit("ERROR: require_bound_tenant not found")
req_end = find_next_top_level_def(req_start)
lines[req_start:req_end] = require_bound_tenant_block

# Patch bind_tenant_id
bind_start = find_top_level_def("bind_tenant_id")
if bind_start < 0:
    raise SystemExit("ERROR: bind_tenant_id not found")
bind_end = find_next_top_level_def(bind_start)
lines[bind_start:bind_end] = bind_block

path.write_text("".join(lines), encoding="utf-8")
print("OK: patched require_bound_tenant + bind_tenant_id (v4b)")
PY
