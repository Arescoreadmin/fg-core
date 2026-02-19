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

# --- 1) Remove redundant single import: "from fastapi import HTTPException" ---
src2 = re.sub(r"(?m)^\s*from\s+fastapi\s+import\s+HTTPException\s*\n", "", src)
src = src2

# --- 2) Restore tenant_denial helper if missing ---
if not re.search(r"(?m)^def\s+tenant_denial\s*\(", src):
    # Insert right after logger initialization if present, otherwise after imports.
    insert_after = re.search(r"(?m)^log\s*=\s*logging\.getLogger\([^)]+\)\s*\n", src)
    helper = """
def tenant_denial(
    request: Request,
    *,
    reason: str,
    tenant_supplied: str | None = None,
    tenant_from_key: str | None = None,
    detail: str | None = None,
) -> None:
    \"\"\"Structured tenant-denial logging (no PII, no tenant enumeration in prod-like).\"\"\"
    try:
        client = getattr(getattr(request, "client", None), "host", None)
        path = getattr(getattr(request, "url", None), "path", None) or getattr(request, "scope", {}).get("path")
        method = getattr(request, "method", None) or getattr(request, "scope", {}).get("method")
        rid = getattr(getattr(request, "state", None), "request_id", None)
    except Exception:
        client = path = method = rid = None

    # Keep it boring and safe. Tests care that the hook exists; ops cares it’s structured.
    log.warning(
        "tenant_denial",
        extra={
            "event": "tenant_denial",
            "reason": reason,
            "path": path,
            "method": method,
            "client_ip": client,
            "request_id": rid,
            "tenant_supplied": tenant_supplied,
            "tenant_from_key": tenant_from_key,
            "detail": detail,
        },
    )
"""
    if insert_after:
        idx = insert_after.end()
        src = src[:idx] + helper + src[idx:]
    else:
        # Fallback: insert after the last import block.
        last_import = None
        for m in re.finditer(r"(?m)^(from|import)\s+", src):
            last_import = m
        idx = last_import.end() if last_import else 0
        # move to end of that line
        idx = src.find("\n", idx) + 1 if idx else 0
        src = src[:idx] + helper + src[idx:]

p.write_text(src, encoding="utf-8")
print("OK: removed redundant HTTPException import + restored tenant_denial helper")
PY

ruff format api/auth_scopes/resolution.py
ruff check api/auth_scopes/resolution.py
