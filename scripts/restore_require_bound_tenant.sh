#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'PY'
from __future__ import annotations
from pathlib import Path
import re

path = Path("api/auth_scopes/resolution.py")
src = path.read_text(encoding="utf-8")

if re.search(r"(?m)^def\s+require_bound_tenant\s*\(", src):
    print("OK: require_bound_tenant already present, nothing to do.")
    raise SystemExit(0)

m = re.search(r"(?m)^def\s+require_tenant_id\s*\(", src)
if not m:
    raise SystemExit("ERROR: def require_tenant_id( not found; cannot determine insertion point")

insert_at = m.start()

block = r'''
def require_bound_tenant(
    request: Request,
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
) -> str:
    """
    FastAPI dependency: require a tenant bound via key semantics.

    - Key-bound tenants: header may be omitted; key tenant is used.
    - Unscoped keys: denied even if tenant is supplied, EXCEPT /ai/query env key path
      (handled inside bind_tenant_id()).
    """
    return bind_tenant_id(
        request,
        x_tenant_id,
        require_explicit_for_unscoped=True,
    )

'''

src2 = src[:insert_at] + block.lstrip("\n") + src[insert_at:]
path.write_text(src2, encoding="utf-8")
print("OK: inserted require_bound_tenant above require_tenant_id")
PY

ruff format "$FILE"
ruff check "$FILE"

python -m pytest -q -k "tenant_binding or unscoped_key_requires_tenant_header" || true
