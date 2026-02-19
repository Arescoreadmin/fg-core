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

m = re.search(r"(?ms)^def bind_tenant_id\([\s\S]*?\):\n", src)
if not m:
    raise SystemExit("ERROR: bind_tenant_id def not found")

start = m.start()
# Replace until next top-level def (require_tenant_id is right after in your file)
m2 = re.search(r"(?ms)^def require_tenant_id\(", src[m.end():])
if not m2:
    raise SystemExit("ERROR: could not find def require_tenant_id after bind_tenant_id")

end = m.end() + m2.start()

# Ensure HTTPException imported
if "HTTPException" not in src:
    if re.search(r"^from\s+fastapi\s+import\s+.*$", src, flags=re.M):
        src = re.sub(
            r"^(from\s+fastapi\s+import\s+)(.*)$",
            lambda mm: mm.group(0) if "HTTPException" in mm.group(2) else f"{mm.group(1)}{mm.group(2)}, HTTPException",
            src,
            flags=re.M,
            count=1,
        )
    else:
        src = "from fastapi import HTTPException\n" + src

new_fn = r'''
def bind_tenant_id(
    request: Request,
    requested_tenant: Optional[str],
    *,
    require_explicit_for_unscoped: bool = False,
    default_unscoped: Optional[str] = None,
) -> str:
    """
    Canonical tenant binding.

    Rules:
    - Key-bound tenant wins. If caller supplies a tenant, it must match key-bound tenant.
    - Unscoped keys cannot act on ANY tenant even if tenant_id is supplied.
      Exception: env FG_API_KEY may bind X-Tenant-Id for /ai/query only (dev convenience).
    """
    # Normalize inputs
    req_tenant = (requested_tenant or "").strip() or None
    header_tenant = None
    try:
        header_tenant = (request.headers.get("X-Tenant-Id") or "").strip() or None
    except Exception:
        header_tenant = None

    path = ""
    try:
        path = str(getattr(getattr(request, "url", None), "path", "") or "")
    except Exception:
        path = ""

    st = getattr(request, "state", None)
    tenant_from_key = getattr(st, "tenant_id", None) if st is not None else None
    key_is_bound = bool(getattr(st, "tenant_is_key_bound", False)) if st is not None else bool(tenant_from_key)

    # Detect env key (best-effort, deterministic)
    presented_key = None
    try:
        presented_key = (request.headers.get("X-API-Key") or "").strip() or None
    except Exception:
        presented_key = None

    expected_env_key = None
    try:
        expected_env_key = getattr(globals().get("settings"), "FG_API_KEY", None)
    except Exception:
        expected_env_key = None
    if expected_env_key is None:
        try:
            Settings = globals().get("Settings")
            if Settings is not None:
                expected_env_key = getattr(Settings(), "FG_API_KEY", None)
        except Exception:
            expected_env_key = None

    is_env_key = bool(expected_env_key) and bool(presented_key) and presented_key == expected_env_key

    # --- Unscoped key policy ---
    if not key_is_bound:
        # ONLY allow /ai/query with env key to bind tenant from header/body param.
        if path == "/ai/query" and is_env_key:
            effective = req_tenant or header_tenant
            if not effective:
                raise HTTPException(
                    status_code=400,
                    detail=redact_detail(
                        "tenant_id required for unscoped keys",
                        generic="invalid request",
                    ),
                )
            if st is not None:
                st.tenant_id = effective
                st.tenant_is_key_bound = False
            return effective

        # Otherwise: forbid ANY tenant selection
        if req_tenant or header_tenant:
            raise HTTPException(
                status_code=400,
                detail=redact_detail(
                    "tenant_id required for unscoped keys",
                    generic="invalid request",
                ),
            )

        if require_explicit_for_unscoped:
            raise HTTPException(
                status_code=400,
                detail=redact_detail(
                    "tenant_id required for unscoped keys",
                    generic="invalid request",
                ),
            )

        if default_unscoped:
            if st is not None:
                st.tenant_id = default_unscoped
                st.tenant_is_key_bound = False
            return default_unscoped

        # No safe default: fail closed
        raise HTTPException(
            status_code=400,
            detail=redact_detail(
                "tenant_id required for unscoped keys",
                generic="invalid request",
            ),
        )

    # --- Key-bound policy ---
    effective_key_tenant = (tenant_from_key or "").strip()
    if not effective_key_tenant:
        # should be unreachable if key_is_bound is true, but fail closed anyway
        raise HTTPException(
            status_code=400,
            detail=redact_detail(
                "tenant_id required",
                generic="invalid request",
            ),
        )

    supplied = req_tenant or header_tenant
    if supplied and supplied != effective_key_tenant:
        raise HTTPException(
            status_code=400,
            detail=redact_detail(
                "tenant mismatch",
                generic="invalid request",
            ),
        )

    if st is not None:
        st.tenant_id = effective_key_tenant
        st.tenant_is_key_bound = True
    return effective_key_tenant
'''

src2 = src[:start] + new_fn.lstrip("\n") + "\n\n" + src[end:]
path.write_text(src2, encoding="utf-8")
print("OK: rewrote bind_tenant_id with deterministic request.state semantics")
PY

ruff format "$FILE"
ruff check "$FILE"

# Run the failing tests fast first
python -m pytest -q \
  tests/security/test_ai_query_unscoped_key_requires_tenant_header.py \
  tests/security/test_tenant_contract_endpoints.py \
  tests/test_admin_audit_tenant_binding.py \
  tests/test_audit_search.py
