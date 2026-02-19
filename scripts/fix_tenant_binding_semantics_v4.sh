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

# --- replace require_bound_tenant (make it callable, not dependency-injected) ---
m_req = re.search(r"(?ms)^def\s+require_bound_tenant\s*\(.*?\)\s*:\n(.*?)(?=^def\s|\Z)", src)
if not m_req:
    raise SystemExit("ERROR: require_bound_tenant not found")

require_bound_tenant_block = r'''
def require_bound_tenant(request: Request, x_tenant_id: Optional[str] = None) -> str:
    """
    Callable helper (NOT a FastAPI Header dependency).
    Several routes call this as require_bound_tenant(request), so we must read headers ourselves.
    """
    if x_tenant_id is None:
        x_tenant_id = request.headers.get("X-Tenant-Id")
    return bind_tenant_id(
        request,
        x_tenant_id,
        require_explicit_for_unscoped=True,
    )
'''.lstrip("\n")

src = src[:m_req.start()] + require_bound_tenant_block + src[m_req.end():]

# --- replace bind_tenant_id with deterministic semantics ---
m_bind = re.search(r"(?ms)^def\s+bind_tenant_id\s*\(.*?\)\s*:\n(.*?)(?=^def\s|\Z)", src)
if not m_bind:
    raise SystemExit("ERROR: bind_tenant_id not found")

bind_block = r'''
def bind_tenant_id(
    request: Request,
    requested_tenant: Optional[str],
    *,
    require_explicit_for_unscoped: bool = False,
    default_unscoped: Optional[str] = None,
) -> str:
    """
    Tenant binding contract:

    - If the API key is tenant-bound: the effective tenant is ALWAYS the key's tenant.
      If the client supplies a different tenant (query/header/body/path), deny with 403.

    - If the API key is unscoped:
      - Any supplied tenant must be valid format; invalid -> 400 invalid tenant_id.
      - Only /ai/query may use FG_API_KEY (env) with X-Tenant-Id for dev convenience.
      - Otherwise: unscoped keys cannot act on ANY tenant, even if supplied -> 400.
    """
    st = getattr(request, "state", None)

    # What auth_gate set from the API key.
    key_tenant = getattr(st, "tenant_id", None) if st is not None else None
    key_is_bound = bool(getattr(st, "tenant_is_key_bound", False)) if st is not None else bool(key_tenant)

    # Normalize supplied tenant from arg or header
    req_tenant = (requested_tenant or "").strip() or None
    hdr_tenant = (request.headers.get("X-Tenant-Id") or "").strip() or None
    supplied = req_tenant or hdr_tenant

    # Helper: request path
    path = ""
    try:
        path = request.url.path
    except Exception:
        path = str(getattr(request, "scope", {}).get("path", ""))

    # Key-bound: clamp, mismatch -> 403
    if key_is_bound and key_tenant:
        if supplied and supplied != key_tenant:
            tenant_denial(
                request,
                reason="tenant_mismatch",
                tenant_supplied=supplied,
                tenant_from_key=key_tenant,
            )
            raise HTTPException(
                status_code=403,
                detail=redact_detail("tenant mismatch", generic="forbidden"),
            )
        if st is not None:
            st.tenant_id = key_tenant
            st.tenant_is_key_bound = True
        return str(key_tenant)

    # Unscoped key: if tenant supplied, validate format first.
    if supplied:
        valid, _err = _validate_tenant_id(supplied)
        if not valid:
            raise HTTPException(
                status_code=400,
                detail=redact_detail("invalid tenant_id", generic="invalid request"),
            )

    # Special-case: /ai/query allows FG_API_KEY env key to bind a supplied tenant header.
    env_key = (os.getenv("FG_API_KEY") or "").strip()
    presented = (request.headers.get("X-API-Key") or "").strip()
    if path == "/ai/query" and env_key and presented == env_key:
        if not supplied:
            raise HTTPException(
                status_code=400,
                detail=redact_detail(
                    "tenant_id required for unscoped keys", generic="invalid request"
                ),
            )
        if st is not None:
            st.tenant_id = supplied
            st.tenant_is_key_bound = False
        return str(supplied)

    # Unscoped minted keys cannot act on any tenant even if tenant is supplied.
    if require_explicit_for_unscoped:
        raise HTTPException(
            status_code=400,
            detail=redact_detail(
                "tenant_id required for unscoped keys", generic="invalid request"
            ),
        )

    # If a legacy caller wants a default for unscoped, allow it.
    if default_unscoped:
        if st is not None:
            st.tenant_id = default_unscoped
            st.tenant_is_key_bound = False
        return str(default_unscoped)

    raise HTTPException(
        status_code=400,
        detail=redact_detail("tenant_id required", generic="invalid request"),
    )
'''.lstrip("\n")

src = src[:m_bind.start()] + bind_block + src[m_bind.end():]

path.write_text(src, encoding="utf-8")
print("OK: rewrote bind_tenant_id + require_bound_tenant deterministically")
PY

ruff format "$FILE"
ruff check "$FILE"
