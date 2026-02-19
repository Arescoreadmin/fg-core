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

def replace_func(name: str, new_block: str) -> str:
    pat = rf"(?ms)^def\s+{re.escape(name)}\s*\(.*?\)\s*:\n.*?(?=^def\s|\Z)"
    m = re.search(pat, src)
    if not m:
        raise SystemExit(f"ERROR: could not find function {name}")
    return re.sub(pat, new_block.strip() + "\n\n", src, count=1)

tenant_denial_block = r'''
def tenant_denial(
    request: Request,
    *,
    reason: str,
    tenant_supplied: Optional[str] = None,
    tenant_from_key: Optional[str] = None,
) -> None:
    """
    Security log for tenant binding denials.

    Tests require:
      - logger name: frostgate.security
      - msg: "tenant_denial"
      - extra fields: event, reason, env, route, method, request_id, remote_ip, tenant_id_hash, key_id
    """
    import os

    log = logging.getLogger("frostgate.security")
    env = os.getenv("FG_ENV", "dev")

    # Route + method (support real Request and mocks)
    route = None
    method = None
    try:
        route = getattr(getattr(request, "url", None), "path", None) or getattr(request, "scope", {}).get("path")
    except Exception:
        route = None
    try:
        method = getattr(request, "method", None) or getattr(request, "scope", {}).get("method")
    except Exception:
        method = None

    # Request id
    request_id = None
    headers = getattr(request, "headers", None) or {}
    try:
        request_id = headers.get("X-Request-Id") or headers.get("X-Request-ID")
    except Exception:
        request_id = None
    if not request_id:
        request_id = getattr(getattr(request, "state", None), "request_id", None)

    # Remote IP (trust proxy only if explicitly enabled)
    trust_proxy = os.getenv("FG_TRUST_PROXY_HEADERS", "0").strip() in ("1", "true", "TRUE", "yes", "YES")
    remote_ip = None
    if trust_proxy:
        try:
            xff = headers.get("X-Forwarded-For")
            if xff:
                remote_ip = xff.split(",")[0].strip()
        except Exception:
            remote_ip = None
    if not remote_ip:
        try:
            client = getattr(request, "client", None)
            remote_ip = getattr(client, "host", None)
        except Exception:
            remote_ip = None

    # Key id: best-effort from auth
    st = getattr(request, "state", None)
    auth = getattr(st, "auth", None) if st is not None else None
    key_id = getattr(auth, "key_id", None) or getattr(auth, "key_hash", None) or getattr(auth, "id", None)

    log.warning(
        "tenant_denial",
        extra={
            "event": "tenant_denial",
            "reason": reason,
            "env": env,
            "route": route,
            "method": method,
            "request_id": request_id,
            "remote_ip": remote_ip,
            "tenant_id_hash": _tenant_hash(tenant_supplied or tenant_from_key),
            "key_id": key_id,
        },
    )
'''

bind_tenant_id_block = r'''
def bind_tenant_id(
    request: Request,
    requested_tenant: Optional[str],
    *,
    require_explicit_for_unscoped: bool = False,
    default_unscoped: Optional[str] = None,
) -> str:
    """
    Tenant binding contract:

    - If the API key is tenant-bound: effective tenant is ALWAYS the key's tenant.
      If the client supplies a different tenant (query/header/body/path), deny with 403.

    - If the API key is unscoped:
      - If any supplied tenant is invalid format -> 400 invalid tenant_id.
      - Only /ai/query may use FG_API_KEY (env) with X-Tenant-Id for dev convenience.
      - Otherwise: unscoped keys cannot act on ANY tenant, even if supplied -> 400.
    """
    import os

    st = getattr(request, "state", None)
    if st is None:
        # extremely defensive: treat as unscoped request object with no state
        st = type("State", (), {})()
        setattr(request, "state", st)

    # Cache: if auth tenant already computed, reuse.
    cached = getattr(st, "tenant_id", None)
    cached_is_bound = bool(getattr(st, "tenant_is_key_bound", False))
    if cached is None and not cached_is_bound:
        # Use the shared helper so tests can monkeypatch + count calls.
        # This helper should derive auth tenant from request.state.auth or verification.
        auth_tenant = None
        auth_is_bound = False
        try:
            auth_tenant = _auth_tenant_from_request(request)
        except Exception:
            auth_tenant = None
        # Determine boundness from request.state.auth if present
        auth = getattr(st, "auth", None)
        if auth is not None:
            auth_tenant = getattr(auth, "tenant_id", None) or auth_tenant
        auth_is_bound = bool(auth_tenant)

        st.tenant_id = auth_tenant
        st.tenant_is_key_bound = bool(auth_is_bound)
        cached = st.tenant_id
        cached_is_bound = bool(st.tenant_is_key_bound)

    key_tenant = cached
    key_is_bound = cached_is_bound or bool(key_tenant)

    # Gather supplied tenant (query arg preferred, then header)
    req_tenant = (requested_tenant or "").strip() or None
    headers = getattr(request, "headers", None) or {}
    hdr_tenant = None
    try:
        hdr_tenant = (headers.get("X-Tenant-Id") or "").strip() or None
    except Exception:
        hdr_tenant = None
    supplied = req_tenant or hdr_tenant

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
        st.tenant_id = key_tenant
        st.tenant_is_key_bound = True
        return str(key_tenant)

    # Unscoped: validate supplied format if present
    if supplied:
        valid, _err = _validate_tenant_id(supplied)
        if not valid:
            raise HTTPException(
                status_code=400,
                detail=redact_detail("invalid tenant_id", generic="invalid request"),
            )

    # /ai/query exception for env key only
    path = None
    try:
        path = getattr(getattr(request, "url", None), "path", None) or getattr(request, "scope", {}).get("path")
    except Exception:
        path = None

    presented = None
    try:
        presented = headers.get("X-API-Key")
    except Exception:
        presented = None
    env_key = os.getenv("FG_API_KEY")

    if path == "/ai/query" and env_key and presented and presented == env_key:
        if hdr_tenant:
            st.tenant_id = hdr_tenant
            st.tenant_is_key_bound = False
            return str(hdr_tenant)
        raise HTTPException(
            status_code=400,
            detail=redact_detail("tenant_id required for unscoped keys", generic="invalid request"),
        )

    # Otherwise, unscoped keys cannot act on any tenant
    if require_explicit_for_unscoped:
        raise HTTPException(
            status_code=400,
            detail=redact_detail("tenant_id required for unscoped keys", generic="invalid request"),
        )

    if default_unscoped:
        st.tenant_id = default_unscoped
        st.tenant_is_key_bound = False
        return str(default_unscoped)

    raise HTTPException(
        status_code=400,
        detail=redact_detail("tenant_id required for unscoped keys", generic="invalid request"),
    )
'''

require_bound_tenant_block = r'''
def require_bound_tenant(request: Request, x_tenant_id: Optional[str] = None) -> str:
    """
    Callable helper (NOT a FastAPI Header dependency).
    Must work with real Requests and test DummyReq objects without .headers.
    """
    headers = getattr(request, "headers", None) or {}
    if x_tenant_id is None:
        try:
            x_tenant_id = headers.get("X-Tenant-Id")
        except Exception:
            x_tenant_id = None
    return bind_tenant_id(
        request,
        (x_tenant_id or "").strip() or None,
        require_explicit_for_unscoped=True,
    )
'''

# Apply replacements
src = re.sub(r"(?ms)^def\s+tenant_denial\s*\(.*?\)\s*:\n.*?(?=^def\s|\Z)", tenant_denial_block.strip() + "\n\n", src, count=1) \
      if re.search(r"(?m)^def\s+tenant_denial\s*\(", src) else tenant_denial_block.strip() + "\n\n" + src

# bind_tenant_id and require_bound_tenant must exist
for name, block in [("bind_tenant_id", bind_tenant_id_block), ("require_bound_tenant", require_bound_tenant_block)]:
    pat = rf"(?ms)^def\s+{re.escape(name)}\s*\(.*?\)\s*:\n.*?(?=^def\s|\Z)"
    if not re.search(pat, src):
        raise SystemExit(f"ERROR: {name} not found")
    src = re.sub(pat, block.strip() + "\n\n", src, count=1)

p.write_text(src, encoding="utf-8")
print("OK: rewrote tenant_denial + bind_tenant_id + require_bound_tenant (v5)")
PY

ruff check api/auth_scopes/resolution.py
ruff format api/auth_scopes/resolution.py
