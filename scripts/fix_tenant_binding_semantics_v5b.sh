#!/usr/bin/env bash
set -euo pipefail

FILE="api/auth_scopes/resolution.py"
test -f "$FILE" || { echo "ERROR: $FILE not found"; exit 2; }

python - <<'PY'
from __future__ import annotations

from pathlib import Path
import re

p = Path("api/auth_scopes/resolution.py")
lines = p.read_text(encoding="utf-8").splitlines(True)

def find_top_def(name: str) -> int:
    prefix = f"def {name}"
    for i, ln in enumerate(lines):
        if ln.startswith(prefix):
            return i
    return -1

def find_def_block(name: str) -> tuple[int, int]:
    """Return (start,end) line indices for the top-level def block."""
    start = find_top_def(name)
    if start < 0:
        return (-1, -1)
    # block ends at next top-level "def " or EOF
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("def "):
            end = j
            break
    return (start, end)

tenant_denial_block = """\
def tenant_denial(
    request: Request,
    *,
    reason: str,
    tenant_supplied: Optional[str] = None,
    tenant_from_key: Optional[str] = None,
) -> None:
    \"""
    Security log for tenant binding denials.

    Tests require:
      - logger name: frostgate.security
      - msg: "tenant_denial"
      - extra fields: event, reason, env, route, method, request_id, remote_ip, tenant_id_hash, key_id
    \"""
    import os

    log_sec = logging.getLogger("frostgate.security")
    env = os.getenv("FG_ENV", "dev")

    headers = getattr(request, "headers", None) or {}
    scope = getattr(request, "scope", None) or {}

    # route + method (works for real Request and mocks)
    route = None
    try:
        route = getattr(getattr(request, "url", None), "path", None) or scope.get("path")
    except Exception:
        route = scope.get("path")
    method = None
    try:
        method = getattr(request, "method", None) or scope.get("method")
    except Exception:
        method = scope.get("method")

    # request id
    request_id = None
    try:
        request_id = headers.get("X-Request-Id") or headers.get("X-Request-ID")
    except Exception:
        request_id = None
    if not request_id:
        request_id = getattr(getattr(request, "state", None), "request_id", None)

    # remote_ip (trust proxy only if explicitly enabled)
    trust_proxy = os.getenv("FG_TRUST_PROXY_HEADERS", "0").strip().lower() in ("1", "true", "yes")
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

    # key_id best-effort
    st = getattr(request, "state", None)
    auth = getattr(st, "auth", None) if st is not None else None
    key_id = getattr(auth, "key_id", None) or getattr(auth, "key_hash", None) or getattr(auth, "id", None)

    log_sec.warning(
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
"""

bind_tenant_id_block = """\
def bind_tenant_id(
    request: Request,
    requested_tenant: Optional[str],
    *,
    require_explicit_for_unscoped: bool = False,
    default_unscoped: Optional[str] = None,
) -> str:
    \"""
    Tenant binding contract:

    - If the API key is tenant-bound: effective tenant is ALWAYS the key's tenant.
      If the client supplies a different tenant (query/header/body/path), deny with 403.

    - If the API key is unscoped:
      - If any supplied tenant is invalid format -> 400 invalid tenant_id.
      - Only /ai/query may use FG_API_KEY (env) with X-Tenant-Id for dev convenience.
      - Otherwise: unscoped keys cannot act on ANY tenant, even if supplied -> 400.
    \"""
    import os

    st = getattr(request, "state", None)
    if st is None:
        st = type("State", (), {})()
        setattr(request, "state", st)

    # Ensure auth-derived tenant is cached once per request.
    if getattr(st, "tenant_id", None) is None and not bool(getattr(st, "tenant_is_key_bound", False)):
        # Use shared helper so cache-count test can monkeypatch it.
        auth_tenant = None
        try:
            auth_tenant = _auth_tenant_from_request(request)
        except Exception:
            auth_tenant = None

        auth = getattr(st, "auth", None)
        if auth is not None:
            auth_tenant = getattr(auth, "tenant_id", None) or auth_tenant

        st.tenant_id = auth_tenant
        st.tenant_is_key_bound = bool(auth_tenant)

    key_tenant = getattr(st, "tenant_id", None)
    key_is_bound = bool(getattr(st, "tenant_is_key_bound", False)) or bool(key_tenant)

    # Gather supplied tenant (query preferred, then header)
    req_tenant = (requested_tenant or "").strip() or None
    headers = getattr(request, "headers", None) or {}
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
    scope = getattr(request, "scope", None) or {}
    path = None
    try:
        path = getattr(getattr(request, "url", None), "path", None) or scope.get("path")
    except Exception:
        path = scope.get("path")

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
"""

require_bound_tenant_block = """\
def require_bound_tenant(request: Request, x_tenant_id: Optional[str] = None) -> str:
    \"""
    Callable helper (NOT a FastAPI Header dependency).
    Must work with real Requests and test DummyReq objects without .headers.
    \"""
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
"""

def upsert_func(name: str, block: str, *, insert_after: str | None = None) -> None:
    start, end = find_def_block(name)
    if start >= 0:
        # replace
        lines[start:end] = [block, "\n"]
        return

    if insert_after:
        astart, aend = find_def_block(insert_after)
        if astart < 0:
            raise SystemExit(f"ERROR: cannot insert {name}; anchor {insert_after} not found")
        # insert immediately after anchor block
        lines[aend:aend] = [block, "\n"]
        return

    # fallback: insert at EOF
    lines.append("\n")
    lines.append(block)
    lines.append("\n")

# tenant_denial: replace if present, else insert near the top (after imports is hard; just insert before bind_tenant_id)
# We'll insert before bind_tenant_id if missing.
if find_top_def("tenant_denial") < 0:
    bstart, _ = find_def_block("bind_tenant_id")
    if bstart < 0:
        raise SystemExit("ERROR: bind_tenant_id not found (cannot place tenant_denial)")
    lines[bstart:bstart] = [tenant_denial_block, "\n"]
else:
    upsert_func("tenant_denial", tenant_denial_block)

# bind_tenant_id must exist: replace
if find_top_def("bind_tenant_id") < 0:
    raise SystemExit("ERROR: bind_tenant_id not found")
upsert_func("bind_tenant_id", bind_tenant_id_block)

# require_bound_tenant: replace if present, else insert right after bind_tenant_id
upsert_func("require_bound_tenant", require_bound_tenant_block, insert_after="bind_tenant_id")

p.write_text("".join(lines), encoding="utf-8")
print("OK: upserted tenant_denial + rewrote bind_tenant_id + upserted require_bound_tenant (v5b)")
PY

ruff check api/auth_scopes/resolution.py
ruff format api/auth_scopes/resolution.py
