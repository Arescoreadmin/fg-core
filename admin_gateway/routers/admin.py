"""Admin router.

Handles admin-specific endpoints including /admin/me.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from admin_gateway.auth import (
    Session,
    Scope,
    get_current_session,
    require_scope_dependency,
    verify_csrf,
)
from admin_gateway.auth.scopes import get_all_scopes, has_scope
from admin_gateway.auth.tenant import get_allowed_tenants

log = logging.getLogger("admin-gateway.admin-router")

router = APIRouter(prefix="/admin", tags=["admin"])


class UserInfo(BaseModel):
    """User information response."""

    user_id: str
    email: Optional[str] = None
    name: Optional[str] = None
    scopes: list[str]
    tenants: list[str]
    current_tenant: Optional[str] = None
    session_id: str
    expires_in: int


class CSRFTokenResponse(BaseModel):
    """CSRF token response."""

    csrf_token: str
    header_name: str


class AdminCreateKeyRequest(BaseModel):
    """Request model for admin key creation."""

    name: Optional[str] = Field(None, max_length=128)
    scopes: list[str] = Field(default_factory=list)
    tenant_id: str = Field(..., max_length=128)
    ttl_seconds: int = Field(default=86400, ge=60, le=365 * 24 * 3600)


class AdminRotateKeyRequest(BaseModel):
    """Request model for admin key rotation."""

    ttl_seconds: int = Field(default=86400, ge=60, le=365 * 24 * 3600)
    revoke_old: bool = Field(default=True)


def _clamp_tenant_id(
    session: Session,
    tenant_id: Optional[str],
) -> str:
    allowed = get_allowed_tenants(session)
    if tenant_id:
        if tenant_id not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to tenant: {tenant_id}",
            )
        return tenant_id
    if len(allowed) == 1:
        return next(iter(allowed))
    raise HTTPException(
        status_code=400,
        detail="tenant_id is required",
    )


def _core_base_url() -> str:
    base_url = (os.getenv("AG_CORE_BASE_URL") or "").strip()
    if not base_url:
        raise HTTPException(
            status_code=503,
            detail="Core service unavailable: AG_CORE_BASE_URL not configured",
        )
    return base_url.rstrip("/")


def _core_api_key() -> str:
    api_key = (os.getenv("AG_CORE_API_KEY") or "").strip()
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Core service unavailable: AG_CORE_API_KEY not configured",
        )
    return api_key


async def _proxy_to_core(
    request: Request,
    method: str,
    path: str,
    *,
    params: Optional[dict[str, Any]] = None,
    json_body: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    base_url = _core_base_url()
    headers = {
        "X-API-Key": _core_api_key(),
        "X-Request-Id": getattr(request.state, "request_id", ""),
    }

    # FG-AUD-009: follow_redirects=False prevents SSRF via redirect chain in proxy path.
    async with httpx.AsyncClient(base_url=base_url, timeout=15.0, follow_redirects=False) as client:
        response = await client.request(
            method,
            path,
            params=params,
            json=json_body,
            headers=headers,
        )

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = response.text
        raise HTTPException(status_code=response.status_code, detail=detail)

    return response.json()


async def _proxy_to_core_raw(
    request: Request,
    method: str,
    path: str,
    *,
    params: Optional[dict[str, Any]] = None,
    json_body: Optional[dict[str, Any]] = None,
) -> Response:
    base_url = _core_base_url()
    headers = {
        "X-API-Key": _core_api_key(),
        "X-Request-Id": getattr(request.state, "request_id", ""),
    }

    # FG-AUD-004: timeout=None removed.  Streaming exports use a generous read
    # timeout (300 s) but are bounded to prevent indefinitely hung connections.
    # FG-AUD-009: follow_redirects=False prevents SSRF via redirect chain.
    _export_timeout = httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=10.0)
    async with httpx.AsyncClient(
        base_url=base_url, timeout=_export_timeout, follow_redirects=False
    ) as client:
        async with client.stream(
            method,
            path,
            params=params,
            json=json_body,
            headers=headers,
        ) as response:
            if response.status_code >= 400:
                body = await response.aread()
                try:
                    detail = json.loads(body).get("detail")
                except (json.JSONDecodeError, AttributeError):
                    detail = body.decode("utf-8", errors="replace")
                raise HTTPException(status_code=response.status_code, detail=detail)

            content_type = response.headers.get(
                "content-type", "application/octet-stream"
            )

            async def _stream():
                async for chunk in response.aiter_bytes():
                    yield chunk

            proxy_response = StreamingResponse(
                _stream(),
                media_type=content_type,
            )
            for header_name in ("content-disposition",):
                header_value = response.headers.get(header_name)
                if header_value:
                    proxy_response.headers[header_name] = header_value
            return proxy_response


def _audit_redaction_enabled() -> bool:
    return os.getenv("FG_AUDIT_REDACT", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }


def _redact_audit_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not _audit_redaction_enabled():
        return items
    redacted: list[dict[str, Any]] = []
    for item in items:
        copy = dict(item)
        copy["ip"] = None
        copy["user_agent"] = None
        redacted.append(copy)
    return redacted


@router.get("/me", response_model=UserInfo)
async def get_current_user(
    request: Request,
    session: Session = Depends(get_current_session),
) -> UserInfo:
    """Get current authenticated user information.

    Returns user profile, scopes, and tenant access.
    """
    allowed_tenants = get_allowed_tenants(session)

    return UserInfo(
        user_id=session.user_id,
        email=session.email,
        name=session.name,
        scopes=sorted(session.scopes),
        tenants=sorted(allowed_tenants),
        current_tenant=session.tenant_id,
        session_id=session.session_id,
        expires_in=session.remaining_ttl,
    )


@router.get("/csrf-token", response_model=CSRFTokenResponse)
async def get_csrf_token(
    request: Request,
    session: Session = Depends(get_current_session),
) -> CSRFTokenResponse:
    """Get CSRF token for state-changing requests.

    The token is also set in a cookie. Include the token value
    in the X-CSRF-Token header for POST/PUT/PATCH/DELETE requests.
    """
    from admin_gateway.auth.csrf import CSRFProtection
    from admin_gateway.auth.config import get_auth_config

    config = get_auth_config()
    csrf = CSRFProtection(config)

    # Get token from cookie or generate new one
    token = request.cookies.get(config.csrf_cookie_name)
    if not token:
        token = csrf._generate_token()

    response = JSONResponse(
        content={
            "csrf_token": token,
            "header_name": config.csrf_header_name,
        }
    )
    csrf.set_token_cookie(response, token)
    return response


@router.get("/scopes")
async def list_scopes(
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List all available scopes and user's current scopes."""
    return {
        "available_scopes": get_all_scopes(),
        "user_scopes": sorted(session.scopes),
    }


@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    session: Session = Depends(get_current_session),
) -> HTMLResponse:
    """Admin console dashboard (HTML)."""
    allowed = any(
        has_scope(session.scopes, scope)
        for scope in (
            Scope.CONSOLE_ADMIN,
            Scope.KEYS_READ,
            Scope.AUDIT_READ,
            Scope.PRODUCT_READ,
        )
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    html = """\
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>FrostGate Admin Console</title>
  <style>
    :root {
      color-scheme: dark;
      --fg-blue: #2b5cff;
      --fg-orange: #ff7a1a;
      --fg-bg: #05070b;
      --fg-panel: rgba(12, 16, 24, 0.92);
      --fg-border: rgba(255,255,255,0.08);
      --fg-text: #eef2ff;
      --fg-muted: #a0a9bb;
    }
    body {
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(circle at top left, rgba(43,92,255,0.18), transparent 45%),
                  radial-gradient(circle at top right, rgba(255,122,26,0.22), transparent 45%),
                  var(--fg-bg);
      color: var(--fg-text);
    }
    .wrap { padding: 20px; }
    .panel {
      background: var(--fg-panel);
      border: 1px solid var(--fg-border);
      border-radius: 16px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .row { display:flex; gap:12px; flex-wrap: wrap; align-items:center; }
    .title { font-size: 20px; font-weight: 600; }
    .chip {
      padding: 4px 10px; border-radius: 999px;
      border: 1px solid var(--fg-border); color: var(--fg-muted); font-size: 12px;
    }
    .table { width:100%; border-collapse: collapse; font-size: 13px; }
    .table th, .table td { padding: 8px; border-bottom: 1px solid var(--fg-border); text-align: left; }
    .table th { color: var(--fg-muted); font-weight: 500; }
    select, button {
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--fg-border);
      border-radius: 10px;
      padding: 8px 10px;
      color: var(--fg-text);
    }
    button.primary {
      background: linear-gradient(120deg, rgba(43,92,255,0.8), rgba(255,122,26,0.8));
      border: none;
      color: #fff;
    }
    .muted { color: var(--fg-muted); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <div class="row">
        <div class="title">Admin Console</div>
        <span class="chip" id="sessionMeta">session: --</span>
        <span class="chip" id="requestMeta">request_id: --</span>
        <div class="row" style="margin-left:auto;">
          <label class="muted">Tenant
            <select id="tenantSelect"></select>
          </label>
          <button id="refreshBtn">Refresh</button>
        </div>
      </div>
    </div>

    <div class="panel" id="usagePanel">
      <div class="row">
        <div>
          <strong>Usage & Quota</strong>
          <div class="muted">Tenant-scoped usage from core</div>
        </div>
      </div>
      <div id="usageSummary" class="row" style="margin-top:12px;"></div>
    </div>

    <div class="panel" id="keysPanel">
      <div class="row">
        <div>
          <strong>API Keys</strong>
          <div class="muted">Tenant key inventory</div>
        </div>
      </div>
      <table class="table" id="keysTable">
        <thead>
          <tr><th>Prefix</th><th>Name</th><th>Scopes</th><th>Status</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

    <div class="panel" id="auditPanel">
      <div class="row">
        <div>
          <strong>Audit Log</strong>
          <div class="muted">Latest tenant audit events</div>
        </div>
      </div>
      <table class="table" id="auditTable">
        <thead>
          <tr><th>Time</th><th>Action</th><th>Actor</th><th>Status</th><th>Request ID</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
<script>
const tenantSelect = document.getElementById("tenantSelect");
const refreshBtn = document.getElementById("refreshBtn");
const sessionMeta = document.getElementById("sessionMeta");
const requestMeta = document.getElementById("requestMeta");
const usageSummary = document.getElementById("usageSummary");
const keysTable = document.querySelector("#keysTable tbody");
const auditTable = document.querySelector("#auditTable tbody");
const usagePanel = document.getElementById("usagePanel");
const keysPanel = document.getElementById("keysPanel");
const auditPanel = document.getElementById("auditPanel");

async function loadSession() {
  const resp = await fetch("/admin/me");
  if (!resp.ok) return;
  const data = await resp.json();
  sessionMeta.textContent = `session: ${data.user_id}`;
  tenantSelect.innerHTML = (data.tenants || []).map(t => `<option value="${t}">${t}</option>`).join("");
  if (data.current_tenant) tenantSelect.value = data.current_tenant;
}

async function loadScopes() {
  const resp = await fetch("/admin/scopes");
  if (!resp.ok) return;
  const data = await resp.json();
  requestMeta.textContent = resp.headers.get("X-Request-Id") || "request_id: --";
  const scopes = new Set(data.user_scopes || []);
  if (!scopes.has("keys:read")) keysPanel.style.display = "none";
  if (!scopes.has("audit:read")) auditPanel.style.display = "none";
  if (!scopes.has("product:read")) usagePanel.style.display = "none";
}

async function loadUsage() {
  if (usagePanel.style.display === "none") return;
  const tenant = tenantSelect.value;
  const resp = await fetch(`/admin/tenants/${tenant}/usage`);
  if (!resp.ok) return;
  const data = await resp.json();
  usageSummary.innerHTML = `
    <span class="chip">Requests: ${data.request_count}</span>
    <span class="chip">Decisions: ${data.decision_count}</span>
    <span class="chip">Quota: ${data.quota_remaining}/${data.quota_limit}</span>
    <span class="chip">Tier: ${data.tier}</span>
  `;
}

async function loadKeys() {
  if (keysPanel.style.display === "none") return;
  const tenant = tenantSelect.value;
  const resp = await fetch(`/admin/keys?tenant_id=${encodeURIComponent(tenant)}`);
  if (!resp.ok) return;
  const data = await resp.json();
  const items = data.items || data.keys || [];
  keysTable.innerHTML = items.map(item => `
    <tr>
      <td>${item.prefix || ""}</td>
      <td>${item.name || ""}</td>
      <td>${(item.scopes || []).join(", ")}</td>
      <td>${item.enabled ? "active" : "disabled"}</td>
    </tr>
  `).join("");
}

async function loadAudit() {
  if (auditPanel.style.display === "none") return;
  const tenant = tenantSelect.value;
  const resp = await fetch(`/admin/audit/search?tenant_id=${encodeURIComponent(tenant)}&page_size=10`);
  if (!resp.ok) return;
  const data = await resp.json();
  const items = data.items || [];
  auditTable.innerHTML = items.map(item => `
    <tr>
      <td>${item.timestamp || ""}</td>
      <td>${item.action || ""}</td>
      <td>${item.actor || ""}</td>
      <td>${item.status || ""}</td>
      <td>${item.request_id || ""}</td>
    </tr>
  `).join("");
}

async function refreshAll() {
  await loadUsage();
  await loadKeys();
  await loadAudit();
}

refreshBtn.addEventListener("click", refreshAll);

loadSession().then(() => loadScopes().then(refreshAll));
</script>
</body>
</html>
"""
    return HTMLResponse(html)


@router.get(
    "/tenants",
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_READ))],
)
async def list_tenants(
    request: Request,
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List tenants the user has access to.

    Requires product:read or higher scope.
    """
    allowed = get_allowed_tenants(session)

    # Audit log
    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_tenants",
            resource="tenants",
            outcome="success",
            actor=session.user_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return {
        "tenants": [{"id": t, "name": t} for t in sorted(allowed)],
        "total": len(allowed),
    }


@router.get(
    "/keys",
    dependencies=[Depends(require_scope_dependency(Scope.KEYS_READ))],
)
async def list_keys(
    request: Request,
    tenant_id: Optional[str] = Query(None, description="Filter by tenant"),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List API keys (proxied to core).

    Requires keys:read or higher scope.
    """
    allowed = get_allowed_tenants(session)
    if tenant_id and tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    payload = await _proxy_to_core(
        request,
        "GET",
        "/admin/keys",
        params={"tenant_id": tenant_id} if tenant_id else None,
    )

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_keys",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": tenant_id},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return payload


@router.get(
    "/tenants/{tenant_id}/usage",
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_READ))],
)
async def get_usage(
    tenant_id: str,
    request: Request,
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Proxy tenant usage to core (tenant-scoped)."""
    effective = _clamp_tenant_id(session, tenant_id)
    payload = await _proxy_to_core(
        request,
        "GET",
        f"/admin/tenants/{effective}/usage",
    )
    payload["request_id"] = getattr(request.state, "request_id", "unknown")
    return payload


@router.post(
    "/keys",
    dependencies=[
        Depends(require_scope_dependency(Scope.KEYS_WRITE)),
        Depends(verify_csrf),
    ],
)
async def create_key(
    request: Request,
    payload: AdminCreateKeyRequest,
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Create a new API key (proxied to core).

    Requires keys:write scope and tenant_id.
    """
    allowed = get_allowed_tenants(session)
    if payload.tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {payload.tenant_id}",
        )

    response = await _proxy_to_core(
        request,
        "POST",
        "/admin/keys",
        json_body=payload.model_dump(),
    )

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="create_key",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": payload.tenant_id},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return response


@router.post(
    "/keys/{prefix}/revoke",
    dependencies=[
        Depends(require_scope_dependency(Scope.KEYS_WRITE)),
        Depends(verify_csrf),
    ],
)
async def revoke_key(
    prefix: str,
    request: Request,
    tenant_id: str = Query(..., description="Tenant ID (required for writes)"),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Revoke an API key (proxied to core)."""
    allowed = get_allowed_tenants(session)
    if tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    response = await _proxy_to_core(
        request,
        "POST",
        f"/admin/keys/{prefix}/revoke",
        params={"tenant_id": tenant_id},
    )

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="revoke_key",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": tenant_id, "prefix": prefix},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return response


@router.post(
    "/keys/{prefix}/rotate",
    dependencies=[
        Depends(require_scope_dependency(Scope.KEYS_WRITE)),
        Depends(verify_csrf),
    ],
)
async def rotate_key(
    prefix: str,
    payload: AdminRotateKeyRequest,
    request: Request,
    tenant_id: str = Query(..., description="Tenant ID (required for writes)"),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Rotate an API key (proxied to core)."""
    allowed = get_allowed_tenants(session)
    if tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    response = await _proxy_to_core(
        request,
        "POST",
        f"/admin/keys/{prefix}/rotate",
        params={"tenant_id": tenant_id},
        json_body=payload.model_dump(),
    )

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="rotate_key",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": tenant_id, "prefix": prefix},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return response


@router.get(
    "/audit/search",
    dependencies=[Depends(require_scope_dependency(Scope.AUDIT_READ))],
)
async def search_audit_events(
    request: Request,
    tenant_id: Optional[str] = Query(None, description="Tenant filter"),
    action: Optional[str] = Query(None, description="Filter by action"),
    actor: Optional[str] = Query(None, description="Filter by actor"),
    status: Optional[str] = Query(None, description="Filter by status"),
    request_id: Optional[str] = Query(None, description="Filter by request id"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[str] = Query(None, description="Filter by resource id"),
    from_ts: Optional[str] = Query(None, description="Start time (RFC3339)"),
    to_ts: Optional[str] = Query(None, description="End time (RFC3339)"),
    cursor: Optional[str] = Query(None, description="Pagination cursor"),
    page_size: int = Query(100, ge=1, le=1000),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Search audit events."""
    effective_tenant_id = _clamp_tenant_id(session, tenant_id)
    log.info(
        "audit.search",
        extra={"effective_tenant_id": effective_tenant_id},
    )

    params: dict[str, Any] = {
        "tenant_id": effective_tenant_id,
        "action": action,
        "actor": actor,
        "status": status,
        "request_id": request_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "cursor": cursor,
        "page_size": page_size,
    }
    params = {k: v for k, v in params.items() if v is not None}

    response = await _proxy_to_core(
        request,
        "GET",
        "/admin/audit/search",
        params=params,
    )

    if "items" in response and isinstance(response["items"], list):
        response["items"] = _redact_audit_items(response["items"])

    return response


class AuditExportRequest(BaseModel):
    """Audit export request."""

    format: str = Field(..., pattern="^(csv|json)$")
    tenant_id: Optional[str] = None
    action: Optional[str] = None
    actor: Optional[str] = None
    status: Optional[str] = None
    request_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    from_ts: Optional[str] = None
    to_ts: Optional[str] = None
    page_size: int = Field(default=1000, ge=1, le=5000)


@router.post(
    "/audit/export",
    dependencies=[Depends(require_scope_dependency(Scope.AUDIT_READ))],
    responses={
        200: {
            "description": "Streaming audit export (CSV or NDJSON).",
            "content": {
                "text/csv": {"schema": {"type": "string", "format": "binary"}},
                "application/x-ndjson": {
                    "schema": {"type": "string", "format": "binary"}
                },
            },
            "headers": {
                "Content-Disposition": {
                    "description": "Attachment filename for the export payload.",
                    "schema": {"type": "string"},
                },
                "Content-Type": {
                    "description": "Streaming content type.",
                    "schema": {"type": "string"},
                },
            },
        }
    },
)
async def export_audit_events(
    request: Request,
    payload: AuditExportRequest,
    session: Session = Depends(get_current_session),
) -> Response:
    """Export audit events as CSV/JSON."""
    effective_tenant_id = _clamp_tenant_id(session, payload.tenant_id)
    log.info(
        "audit.export",
        extra={"effective_tenant_id": effective_tenant_id},
    )

    body = payload.model_dump()
    body["tenant_id"] = effective_tenant_id

    return await _proxy_to_core_raw(
        request,
        "POST",
        "/admin/audit/export",
        json_body=body,
    )
