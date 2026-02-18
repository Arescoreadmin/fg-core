from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from api.auth_scopes import bind_tenant_id, require_scopes
from api.config.env import is_production_env
from api.security_audit import audit_admin_action
from services.dashboard_contracts import (
    ContractLoadError,
    load_json_contract,
    validate_theme_contract,
)

router = APIRouter(prefix="/ui", tags=["ui-theme"])

_THEME_ROOT = Path("contracts/dashboard").resolve()
_THEMES_DIR = _THEME_ROOT / "themes"
_THEME_SCHEMA_PATH = _THEME_ROOT / "schema" / "theme.schema.json"
_MAX_CSS_BYTES = int(os.getenv("FG_THEME_CSS_MAX_BYTES", "16384"))
_MAX_LOGO_URL_LEN = int(os.getenv("FG_THEME_LOGO_URL_MAX_LEN", "2048"))
_REDIRECT_HOPS = int(os.getenv("FG_THEME_LOGO_REDIRECT_HOPS", "3"))
_METADATA_HOSTS = {"metadata.google.internal"}


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_and_validate_host(hostname: str) -> None:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail="invalid_logo_host") from exc
    if not infos:
        raise HTTPException(status_code=400, detail="invalid_logo_host")
    for info in infos:
        addr = info[4][0]
        if _is_private_ip(addr):
            raise HTTPException(status_code=400, detail="private_logo_host_forbidden")


def _allowed_logo_hosts() -> set[str]:
    raw = (os.getenv("FG_THEME_LOGO_HOST_ALLOWLIST") or "").strip()
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _validate_logo_url(raw: str) -> str:
    if len(raw) > _MAX_LOGO_URL_LEN:
        raise HTTPException(status_code=400, detail="logo_url_too_long")
    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="invalid_logo_scheme")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="invalid_logo_userinfo")
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise HTTPException(status_code=400, detail="invalid_logo_host")
    if hostname in _METADATA_HOSTS:
        raise HTTPException(status_code=400, detail="private_logo_host_forbidden")
    if _is_private_ip(hostname):
        raise HTTPException(status_code=400, detail="private_logo_host_forbidden")

    allowlist = _allowed_logo_hosts()
    if allowlist and hostname not in allowlist:
        raise HTTPException(status_code=400, detail="logo_host_not_allowlisted")

    _resolve_and_validate_host(hostname)
    return raw


def _override_params_hash(
    *, source_tenant: str, target_tenant: str, reason: str
) -> str:
    import json

    blob = json.dumps(
        {
            "source_tenant_id": source_tenant,
            "target_tenant_id": target_tenant,
            "reason": reason,
            "route": "/ui/theme",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return __import__("hashlib").sha256(blob.encode("utf-8")).hexdigest()


def _validate_redirect_chain(url: str) -> None:
    if os.getenv("FG_THEME_VALIDATE_REDIRECTS", "0") not in {"1", "true", "yes", "on"}:
        return
    current = url
    for _ in range(_REDIRECT_HOPS):
        resp = requests.get(current, allow_redirects=False, timeout=1.5)
        if resp.is_redirect or resp.is_permanent_redirect:
            location = resp.headers.get("location")
            if not location:
                raise HTTPException(status_code=400, detail="invalid_logo_redirect")
            parsed = urlparse(location)
            if location.startswith("//") or not parsed.scheme:
                raise HTTPException(status_code=400, detail="invalid_logo_redirect")
            if parsed.scheme != "https":
                raise HTTPException(status_code=400, detail="invalid_logo_redirect")
            current = _validate_logo_url(location)
            continue
        return
    raise HTTPException(status_code=400, detail="logo_redirect_hops_exceeded")


def sanitize_css(css: str | None) -> str | None:
    if not css:
        return None
    if len(css.encode("utf-8")) > _MAX_CSS_BYTES:
        raise HTTPException(status_code=400, detail="theme_css_too_large")

    cleaned = css
    cleaned = re.sub(r"@import[^;]*;?", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"url\s*\([^)]*\)", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"expression\s*\([^)]*\)", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace("</style>", "").replace("<", "").replace(">", "")

    banned_patterns = [
        r"@import",
        r"url\s*\(",
        r"expression\s*\(",
        r"</style>",
        r"<",
        r">",
    ]
    for pattern in banned_patterns:
        if re.search(pattern, cleaned, flags=re.IGNORECASE):
            cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE)

    return cleaned.strip() or None


def _theme_for_tenant(tenant_id: str) -> dict[str, Any]:
    path = _THEMES_DIR / f"{tenant_id}.json"
    if not path.exists():
        path = _THEMES_DIR / "default.json"
    _ = load_json_contract(_THEME_SCHEMA_PATH, root=_THEME_ROOT)
    try:
        payload = load_json_contract(path, root=_THEME_ROOT)
    except ContractLoadError as exc:
        raise HTTPException(status_code=500, detail="invalid_theme_contract") from exc

    errs = validate_theme_contract(payload)
    if errs:
        raise HTTPException(status_code=500, detail="invalid_theme_contract")

    payload["logo_url"] = _validate_logo_url(str(payload.get("logo_url") or ""))
    _validate_redirect_chain(payload["logo_url"])
    payload["css_overrides"] = sanitize_css(payload.get("css_overrides"))
    return payload


def _override_enabled() -> bool:
    if is_production_env() or (os.getenv("FG_ENV", "").lower() == "staging"):
        return False
    return os.getenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "0").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _override_scope_and_reason(
    request: Request,
    reason: str | None,
) -> tuple[str, str]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    scopes = set(getattr(auth, "scopes", set()) or set())
    if "admin:tenant_override" not in scopes:
        raise HTTPException(status_code=403, detail="admin_override_scope_required")
    r = (reason or "").strip()
    if len(r) < 8:
        raise HTTPException(status_code=400, detail="admin_override_reason_required")
    return str(getattr(auth, "key_prefix", "unknown")), r


@router.get(
    "/theme",
    dependencies=[Depends(require_scopes("ui:read"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_theme(
    request: Request,
    x_fg_admin_override_tenant: str | None = Header(
        default=None, alias="X-FG-Admin-Override-Tenant"
    ),
    x_fg_override_reason: str | None = Header(
        default=None, alias="X-FG-Override-Reason"
    ),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    target_tenant = tenant_id
    if x_fg_admin_override_tenant:
        if not _override_enabled():
            raise HTTPException(status_code=403, detail="admin_override_disabled")
        key_prefix, reason = _override_scope_and_reason(request, x_fg_override_reason)
        target_tenant = x_fg_admin_override_tenant.strip()
        audit_admin_action(
            action="ui_theme_admin_override",
            tenant_id=tenant_id,
            request=request,
            details={
                "actor_key_prefix": key_prefix,
                "source_tenant_id": tenant_id,
                "target_tenant_id": target_tenant,
                "reason": reason,
                "route": "/ui/theme",
                "parameters_hash": _override_params_hash(
                    source_tenant=tenant_id,
                    target_tenant=target_tenant,
                    reason=reason,
                ),
            },
        )
    theme = _theme_for_tenant(target_tenant)
    return {"tenant_id": target_tenant, "theme": theme}
