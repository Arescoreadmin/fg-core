from __future__ import annotations

import os
from typing import Callable, Optional, Set

from fastapi import Depends, Header, HTTPException, Request

ERR_INVALID = "Invalid or missing API key"
UI_COOKIE_NAME = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _auth_enabled() -> bool:
    # Explicit flag wins. Else: presence of FG_API_KEY implies auth enabled.
    if os.getenv("FG_AUTH_ENABLED") is not None:
        return _env_bool("FG_AUTH_ENABLED", default=False)
    return bool(os.getenv("FG_API_KEY"))


def _expected_global_key() -> str:
    return os.getenv("FG_API_KEY") or "supersecret"


def _clean(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    vv = str(v).strip()
    return vv if vv else None


def _extract_key(req: Request, header_value: Optional[str] = None) -> Optional[str]:
    # 1) Explicit Header injection (fast + clean)
    k = _clean(header_value)
    if k:
        return k

    # 2) Raw headers (case-insensitive in Starlette, but be explicit anyway)
    k = _clean(req.headers.get("x-api-key")) or _clean(req.headers.get("X-API-Key"))
    if k:
        return k

    # 3) Cookie (UI flow)
    k = _clean(req.cookies.get(UI_COOKIE_NAME))
    if k:
        return k

    # 4) Query params (dev convenience)
    qp = req.query_params
    k = _clean(qp.get("api_key")) or _clean(qp.get("key"))
    if k:
        return k

    return None


def require_api_key_always(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """
    Enforce API key when auth is enabled.
    Accepts:
      - Header: X-API-Key
      - Cookie: FG_UI_COOKIE_NAME (default fg_api_key)
      - Query: api_key / key (dev convenience)
    """
    if not _auth_enabled():
        return "auth_disabled"

    got = _extract_key(request, x_api_key)
    if not got:
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    if str(got) != str(_expected_global_key()):
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    return str(got)


def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    # Back-compat name used in other modules (e.g. api/decisions.py)
    return require_api_key_always(request, x_api_key)


def require_scopes(*scopes: str) -> Callable[..., None]:
    """
    Scope enforcement stub.
    Right now: key must be valid (when auth is enabled). Scopes are accepted.
    Later: plug into tenant registry / RBAC / token scope sets.
    """
    needed: Set[str] = {s.strip() for s in scopes if str(s).strip()}

    def _dep(_: str = Depends(require_api_key_always)) -> None:
        # Placeholder: all scopes allowed once authenticated.
        # Keep `needed` to make future implementation trivial.
        _ = needed
        return None

    return _dep
