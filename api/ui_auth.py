from __future__ import annotations

import os
from typing import Optional

from fastapi import Header, HTTPException, Request

from api.auth_scopes import ERR_INVALID, verify_api_key_detailed


def _extract_ui_key(request: Request, x_api_key: Optional[str]) -> Optional[str]:
    if x_api_key and str(x_api_key).strip():
        return str(x_api_key).strip()
    cookie_name = (
        os.getenv("FG_UI_COOKIE_NAME") or "fg_api_key"
    ).strip() or "fg_api_key"
    cookie_value = (request.cookies.get(cookie_name) or "").strip()
    if cookie_value:
        return cookie_value
    return None


def resolve_ui_principal(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    raw_key = _extract_ui_key(request, x_api_key)
    if not raw_key:
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    result = verify_api_key_detailed(raw=raw_key, request=request)
    if not result.valid:
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    request.state.auth = result
    return str(result.key_prefix or "")
