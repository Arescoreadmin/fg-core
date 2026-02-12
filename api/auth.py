# api/auth.py
"""
Authentication module - thin adapter over auth_scopes.

This module provides FastAPI dependencies that delegate all auth logic
to auth_scopes.verify_api_key_detailed(), which is the SINGLE SOURCE OF TRUTH.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
import api.auth_scopes as auth_scopes

try:
    from tools.tenants.registry import get_tenant as _registry_get_tenant
except Exception:  # pragma: no cover
    _registry_get_tenant = None


def get_tenant(tenant_id: str):
    if _registry_get_tenant is None:
        return None
    return _registry_get_tenant(tenant_id)


API_KEY_HEADER = APIKeyHeader(name="x-api-key", auto_error=False)


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def auth_enabled() -> bool:
    if os.getenv("FG_AUTH_ENABLED") is not None:
        return _env_bool("FG_AUTH_ENABLED", default=False)
    return bool(os.getenv("FG_API_KEY"))


async def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Depends(API_KEY_HEADER),
) -> None:
    """
    FastAPI dependency that verifies API keys.

    Delegates ALL verification logic to auth_scopes.verify_api_key_detailed()
    to ensure a single source of truth.

    Status codes:
      - 401: Missing key
      - 403: Invalid key (wrong, expired, disabled, etc.)
    """
    if not auth_enabled():
        return

    # Use auth_scopes._extract_key for consistent key extraction
    raw = auth_scopes._extract_key(request, x_api_key)

    # Delegate to single source of truth
    result = auth_scopes.verify_api_key_detailed(
        raw=raw, required_scopes=None, request=request
    )

    if result.valid:
        request.state.auth = result
        return

    # Proper status codes: 401 for missing/invalid
    if result.is_missing_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key"
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
    )


def require_status_auth(
    _: Request,
    __: None = Depends(verify_api_key),
) -> None:
    return
