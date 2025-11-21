# api/auth.py
from __future__ import annotations

from fastapi import Header, HTTPException, status
from loguru import logger

from .config import settings

# Tenant registry is optional at import time so unit tests / tools still work
try:
    from tools.tenants.registry import get_tenant  # type: ignore
except Exception:  # pragma: no cover - defensive fallback
    get_tenant = None


class AuthError(HTTPException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        )


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias="x-api-key"),
    x_tenant_id: str | None = Header(default=None, alias="x-tenant-id"),
) -> None:
    """
    API auth layer with two paths:

    1) Global operator key (legacy / CI contract):
         - FG_API_KEY env var
         - Header: x-api-key: <FG_API_KEY>

    2) Per-tenant key from registry (tenant onboarding flow):
         - Header: x-tenant-id: <tenant_id>
         - Header: x-api-key: <tenant_api_key>

    If FG_API_KEY is unset:
      - Only tenant-based auth works (if registry is present).
    If both are present:
      - Either a matching global key OR a matching tenant key passes.

    Return value is ignored by endpoints; this is a gate only.
    """

    # If auth is globally disabled (FG_API_KEY unset *and* no registry),
    # let traffic through. This keeps local dev simple.
    if not settings.api_key and get_tenant is None:
        return

    # Fast path: global operator key (what your tests and CI expect)
    if settings.api_key:
        if x_api_key == settings.api_key:
            return

    # Tenant-based auth (only if registry is available and tenant id is present)
    if get_tenant is not None and x_tenant_id and x_api_key:
        try:
            tenant = get_tenant(x_tenant_id)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error(
                "tenant_registry_error",
                extra={"tenant_id": x_tenant_id, "error": str(exc)},
            )
            raise AuthError("Tenant registry unavailable")

        if tenant is not None:
            status_val = getattr(tenant, "status", "active")
            api_key_val = getattr(tenant, "api_key", None)

            if status_val == "active" and api_key_val and api_key_val == x_api_key:
                # Auth ok for this tenant
                return

    # If we got here, no valid key was found
    raise AuthError("Invalid or missing API key")
