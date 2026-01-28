"""Authentication and Authorization for Admin Gateway.

Provides RBAC scope enforcement and tenant scoping for multi-tenant isolation.
"""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Depends, HTTPException, Request, status


# Available RBAC scopes for products
class Scopes:
    """Available RBAC scopes."""

    PRODUCT_READ = "product:read"
    PRODUCT_WRITE = "product:write"
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"
    WILDCARD = "*"


@dataclass
class AuthContext:
    """Authentication context with tenant and scope information."""

    authenticated: bool = False
    tenant_id: Optional[str] = None
    actor: Optional[str] = None
    scopes: list[str] = field(default_factory=list)
    key_prefix: Optional[str] = None
    error: Optional[str] = None

    def has_scope(self, scope: str) -> bool:
        """Check if context has the given scope."""
        if Scopes.WILDCARD in self.scopes:
            return True
        return scope in self.scopes

    def has_any_scope(self, *scopes: str) -> bool:
        """Check if context has any of the given scopes."""
        return any(self.has_scope(s) for s in scopes)

    def has_all_scopes(self, *scopes: str) -> bool:
        """Check if context has all of the given scopes."""
        return all(self.has_scope(s) for s in scopes)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _validate_tenant_id(tenant_id: str) -> tuple[bool, str]:
    """Validate tenant ID format.

    Returns (is_valid, error_message).
    """
    if not tenant_id:
        return False, "Tenant ID is required"

    if len(tenant_id) > 128:
        return False, "Tenant ID too long (max 128 chars)"

    # Only allow alphanumeric, dash, underscore
    if not re.match(r"^[a-zA-Z0-9_-]+$", tenant_id):
        return False, "Tenant ID contains invalid characters"

    return True, ""


def _extract_api_key(request: Request) -> Optional[str]:
    """Extract API key from request.

    Priority:
    1. X-API-Key header
    2. Authorization Bearer token
    3. Cookie (for UI sessions)

    Never from query parameters (security: prevents logging in proxies/referrer).
    """
    # Header (preferred)
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key

    # Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    # Cookie fallback (for UI)
    api_key = request.cookies.get("fg_api_key")
    if api_key:
        return api_key

    return None


def _extract_tenant_id(request: Request) -> Optional[str]:
    """Extract tenant ID from request.

    Priority:
    1. X-Tenant-ID header
    2. Query parameter (for convenience in dev)
    """
    tenant_id = request.headers.get("X-Tenant-ID")
    if tenant_id:
        return tenant_id

    # Query param fallback (dev only)
    if os.getenv("AG_ENV", "prod") == "dev":
        return request.query_params.get("tenant_id")

    return None


async def get_auth_context(request: Request) -> AuthContext:
    """FastAPI dependency to extract authentication context.

    This validates the API key and extracts tenant/scope information.
    """
    api_key = _extract_api_key(request)
    tenant_id = _extract_tenant_id(request)

    # Check if auth is disabled (dev mode)
    auth_enabled = os.getenv("AG_AUTH_ENABLED", "1").lower() in ("1", "true", "yes")
    if not auth_enabled:
        # Dev mode: allow all with default tenant
        return AuthContext(
            authenticated=True,
            tenant_id=tenant_id or "dev-tenant",
            actor="dev-user",
            scopes=[Scopes.WILDCARD],
        )

    # Validate API key
    if not api_key:
        return AuthContext(authenticated=False, error="API key required")

    # Check against environment key (simple mode)
    env_key = os.getenv("AG_API_KEY") or os.getenv("FG_API_KEY")
    if env_key and _constant_time_compare(api_key, env_key):
        # Environment key grants wildcard access
        return AuthContext(
            authenticated=True,
            tenant_id=tenant_id or "default",
            actor="api-key",
            scopes=[Scopes.WILDCARD],
            key_prefix=api_key[:8] if len(api_key) >= 8 else api_key,
        )

    # TODO: Add database key lookup when needed
    # For now, reject unknown keys
    return AuthContext(authenticated=False, error="Invalid API key")


def require_auth(
    request: Request, auth: AuthContext = Depends(get_auth_context)
) -> AuthContext:
    """Dependency that requires authentication."""
    if not auth.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=auth.error or "Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth


def require_scopes(*required_scopes: str):
    """Factory for scope-checking dependency.

    Usage:
        @app.get("/admin/products")
        async def list_products(auth: AuthContext = Depends(require_scopes("product:read"))):
            ...
    """

    def _check_scopes(
        request: Request, auth: AuthContext = Depends(require_auth)
    ) -> AuthContext:
        if not auth.has_any_scope(*required_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {', '.join(required_scopes)}",
            )
        return auth

    return _check_scopes


def require_tenant(
    tenant_id: str, auth: AuthContext = Depends(require_auth)
) -> AuthContext:
    """Validate tenant access.

    Ensures the authenticated user can access the specified tenant.
    """
    # Wildcard scope can access any tenant
    if auth.has_scope(Scopes.WILDCARD):
        return auth

    # Admin scope can access any tenant
    if auth.has_scope(Scopes.ADMIN_READ) or auth.has_scope(Scopes.ADMIN_WRITE):
        return auth

    # Otherwise, must match tenant
    if auth.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: tenant mismatch",
        )

    return auth


class TenantScoped:
    """Helper for tenant-scoped database queries.

    Usage:
        scoped = TenantScoped(auth)
        query = scoped.filter_query(select(Product))
    """

    def __init__(self, auth: AuthContext):
        self.auth = auth
        self.tenant_id = auth.tenant_id

    def validate_tenant_id(self, tenant_id: str) -> None:
        """Validate that the given tenant ID matches the auth context."""
        valid, error = _validate_tenant_id(tenant_id)
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error,
            )

        # Check access
        if not self.auth.has_scope(Scopes.WILDCARD):
            if self.auth.tenant_id != tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: tenant mismatch",
                )

    def get_tenant_id(self) -> str:
        """Get the tenant ID for operations."""
        if not self.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tenant ID required",
            )
        return self.tenant_id
