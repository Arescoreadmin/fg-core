"""Tenant scoping framework.

Manages multi-tenant access control for admin operations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Set

from fastapi import HTTPException

if TYPE_CHECKING:
    from admin_gateway.auth.session import Session

# Tenant ID validation pattern: alphanumeric, dash, underscore, max 128 chars
TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")

# Default tenant for single-tenant setups
DEFAULT_TENANT = "default"


@dataclass
class TenantContext:
    """Tenant context for a request.

    Attributes:
        tenant_id: The active tenant for this request
        allowed_tenants: Set of tenants the user can access
        is_write_operation: Whether this is a write operation
    """

    tenant_id: Optional[str] = None
    allowed_tenants: Set[str] = field(default_factory=set)
    is_write_operation: bool = False

    def validate(self) -> None:
        """Validate tenant context and raise HTTPException on failure."""
        # Write operations require explicit tenant_id
        if self.is_write_operation and not self.tenant_id:
            raise HTTPException(
                status_code=400,
                detail="tenant_id is required for write operations",
            )

        # Validate tenant_id format if provided
        if self.tenant_id and not TENANT_ID_PATTERN.match(self.tenant_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tenant_id format: must be alphanumeric, dash, or underscore (max 128 chars)",
            )

        # Check access to the specified tenant
        if self.tenant_id and self.allowed_tenants:
            if self.tenant_id not in self.allowed_tenants:
                raise HTTPException(
                    status_code=403,
                    detail="Tenant access denied",
                )


def get_allowed_tenants(session: "Session") -> Set[str]:
    """Extract allowed tenants from session.

    Looks for:
    1. allowed_tenants claim from OIDC token
    2. tenant_id single value (legacy support)
    3. Falls back to DEFAULT_TENANT if none specified
    """
    allowed = set()

    # Check for allowed_tenants claim (list)
    if session.claims:
        tenants_claim = session.claims.get("allowed_tenants")
        if isinstance(tenants_claim, list):
            allowed.update(str(t) for t in tenants_claim)
        elif isinstance(tenants_claim, str):
            # Single tenant as string
            allowed.add(tenants_claim)

        # Also check for single tenant_id claim
        tenant_id = session.claims.get("tenant_id")
        if tenant_id:
            allowed.add(str(tenant_id))

    # If no tenants specified, use default
    if not allowed:
        allowed.add(DEFAULT_TENANT)

    return allowed


def validate_tenant_access(
    session: "Session",
    tenant_id: Optional[str],
    is_write: bool = False,
) -> TenantContext:
    """Validate tenant access for a request.

    Args:
        session: The authenticated session
        tenant_id: The tenant ID from the request
        is_write: Whether this is a write operation

    Returns:
        TenantContext if valid

    Raises:
        HTTPException: If validation fails
    """
    allowed = get_allowed_tenants(session)

    resolved_tenant = tenant_id
    if not resolved_tenant and not is_write and len(allowed) == 1:
        resolved_tenant = list(allowed)[0]

    ctx = TenantContext(
        tenant_id=resolved_tenant,
        allowed_tenants=allowed,
        is_write_operation=is_write,
    )

    ctx.validate()
    return ctx


def require_tenant(is_write: bool = False):
    """Decorator to require tenant context.

    Usage:
        @require_tenant(is_write=True)
        async def create_key(session: Session, tenant_id: str, ...):
            ...
    """
    from functools import wraps

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            session = kwargs.get("session")
            tenant_id = kwargs.get("tenant_id")

            if session is None:
                raise ValueError("No session found in function arguments")

            # Validate and set tenant context
            ctx = validate_tenant_access(session, tenant_id, is_write=is_write)
            kwargs["tenant_context"] = ctx

            return await func(*args, **kwargs)

        wrapper._requires_tenant = True
        wrapper._tenant_is_write = is_write
        return wrapper

    return decorator
