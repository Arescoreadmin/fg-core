"""Development authentication bypass.

Provides a stub authentication for local development.
MUST NEVER be enabled in production.
"""

from __future__ import annotations

import logging
import os
from typing import Iterable, Optional, Set

from admin_gateway.auth.config import AuthConfig, get_auth_config
from admin_gateway.auth.scopes import Scope
from admin_gateway.auth.session import Session

log = logging.getLogger("admin-gateway.dev-bypass")


class DevBypassError(Exception):
    """Raised when dev bypass is used incorrectly."""

    pass


def is_dev_bypass_allowed(config: Optional[AuthConfig] = None) -> bool:
    """Check if dev bypass is allowed.

    Returns:
        True if FG_DEV_AUTH_BYPASS=true AND FG_ENV != prod
    """
    config = config or get_auth_config()
    return config.dev_bypass_allowed


def assert_not_production(config: Optional[AuthConfig] = None) -> None:
    """Assert that we are not in production.

    Raises:
        DevBypassError: If running in production environment
    """
    config = config or get_auth_config()

    if config.is_prod:
        log.critical("SECURITY: Attempted to use dev bypass in production!")
        raise DevBypassError(
            "Dev auth bypass is NOT allowed in production. "
            "Set FG_ENV to a non-production value or disable FG_DEV_AUTH_BYPASS."
        )


def create_dev_session(
    user_id: str = "dev-user",
    email: str = "dev@localhost",
    name: str = "Development User",
    scopes: Optional[Set[str]] = None,
    tenant_id: str = "default",
    allowed_tenants: Optional[Iterable[str]] = None,
    config: Optional[AuthConfig] = None,
) -> Session:
    """Create a development session with full admin access.

    This function is for LOCAL DEVELOPMENT ONLY.

    Args:
        user_id: Development user ID
        email: Development user email
        name: Development user display name
        scopes: Scopes to grant (defaults to console:admin)
        tenant_id: Default tenant
        config: Auth configuration

    Returns:
        Session with development credentials

    Raises:
        DevBypassError: If running in production
    """
    config = config or get_auth_config()

    # CRITICAL: Always check production status
    assert_not_production(config)

    if not config.dev_bypass_allowed:
        raise DevBypassError(
            "Dev auth bypass is disabled. Set FG_DEV_AUTH_BYPASS=true in development."
        )

    # Default to full admin access for dev
    if scopes is None:
        scopes = {Scope.CONSOLE_ADMIN.value}

    allowed = list(allowed_tenants) if allowed_tenants else [tenant_id]

    log.warning(
        "DEV BYPASS: Creating development session for user=%s with scopes=%s",
        user_id,
        scopes,
    )

    return Session(
        user_id=user_id,
        email=email,
        name=name,
        scopes=scopes,
        claims={
            "sub": user_id,
            "email": email,
            "name": name,
            "dev_bypass": True,
            "tenant_id": tenant_id,
            "allowed_tenants": allowed,
        },
        tenant_id=tenant_id,
    )


def get_dev_bypass_session(config: Optional[AuthConfig] = None) -> Optional[Session]:
    """Get a dev bypass session if bypass is enabled.

    This is the main entry point for dev bypass authentication.

    Returns:
        Session if dev bypass is enabled, None otherwise

    Raises:
        DevBypassError: If attempted in production
    """
    config = config or get_auth_config()

    # Not in prod + bypass enabled = create dev session
    if config.dev_bypass_allowed:
        tenants = _parse_csv_env("FG_DEV_AUTH_TENANTS")
        tenant_id = os.getenv("FG_DEV_AUTH_TENANT_ID") or (
            tenants[0] if tenants else "default"
        )
        scopes = _parse_csv_env("FG_DEV_AUTH_SCOPES")
        return create_dev_session(
            user_id=os.getenv("FG_DEV_AUTH_USER_ID", "dev-user"),
            email=os.getenv("FG_DEV_AUTH_EMAIL", "dev@localhost"),
            name=os.getenv("FG_DEV_AUTH_NAME", "Development User"),
            scopes=set(scopes) if scopes else None,
            tenant_id=tenant_id,
            allowed_tenants=tenants or None,
            config=config,
        )

    return None


def _parse_csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]
