"""Authentication package for admin-gateway.

Provides OIDC authentication, session management, CSRF protection,
RBAC scopes, and tenant scoping for human users.
"""

from admin_gateway.auth.config import AuthConfig, get_auth_config, reset_auth_config
from admin_gateway.auth.session import SessionManager, Session
from admin_gateway.auth.scopes import Scope, has_scope, require_scope, expand_scopes
from admin_gateway.auth.tenant import TenantContext, validate_tenant_access
from admin_gateway.auth.csrf import CSRFProtection
from admin_gateway.auth.oidc import OIDCClient
from admin_gateway.auth.dev_bypass import (
    is_dev_bypass_allowed,
    get_dev_bypass_session,
    DevBypassError,
)
from admin_gateway.auth.dependencies import (
    get_current_session,
    get_optional_session,
    verify_csrf,
    require_scope_dependency,
    require_tenant_dependency,
    require_auth_with_csrf,
    require_admin,
)

__all__ = [
    # Config
    "AuthConfig",
    "get_auth_config",
    "reset_auth_config",
    # Session
    "SessionManager",
    "Session",
    # Scopes
    "Scope",
    "has_scope",
    "require_scope",
    "expand_scopes",
    # Tenant
    "TenantContext",
    "validate_tenant_access",
    # CSRF
    "CSRFProtection",
    # OIDC
    "OIDCClient",
    # Dev bypass
    "is_dev_bypass_allowed",
    "get_dev_bypass_session",
    "DevBypassError",
    # Dependencies
    "get_current_session",
    "get_optional_session",
    "verify_csrf",
    "require_scope_dependency",
    "require_tenant_dependency",
    "require_auth_with_csrf",
    "require_admin",
]
