"""api/identity_authority — FrostGate Identity Authority Platform (FIAP).

Single canonical identity authority for all FrostGate authentication.

Public API:
  - get_identity_authority() → IdentityAuthority
  - get_authorization_context  (FastAPI dependency)
  - require_permission_v2      (FastAPI dependency factory)
  - get_actor_context_compat   (backwards compat FastAPI dependency)
"""

from api.identity_authority.authority import IdentityAuthority, get_identity_authority
from api.identity_authority.integration import (
    get_actor_context_compat,
    get_authorization_context,
    require_permission_v2,
)
from api.identity_authority.models import (
    AuthorizationContext,
    CanonicalIdentity,
    TenantBinding,
)
from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityValidationError,
)

__all__ = [
    "IdentityAuthority",
    "get_identity_authority",
    "get_authorization_context",
    "require_permission_v2",
    "get_actor_context_compat",
    "AuthorizationContext",
    "CanonicalIdentity",
    "TenantBinding",
    "IdentityValidationError",
    "IdentityProviderError",
]
