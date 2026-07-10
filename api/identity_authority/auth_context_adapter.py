"""api/identity_authority/auth_context_adapter.py — FIAP → ActorContext adapter.

When ``FG_IDENTITY_AUTHORITY_ENABLED=1`` the FIAP path emits an
:class:`AuthorizationContext`; the rest of the request path expects an
:class:`ActorContext`. This module provides a single deterministic conversion
so that the switch to FIAP is transparent to downstream code.

Rules:
    - ``subject``, ``email``, ``name`` come from the CanonicalIdentity.
    - ``permissions`` come from the resolved authorization set (already
      merged from roles + capabilities in the FIAP path).
    - ``roles`` come from the tenant binding (empty tuple if unbound).
    - ``tenant_id`` and ``membership_id`` come from the resolved tenant
      binding.
    - The ``auth_source`` is mapped from the provider name using the same
      table used by :meth:`CanonicalIdentity.to_actor_context`, so both
      paths produce identical values.
"""

from __future__ import annotations

from typing import Optional

from api.actor_context import ActorContext
from api.identity_authority.models import AuthorizationContext

# Provider name → legacy auth_source string. Kept in sync with
# ``CanonicalIdentity.to_actor_context``.
_PROVIDER_MAP: dict[str, str] = {
    "auth0": "oidc_auth0",
    "entra": "oidc_entra",
    "google": "oidc_google",
    "api_key": "api_key",
    "machine": "api_key",
    "agent": "api_key",
}


def authorization_context_to_actor_context(
    auth_ctx: AuthorizationContext,
    tenant_id: Optional[str] = None,
) -> ActorContext:
    """Convert an AuthorizationContext to an ActorContext.

    ``tenant_id`` is an explicit override — when provided (non-empty) it
    replaces the tenant_id from the auth context. This supports contexts
    where the tenant is resolved after the FIAP authenticate call (rare;
    normally the auth context has already resolved it).
    """
    identity = auth_ctx.identity
    binding = identity.tenant_binding

    resolved_tenant = tenant_id or auth_ctx.tenant_id
    resolved_membership = binding.membership_id if binding else None
    roles = list(binding.roles) if binding else []

    provider_name = identity.provider.name
    auth_source = _PROVIDER_MAP.get(provider_name, f"oidc_{provider_name}")

    return ActorContext(
        subject=identity.subject,
        email=identity.email or "",
        name=identity.name or "",
        permissions=auth_ctx.permissions,
        roles=roles,
        auth_source=auth_source,
        tenant_id=resolved_tenant,
        membership_id=resolved_membership,
    )


__all__ = [
    "authorization_context_to_actor_context",
]
