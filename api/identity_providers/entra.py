"""Entra ID (Azure AD) identity provider — stub for future implementation.

When FG_ENTRA_TENANT_ID and FG_ENTRA_AUDIENCE are configured, this provider
validates RS256 JWTs from the Microsoft identity platform.

Not yet implemented. Wired in api.auth_dispatch when available.
"""

from __future__ import annotations

from api.actor_context import ActorContext


class EntraProvider:
    """Microsoft Entra ID OIDC provider (not yet implemented)."""

    def extract_actor(self, token: str) -> ActorContext:
        raise NotImplementedError(
            "Entra ID provider is not yet implemented. "
            "Configure FG_AUTH0_DOMAIN for Auth0-based OIDC."
        )
