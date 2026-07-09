"""Entra ID (Azure AD) identity provider — delegates to FIAP EntraOIDCProvider.

This module is preserved for backwards import compatibility.
Authentication is now handled by api.identity_authority.providers.entra_provider.
"""

from __future__ import annotations

from api.actor_context import ActorContext


class EntraProvider:
    """Microsoft Entra ID OIDC provider — delegates to FIAP."""

    def extract_actor(self, token: str) -> ActorContext:
        from api.identity_authority.providers.entra_provider import EntraOIDCProvider

        provider = EntraOIDCProvider()
        if not provider.is_configured():
            raise RuntimeError(
                "Entra ID provider is not configured. "
                "Set FG_ENTRA_TENANT_ID and FG_ENTRA_CLIENT_ID."
            )
        identity = provider.validate_token(token)
        return identity.to_actor_context()
