"""api/identity_authority/providers/registry.py — Identity provider resolution chain.

Resolves the correct provider at startup based on configured environment variables.
Providers are tried in order on every JWT authentication request.
"""

from __future__ import annotations

import logging
from typing import Optional

from api.identity_authority.models import CanonicalIdentity
from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityProviderProtocol,
    IdentityValidationError,
)

log = logging.getLogger("frostgate.identity_authority.registry")


class IdentityProviderRegistry:
    """Resolves the correct identity provider chain at startup.

    Provider resolution order (first configured wins for JWT auth):
      1. Auth0   (FG_AUTH0_DOMAIN)
      2. Entra   (FG_ENTRA_TENANT_ID + FG_ENTRA_CLIENT_ID)
      3. Google  (FG_GOOGLE_CLIENT_ID)
      4. Generic OIDC (FG_OIDC_ISSUER + FG_OIDC_CLIENT_ID)

    API key auth is handled separately and is always available.
    """

    def __init__(self) -> None:
        self._providers: list[IdentityProviderProtocol] = []
        self._build_chain()

    def _build_chain(self) -> None:
        """Build ordered provider list from environment configuration."""
        from api.identity_authority.providers.auth0_provider import Auth0OIDCProvider
        from api.identity_authority.providers.entra_provider import EntraOIDCProvider
        from api.identity_authority.providers.google_provider import GoogleOIDCProvider
        from api.identity_authority.providers.generic_oidc_provider import GenericOIDCProvider

        candidates = [
            Auth0OIDCProvider(),
            EntraOIDCProvider(),
            GoogleOIDCProvider(),
            GenericOIDCProvider(),
        ]
        for p in candidates:
            if p.is_configured():
                self._providers.append(p)
                log.info(
                    "identity_authority.provider_registered",
                    extra={"provider": p.provider_name},
                )

        if not self._providers:
            log.warning(
                "identity_authority.no_jwt_providers_configured",
                extra={"hint": "set FG_AUTH0_DOMAIN, FG_ENTRA_TENANT_ID, or FG_OIDC_ISSUER"},
            )

    def resolve_jwt(self, token: str) -> CanonicalIdentity:
        """Try each configured JWT provider in order.

        Raises IdentityValidationError if all providers reject the token.
        Raises IdentityProviderError if the matching provider is unavailable.
        """
        if not self._providers:
            raise IdentityValidationError(
                "no JWT identity providers configured",
                code="NO_PROVIDER",
                provider="registry",
            )

        last_exc: Optional[Exception] = None
        for provider in self._providers:
            try:
                identity = provider.validate_token(token)
                log.debug(
                    "identity_authority.jwt_validated",
                    extra={"provider": provider.provider_name},
                )
                return identity
            except IdentityValidationError as exc:
                # Wrong provider or definitely invalid — try next
                log.debug(
                    "identity_authority.provider_rejected",
                    extra={"provider": provider.provider_name, "code": exc.code},
                )
                last_exc = exc
                continue
            except IdentityProviderError:
                # Provider is misconfigured or unreachable — propagate immediately
                raise

        raise IdentityValidationError(
            f"all configured providers rejected the token",
            code="ALL_PROVIDERS_REJECTED",
            provider="registry",
        ) from last_exc

    def configured_providers(self) -> list[str]:
        """Return names of all configured providers."""
        return [p.provider_name for p in self._providers]

    def get_provider(self, name: str) -> Optional[IdentityProviderProtocol]:
        """Return a specific provider by name, or None if not configured."""
        for p in self._providers:
            if p.provider_name == name:
                return p
        return None

    def __len__(self) -> int:
        return len(self._providers)
