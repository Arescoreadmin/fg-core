"""api/identity_authority/providers/registry.py — Identity provider resolution chain.

Resolves the correct provider at startup based on configured environment variables.
Providers are tried in order on every JWT authentication request.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Optional
from urllib.parse import urlparse

from api.identity_authority.models import CanonicalIdentity
from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityProviderProtocol,
    IdentityValidationError,
)

log = logging.getLogger("frostgate.identity_authority.registry")


def _peek_issuer(token: str) -> Optional[str]:
    """Extract the iss claim from a JWT without verifying the signature."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        padding = 4 - (len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        return json.loads(raw).get("iss")
    except Exception:
        return None


def _host(url: Optional[str]) -> Optional[str]:
    """Return the lowercase hostname from a URL, or None."""
    if not url:
        return None
    try:
        return urlparse(url).netloc.lower() or None
    except Exception:
        return None


def _token_matches_provider(token: str, provider: IdentityProviderProtocol) -> bool:
    """Return True if the token's iss hostname matches this provider's issuer hostname.

    Used to decide whether an IdentityProviderError from this provider should
    propagate (the token is for this provider and it's unavailable) or be skipped
    (the token belongs to a different provider; the error is irrelevant).
    """
    token_host = _host(_peek_issuer(token))
    provider_host = _host(provider.get_issuer())
    if not token_host or not provider_host:
        return True  # cannot determine; default to stop-on-error (safe)
    return token_host == provider_host


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
            except IdentityProviderError as exc:
                if _token_matches_provider(token, provider):
                    # Token's issuer matches this provider — it's unavailable for its
                    # own tokens. Propagate immediately; trying other providers won't help.
                    raise
                # Token's issuer doesn't match this provider (e.g., Auth0 JWKS down
                # while validating an Entra token). Log and continue to next provider.
                log.warning(
                    "identity_authority.provider_error_skipped",
                    extra={"provider": provider.provider_name, "reason": str(exc)},
                )
                last_exc = exc
                continue

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
