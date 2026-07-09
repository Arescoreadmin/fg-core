"""api/identity_authority/providers/base.py — Provider protocol and error types."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from api.identity_authority.models import CanonicalIdentity


class IdentityProviderProtocol(Protocol):
    """Protocol all identity providers must implement."""

    provider_name: str

    def is_configured(self) -> bool:
        """Return True if this provider has its required env vars set."""
        ...

    def validate_token(self, token: str) -> "CanonicalIdentity":
        """Validate a JWT token and return a CanonicalIdentity.

        Raises:
            IdentityValidationError: token is invalid, expired, or malformed
            IdentityProviderError: provider is misconfigured or unreachable
        """
        ...

    def get_jwks_uri(self) -> str:
        """Return the JWKS URI for this provider."""
        ...

    def get_issuer(self) -> str:
        """Return the expected issuer string."""
        ...


class IdentityValidationError(Exception):
    """Token is invalid, expired, or otherwise unacceptable."""

    def __init__(
        self,
        message: str,
        code: str = "INVALID_TOKEN",
        provider: str = "unknown",
    ):
        super().__init__(message)
        self.code = code
        self.provider = provider


class IdentityProviderError(Exception):
    """Provider is misconfigured or temporarily unreachable."""

    def __init__(self, message: str, provider: str = "unknown"):
        super().__init__(message)
        self.provider = provider
