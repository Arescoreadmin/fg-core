"""api/identity_authority/management/base.py — Management provider protocol and error types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class OrganizationRecord:
    provider_org_id: str
    provider_org_name: str
    provider: str


class ManagementProviderProtocol(Protocol):
    """Provider-agnostic interface for organization management operations.

    All provider-specific operations are encapsulated here per ADR-IA-001.
    Replacing Auth0 with another provider requires only a new implementation
    of this protocol — no changes to Console workflows or business logic.
    """

    provider_name: str

    def is_configured(self) -> bool:
        """Return True if required env vars are present."""
        ...

    def create_organization(
        self,
        *,
        name: str,
        display_name: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> OrganizationRecord:
        """Create an organization.

        Idempotent: if an organization already exists with this name,
        return the existing record rather than raising.

        Raises:
            RetryableProviderError: transient failure (rate limit, 5xx, timeout)
            ManagementProviderError: non-retryable failure (misconfiguration)
        """
        ...

    def get_organization(self, *, provider_org_id: str) -> OrganizationRecord | None:
        """Fetch an organization by provider ID. Returns None if not found."""
        ...


class ManagementProviderError(Exception):
    """Non-retryable provider failure (misconfiguration, auth failure)."""

    def __init__(self, message: str, code: str, provider: str = "unknown"):
        super().__init__(message)
        self.code = code
        self.provider = provider


class RetryableProviderError(Exception):
    """Transient provider failure — caller should retry with backoff."""

    def __init__(
        self,
        message: str,
        code: str,
        provider: str = "unknown",
        retry_after: int | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.provider = provider
        self.retry_after = retry_after
