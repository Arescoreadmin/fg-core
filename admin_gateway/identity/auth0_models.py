"""Safe data transfer types for Auth0 provisioning operations.

These types carry only non-secret provisioning metadata: IDs, statuses, safe
reason codes. They must never contain tokens, secrets, or raw callback payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Auth0OrgResult:
    """Result of an Auth0 organization create or associate operation."""

    organization_id: str
    organization_name: str
    was_created: bool


@dataclass(frozen=True)
class Auth0ConnectionResult:
    """Result of attaching a connection to an Auth0 organization."""

    connection_id: str
    connection_name: str
    strategy: str
    was_attached: bool


@dataclass(frozen=True)
class Auth0ProvisioningResult:
    """Aggregated provisioning outcome for a tenant SSO or managed configuration."""

    organization_id: Optional[str]
    connection_id: Optional[str]
    status: str  # "success" | "partial" | "failed"
    error_code: Optional[str]


@dataclass(frozen=True)
class Auth0IdentityClaims:
    """Normalized, adapter-validated identity claims extracted from an Auth0 ID token.

    Contains only safe identity fields. Never contains access token, refresh
    token, authorization header, or client secret.
    """

    provider: str
    issuer: str
    subject: str
    email: str
    email_verified: bool
    organization_id: Optional[str]
    connection_id: Optional[str]
    identity_type: str = "human"
