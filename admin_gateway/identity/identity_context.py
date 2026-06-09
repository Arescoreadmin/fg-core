"""Provider-neutral validated identity and tenant-session context."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticatedIdentity:
    provider: str
    issuer: str
    subject: str
    email: str
    email_verified: bool
    connection_id: str | None = None
    organization_id: str | None = None
    identity_type: str = "human"
    correlation_id: str | None = None


@dataclass(frozen=True)
class TenantSessionContext:
    tenant_id: str
    membership_id: str
    user_id: str
    email: str
    identity_provider: str
    identity_issuer: str
    identity_subject: str
    identity_type: str
    role: str
    scopes: frozenset[str]
    binding_status: str
