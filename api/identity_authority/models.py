"""api/identity_authority/models.py — Canonical data models for the FrostGate Identity Authority.

All data models flowing through the unified identity system.
These are immutable (frozen=True) dataclasses to prevent accidental mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional


@dataclass(frozen=True)
class IdentityProvider:
    """Identifies which IdP authenticated this identity."""

    name: str  # "auth0" | "entra" | "google" | "okta" | "api_key" | "machine" | "agent"
    issuer: str
    subject: str


@dataclass(frozen=True)
class AuthenticationContext:
    """Authentication strength and method metadata."""

    mfa_verified: bool
    mfa_method: Optional[str]  # "totp" | "webauthn" | "sms" | None
    auth_time: datetime
    amr: list[str]  # Authentication Method References from OIDC
    acr: Optional[str]  # Authentication Context Class Reference
    pkce_used: bool
    nonce_verified: bool


@dataclass(frozen=True)
class TenantBinding:
    """FrostGate tenant membership resolved for this identity."""

    tenant_id: str
    organization_id: Optional[str]
    membership_id: Optional[str]
    roles: frozenset[str]
    permissions: frozenset[str]


@dataclass(frozen=True)
class IdentitySubscription:
    """Subscription tier and licensed features for this identity's tenant."""

    tier: str  # "free" | "starter" | "pro" | "enterprise" | "internal"
    capabilities: frozenset[str]
    licensed_features: frozenset[str]


@dataclass(frozen=True)
class CanonicalIdentity:
    """Single canonical identity flowing through all of FrostGate.

    This is the universal identity representation produced by every
    identity provider and consumed by the authorization layer.
    """

    # Core identity
    subject: str  # provider's stable subject identifier
    email: str
    name: str
    email_verified: bool
    # Provider information
    provider: IdentityProvider
    # Authentication strength
    auth_context: AuthenticationContext
    # Tenant binding (resolved from membership)
    tenant_binding: Optional[TenantBinding]
    # Subscription/licensing
    subscription: Optional[IdentitySubscription]
    # Identity type classification
    identity_type: Literal["human", "machine", "agent", "service"]
    # Timestamps
    issued_at: datetime
    expires_at: datetime

    def to_actor_context(self) -> "ActorContext":  # noqa: F821
        """Convert to ActorContext for backwards compatibility with existing routes."""
        from api.actor_context import ActorContext, roles_to_permissions

        roles = list(self.tenant_binding.roles) if self.tenant_binding else []
        permissions = (
            self.tenant_binding.permissions
            if self.tenant_binding
            else roles_to_permissions(roles)
        )

        # Map provider name to auth_source string used by legacy code
        provider_map = {
            "auth0": "oidc_auth0",
            "entra": "oidc_entra",
            "google": "oidc_google",
            "api_key": "api_key",
            "machine": "api_key",
            "agent": "api_key",
        }
        auth_source = provider_map.get(self.provider.name, f"oidc_{self.provider.name}")

        return ActorContext(
            subject=self.subject,
            email=self.email,
            name=self.name,
            permissions=permissions,
            roles=roles,
            auth_source=auth_source,
            tenant_id=self.tenant_binding.tenant_id if self.tenant_binding else None,
            membership_id=self.tenant_binding.membership_id
            if self.tenant_binding
            else None,
        )


@dataclass(frozen=True)
class AuthorizationContext:
    """Fully resolved authorization context attached to every request."""

    identity: CanonicalIdentity
    # Resolved effective permissions (from role + direct grants)
    permissions: frozenset[str]
    # Resolved capabilities (from subscription + entitlements)
    capabilities: frozenset[str]
    # Tenant context
    tenant_id: Optional[str]
    organization_id: Optional[str]
    # Session metadata
    session_id: str
    session_risk_score: float  # 0.0-1.0, always 0.0 for now
    # Request tracing
    correlation_id: str

    def has_permission(self, *perms: str) -> bool:
        """Return True if ALL listed permissions are held."""
        return all(p in self.permissions for p in perms)

    def has_capability(self, cap: str) -> bool:
        """Return True if the capability is available for this identity."""
        return cap in self.capabilities

    def is_platform_admin(self) -> bool:
        """Return True if this identity holds platform.admin."""
        return "platform.admin" in self.permissions

    def primary_role(self) -> Optional[str]:
        """Return the most privileged role held by this identity."""
        from api.actor_context import _ROLE_DISPLAY_HIERARCHY

        if self.identity.tenant_binding is None:
            return None
        roles = self.identity.tenant_binding.roles
        for r in _ROLE_DISPLAY_HIERARCHY:
            if r in roles:
                return r
        return next(iter(roles), None)

    def to_actor_context(self) -> "ActorContext":  # noqa: F821
        """Convert to ActorContext for backwards compatibility with existing routes."""
        return self.identity.to_actor_context()


@dataclass(frozen=True)
class IdentityClaims:
    """Canonical JWT claims representation."""

    sub: str
    email: str
    name: str
    email_verified: bool
    tenant_id: Optional[str]
    roles: list[str]
    permissions: list[str]
    capabilities: list[str]
    tier: str
    mfa_verified: bool
    identity_type: str
    provider: str
    iat: int
    exp: int
    jti: str  # JWT ID for replay prevention
    session_id: str
    correlation_id: str
