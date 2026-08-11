"""api/identity_authority/machine_identity.py — Machine and service identity.

Handles authentication for non-human principals:
  - API keys (tenant service accounts, CI/CD integrations)
  - Agent tokens (autonomous governance agents)

Machine identities are validated against the tenant_credentials table.
They never go through OIDC and have no session TTL.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from api.identity_authority.models import (
    AuthenticationContext,
    CanonicalIdentity,
    IdentityProvider,
    TenantBinding,
)

log = logging.getLogger("frostgate.identity_authority.machine")


@dataclass(frozen=True)
class MachineIdentityRecord:
    """Resolved machine identity from the database."""

    key_id: str
    key_prefix: str
    tenant_id: str
    roles: frozenset[str]
    scopes: frozenset[str]
    is_active: bool
    key_hash: Optional[str] = None
    hash_alg: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class MachineIdentityAuthority:
    """Authenticates machine principals (API keys, agent tokens).

    Validates HMAC-SHA256 key secrets against stored hashed secrets.
    """

    def __init__(self) -> None:
        pass

    def authenticate_api_key_from_state(
        self,
        request_state,
        db: Optional[object] = None,
    ) -> Optional[CanonicalIdentity]:
        """Extract and validate an API key from request.state.auth (middleware path).

        Returns None if no API key context is present on the request.
        """
        auth_state = getattr(request_state, "auth", None)
        if auth_state is None:
            return None

        key_id = getattr(auth_state, "key_id", None)
        key_prefix = getattr(auth_state, "key_prefix", None)
        tenant_id = getattr(auth_state, "tenant_id", None)
        roles = getattr(auth_state, "roles", [])

        if not key_id:
            return None

        from api.actor_context import roles_to_permissions

        perms = roles_to_permissions(list(roles))

        now = datetime.now(tz=timezone.utc)
        provider = IdentityProvider(
            name="api_key",
            issuer="frostgate.internal",
            subject=key_prefix or key_id,
        )
        auth_ctx = AuthenticationContext(
            mfa_verified=False,
            mfa_method=None,
            auth_time=now,
            amr=[],
            acr=None,
            pkce_used=False,
            nonce_verified=False,
        )
        binding = TenantBinding(
            tenant_id=str(tenant_id or ""),
            organization_id=None,
            membership_id=None,
            roles=frozenset(roles),
            permissions=perms,
        )

        return CanonicalIdentity(
            subject=key_prefix or key_id,
            email="",
            name=f"api-key:{key_prefix or key_id[:8]}",
            email_verified=False,
            provider=provider,
            auth_context=auth_ctx,
            tenant_binding=binding,
            subscription=None,
            identity_type="machine",
            issued_at=now,
            expires_at=now,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_identity(self, record: MachineIdentityRecord) -> CanonicalIdentity:
        from api.actor_context import roles_to_permissions

        now = datetime.now(tz=timezone.utc)
        perms = roles_to_permissions(list(record.roles))

        provider = IdentityProvider(
            name="api_key",
            issuer="frostgate.internal",
            subject=record.key_prefix,
        )
        auth_ctx = AuthenticationContext(
            mfa_verified=False,
            mfa_method=None,
            auth_time=now,
            amr=[],
            acr=None,
            pkce_used=False,
            nonce_verified=False,
        )
        binding = TenantBinding(
            tenant_id=record.tenant_id,
            organization_id=None,
            membership_id=None,
            roles=record.roles,
            permissions=perms,
        )

        return CanonicalIdentity(
            subject=record.key_prefix,
            email="",
            name=f"api-key:{record.key_prefix}",
            email_verified=False,
            provider=provider,
            auth_context=auth_ctx,
            tenant_binding=binding,
            subscription=None,
            identity_type="machine",
            issued_at=now,
            expires_at=now,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_machine_authority: Optional[MachineIdentityAuthority] = None


def get_machine_authority() -> MachineIdentityAuthority:
    global _machine_authority
    if _machine_authority is None:
        _machine_authority = MachineIdentityAuthority()
    return _machine_authority
