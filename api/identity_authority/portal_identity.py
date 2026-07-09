"""api/identity_authority/portal_identity.py — Portal identity bridge.

Replaces the portal's shared-secret (PORTAL_PASSWORD) authentication model
with per-user identity backed by the unified IdentityAuthority.

The portal currently authenticates all users with a single shared password
(PORTAL_PASSWORD env var). This module provides a migration bridge:

  1. Validate the portal session (legacy or new unified format)
  2. Resolve the CanonicalIdentity from the session
  3. Return an AuthorizationContext with proper per-user tenant binding

Portal-specific context enrichment:
  - engagement_id from URL or request state
  - portal_role from invitation record (assessor, viewer, evidence_submitter)
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from sqlalchemy.orm import Session

from api.identity_authority.audit import get_identity_auditor
from api.identity_authority.models import (
    AuthenticationContext,
    AuthorizationContext,
    CanonicalIdentity,
    IdentityProvider,
    TenantBinding,
)

log = logging.getLogger("frostgate.identity_authority.portal")

_PORTAL_PASSWORD = os.getenv("PORTAL_PASSWORD", "")


class PortalIdentityBridge:
    """Bridges the portal shared-secret model to per-user identity.

    Usage:
        bridge = PortalIdentityBridge()
        ctx = bridge.validate_portal_session(session_token, db=db)
        # ctx is an AuthorizationContext with correct per-user permissions
    """

    def __init__(self) -> None:
        self._auditor = get_identity_auditor()

    def validate_portal_session(
        self,
        session_token: str,
        *,
        db: Optional[Session] = None,
        correlation_id: Optional[str] = None,
    ) -> Optional[AuthorizationContext]:
        """Validate a portal session token.

        Tries unified session format first, then legacy HMAC format.
        Returns None if the token is not a portal session.
        Raises ValueError if the token is recognisable but invalid/expired.
        """
        from api.identity_authority.session_authority import (
            SessionExpiredError,
            SessionInvalidError,
            SessionRevokedError,
        )
        from api.identity_authority.authority import get_identity_authority

        authority = get_identity_authority()

        # Try unified session format first
        try:
            session_ctx = authority._session.validate_session(session_token)
            # Only handle portal sessions (not console admin sessions)
            if session_ctx.identity_type not in ("human", "machine"):
                return None
            return self._build_from_session_context(
                session_ctx, db=db, correlation_id=correlation_id
            )
        except (SessionInvalidError, ValueError):
            pass  # Not a unified session — try legacy
        except (SessionExpiredError, SessionRevokedError) as exc:
            raise ValueError(str(exc)) from exc

        # Try legacy portal HMAC format
        if _PORTAL_PASSWORD:
            from api.identity_authority.migration import (
                get_legacy_migrator,
                LegacyMigrationError,
            )

            try:
                migrator = get_legacy_migrator()
                payload = migrator.migrate(session_token, correlation_id=correlation_id)
                return self._build_from_legacy_payload(
                    payload, db=db, correlation_id=correlation_id
                )
            except LegacyMigrationError:
                pass  # Not a legacy token either
            except ValueError:
                raise  # Expired / invalid legacy token

        return None

    def validate_shared_secret(self, password: str) -> bool:
        """Validate the legacy portal shared password.

        This is the current (pre-FIAP) authentication model.
        Returns True if the password matches PORTAL_PASSWORD.

        DEPRECATED: Portal should migrate to per-user OIDC sessions.
        """
        if not _PORTAL_PASSWORD:
            return False
        import hmac as _hmac

        return _hmac.compare_digest(_PORTAL_PASSWORD.encode(), password.encode())

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_from_session_context(
        self,
        session_ctx,
        *,
        db: Optional[Session],
        correlation_id: Optional[str],
    ) -> AuthorizationContext:
        from api.actor_context import roles_to_permissions
        import secrets

        roles = ["viewer"]
        if db is not None and session_ctx.tenant_id:
            roles = self._lookup_portal_roles(
                session_ctx.subject, session_ctx.tenant_id, db
            )

        perms = roles_to_permissions(roles)
        provider = IdentityProvider(
            name="portal_session",
            issuer="frostgate.portal",
            subject=session_ctx.subject,
        )
        auth_ctx = AuthenticationContext(
            mfa_verified=session_ctx.mfa_verified,
            mfa_method=None,
            auth_time=session_ctx.issued_at,
            amr=[],
            acr=None,
            pkce_used=False,
            nonce_verified=False,
        )
        binding = (
            TenantBinding(
                tenant_id=session_ctx.tenant_id or "",
                organization_id=None,
                membership_id=None,
                roles=frozenset(roles),
                permissions=perms,
            )
            if session_ctx.tenant_id
            else None
        )

        identity = CanonicalIdentity(
            subject=session_ctx.subject,
            email=session_ctx.email,
            name=session_ctx.email,
            email_verified=False,
            provider=provider,
            auth_context=auth_ctx,
            tenant_binding=binding,
            subscription=None,
            identity_type="human",
            issued_at=session_ctx.issued_at,
            expires_at=session_ctx.expires_at,
        )

        return AuthorizationContext(
            identity=identity,
            permissions=perms,
            capabilities=frozenset(),
            tenant_id=session_ctx.tenant_id,
            organization_id=None,
            session_id=session_ctx.session_id,
            session_risk_score=0.0,
            correlation_id=correlation_id or secrets.token_hex(8),
        )

    def _build_from_legacy_payload(
        self,
        payload,
        *,
        db: Optional[Session],
        correlation_id: Optional[str],
    ) -> AuthorizationContext:
        from api.identity_authority.migration import get_legacy_migrator
        import secrets

        migrator = get_legacy_migrator()
        identity = migrator.build_identity_from_legacy(payload)
        binding = identity.tenant_binding
        perms = binding.permissions if binding else frozenset()

        return AuthorizationContext(
            identity=identity,
            permissions=perms,
            capabilities=frozenset(),
            tenant_id=payload.tenant_id,
            organization_id=None,
            session_id=payload.session_id or "",
            session_risk_score=0.0,
            correlation_id=correlation_id or secrets.token_hex(8),
        )

    def _lookup_portal_roles(
        self, subject: str, tenant_id: str, db: Session
    ) -> list[str]:
        """Look up portal roles from the engagement invitation record."""
        try:
            from admin_gateway.identity.models import TenantUser

            member = (
                db.query(TenantUser)
                .filter(
                    TenantUser.identity_subject == subject,
                    TenantUser.tenant_id == tenant_id,
                    TenantUser.active.is_(True),
                )
                .first()
            )
            if member is None:
                return ["viewer"]
            role = getattr(member, "role", None) or "viewer"
            return [role]
        except Exception:
            return ["viewer"]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_bridge: Optional[PortalIdentityBridge] = None


def get_portal_bridge() -> PortalIdentityBridge:
    global _bridge
    if _bridge is None:
        _bridge = PortalIdentityBridge()
    return _bridge
