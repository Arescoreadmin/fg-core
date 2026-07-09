"""api/identity_authority/authority.py — Unified Identity Authority.

Single entry point for all FrostGate authentication and authorization.
Nothing outside this module should perform authentication.

Authentication flow:
  1. Provider resolves token → CanonicalIdentity
  2. TenantResolver binds tenant from membership or hint
  3. Permissions are resolved from roles
  4. AuthorizationContext is assembled and returned
  5. Audit event is emitted
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Optional

from sqlalchemy.orm import Session

from api.identity_authority.audit import IdentityAuditor, IdentityEventType
from api.identity_authority.metrics import (
    AUTH_FAILED_TOTAL,
    AUTH_LATENCY,
    AUTH_SUCCESS_TOTAL,
    SESSION_CREATED_TOTAL,
)
from api.identity_authority.models import (
    AuthorizationContext,
    CanonicalIdentity,
)
from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityValidationError,
)
from api.identity_authority.providers.registry import IdentityProviderRegistry
from api.identity_authority.session_authority import SessionAuthority
from api.identity_authority.tenant_resolver import TenantResolver

log = logging.getLogger("frostgate.identity_authority.authority")


class IdentityAuthority:
    """Unified identity authority for all FrostGate authentication.

    Inject this into FastAPI routes via the integration module.
    Do not construct per-request; use the module singleton.
    """

    def __init__(
        self,
        provider_registry: IdentityProviderRegistry,
        session_authority: SessionAuthority,
        tenant_resolver: TenantResolver,
        auditor: IdentityAuditor,
    ) -> None:
        self._registry = provider_registry
        self._session = session_authority
        self._resolver = tenant_resolver
        self._auditor = auditor

    # ------------------------------------------------------------------
    # Public authentication entry points
    # ------------------------------------------------------------------

    def authenticate_jwt(
        self,
        token: str,
        *,
        tenant_id_hint: Optional[str] = None,
        correlation_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> AuthorizationContext:
        """Authenticate a Bearer JWT token.

        Raises:
            IdentityValidationError: token rejected by all providers
            IdentityProviderError: provider misconfigured or unavailable
        """
        t0 = time.monotonic()
        cid = correlation_id or secrets.token_hex(8)

        try:
            identity = self._registry.resolve_jwt(token)

            ctx = self._build_authorization_context(
                identity=identity,
                tenant_id_hint=tenant_id_hint,
                correlation_id=cid,
                db=db,
            )

            elapsed = time.monotonic() - t0
            AUTH_SUCCESS_TOTAL.labels(
                provider=identity.provider.name,
                identity_type=identity.identity_type,
            ).inc()
            AUTH_LATENCY.labels(provider=identity.provider.name).observe(elapsed)

            self._auditor.emit(
                IdentityEventType.AUTH_SUCCESS,
                subject=identity.subject,
                tenant_id=ctx.tenant_id,
                provider=identity.provider.name,
                correlation_id=cid,
                details={
                    "identity_type": identity.identity_type,
                    "mfa": identity.auth_context.mfa_verified,
                },
            )

            return ctx

        except IdentityValidationError as exc:
            AUTH_FAILED_TOTAL.labels(provider=exc.provider, reason=exc.code).inc()
            self._auditor.emit(
                IdentityEventType.AUTH_FAILED,
                provider=exc.provider,
                correlation_id=cid,
                details={"reason": exc.code},
            )
            raise
        except IdentityProviderError as exc:
            AUTH_FAILED_TOTAL.labels(
                provider=exc.provider, reason="provider_error"
            ).inc()
            self._auditor.emit(
                IdentityEventType.AUTH_PROVIDER_ERROR,
                provider=exc.provider,
                correlation_id=cid,
                details={"reason": str(exc)},
            )
            raise

    def authenticate_api_key(
        self,
        key_id: str,
        key_secret: str,
        *,
        tenant_id_hint: Optional[str] = None,
        correlation_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> AuthorizationContext:
        """Authenticate an API key credential pair.

        Delegates to MachineIdentityAuthority for key validation.
        """
        from api.identity_authority.machine_identity import get_machine_authority

        cid = correlation_id or secrets.token_hex(8)
        machine_auth = get_machine_authority()

        identity = machine_auth.authenticate_api_key(
            key_id=key_id,
            key_secret=key_secret,
            db=db,
            correlation_id=cid,
        )

        ctx = self._build_authorization_context(
            identity=identity,
            tenant_id_hint=tenant_id_hint,
            correlation_id=cid,
            db=db,
        )

        AUTH_SUCCESS_TOTAL.labels(
            provider="api_key",
            identity_type=identity.identity_type,
        ).inc()

        self._auditor.emit(
            IdentityEventType.MACHINE_AUTH_SUCCESS,
            subject=identity.subject,
            tenant_id=ctx.tenant_id,
            provider="api_key",
            correlation_id=cid,
            details={"identity_type": identity.identity_type},
        )

        return ctx

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(
        self,
        ctx: AuthorizationContext,
        *,
        device_hint: Optional[str] = None,
    ) -> str:
        """Issue a signed session token for an authenticated authorization context."""
        identity = ctx.identity
        token = self._session.create_session(
            subject=identity.subject,
            email=identity.email,
            tenant_id=ctx.tenant_id,
            identity_type=identity.identity_type,
            provider=identity.provider.name,
            mfa_verified=identity.auth_context.mfa_verified,
            device_hint=device_hint,
        )

        SESSION_CREATED_TOTAL.labels(
            provider=identity.provider.name,
            identity_type=identity.identity_type,
        ).inc()

        self._auditor.emit(
            IdentityEventType.SESSION_CREATED,
            subject=identity.subject,
            tenant_id=ctx.tenant_id,
            provider=identity.provider.name,
            correlation_id=ctx.correlation_id,
            details={
                "sid": token.session_id,
                "mfa": identity.auth_context.mfa_verified,
            },
        )

        return token.token

    def logout(
        self,
        session_id: str,
        *,
        subject: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        """Revoke a single session (logout)."""
        self._session.revoke_session(session_id)
        self._auditor.emit(
            IdentityEventType.LOGOUT,
            subject=subject,
            correlation_id=correlation_id,
            details={"sid": session_id},
        )

    def logout_all(
        self,
        subject: str,
        session_ids: list[str],
        *,
        correlation_id: Optional[str] = None,
    ) -> int:
        """Revoke all known sessions for a subject."""
        count = self._session.revoke_all_for_subject(subject, session_ids)
        self._auditor.emit(
            IdentityEventType.LOGOUT_ALL,
            subject=subject,
            correlation_id=correlation_id,
            details={"count": count},
        )
        return count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_authorization_context(
        self,
        identity: CanonicalIdentity,
        *,
        tenant_id_hint: Optional[str] = None,
        correlation_id: str,
        db: Optional[Session] = None,
    ) -> AuthorizationContext:
        """Resolve tenant, permissions, and assemble AuthorizationContext."""
        binding = identity.tenant_binding

        if db is not None:
            resolved = self._resolver.resolve(
                identity=identity,
                db=db,
                tenant_id_hint=tenant_id_hint,
            )
            if resolved is not None:
                binding = resolved

        permissions = binding.permissions if binding else frozenset()
        capabilities = (
            identity.subscription.capabilities if identity.subscription else frozenset()
        )

        if binding:
            self._auditor.emit(
                IdentityEventType.TENANT_RESOLVED,
                subject=identity.subject,
                tenant_id=binding.tenant_id,
                provider=identity.provider.name,
                correlation_id=correlation_id,
            )
        else:
            log.debug(
                "identity_authority.no_tenant_binding",
                extra={"subject_prefix": identity.subject[:16]},
            )

        return AuthorizationContext(
            identity=identity
            if binding is None
            else _identity_with_binding(identity, binding),
            permissions=permissions,
            capabilities=capabilities,
            tenant_id=binding.tenant_id if binding else None,
            organization_id=binding.organization_id if binding else None,
            session_id="",
            session_risk_score=0.0,
            correlation_id=correlation_id,
        )


def _identity_with_binding(
    identity: CanonicalIdentity,
    binding,
) -> CanonicalIdentity:
    """Return a new CanonicalIdentity with the resolved tenant_binding."""
    from dataclasses import replace

    return replace(identity, tenant_binding=binding)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_authority: Optional[IdentityAuthority] = None


def get_identity_authority() -> IdentityAuthority:
    """Return the module singleton, initializing it on first call."""
    global _authority
    if _authority is None:
        _authority = _build_authority()
    return _authority


def _build_authority() -> IdentityAuthority:
    from api.identity_authority.audit import get_identity_auditor
    from api.identity_authority.session_authority import SessionAuthority
    from api.identity_authority.tenant_resolver import TenantResolver
    from api.identity_authority.providers.registry import IdentityProviderRegistry

    return IdentityAuthority(
        provider_registry=IdentityProviderRegistry(),
        session_authority=SessionAuthority(),
        tenant_resolver=TenantResolver(),
        auditor=get_identity_auditor(),
    )
