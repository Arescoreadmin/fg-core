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
        """Resolve tenant, permissions, and assemble AuthorizationContext.

        Canonical delegation invariant (P1-01-PR2):
            For OIDC/human identities (auth0, entra, google, generic_oidc)
            the JWT-derived ``tenant_binding`` is TRUSTED FOR IDENTITY ONLY.
            Authoritative tenant + roles + permissions MUST come from the
            canonical FrostGate ``tenant_users`` membership row resolved
            through :class:`TenantResolver`.  If no canonical membership
            binding is produced, the returned :class:`AuthorizationContext`
            has ``permissions=frozenset()`` and ``tenant_id=None`` — the
            authenticated subject is preserved but no delegated authority
            flows.

        Machine / service identities (api_key, machine, agent) continue
        to use ``TenantResolver`` — API-key credentials are validated by
        the canonical credential-authority before this method runs, so
        their tenant binding is already canonical.

        Fail-closed conditions:
            - ``db is None`` for an OIDC/human identity → no authority.
            - :meth:`TenantResolver.resolve` returns ``None`` for an
              OIDC/human identity → no authority (JWT-declared roles or
              tenant_id in the token do NOT confer authority).
            - Cross-tenant hint mismatch → no authority (already enforced
              inside :class:`TenantResolver`).
        """
        is_oidc_human = identity.identity_type == "human"

        resolved_binding = None
        if db is not None:
            resolved_binding = self._resolver.resolve(
                identity=identity,
                db=db,
                tenant_id_hint=tenant_id_hint,
            )

        # Canonical delegation gate: OIDC/human identities NEVER inherit
        # authority from JWT claims — only from canonical resolver output.
        # A JWT with roles=["platform_admin"] and no membership row must
        # produce zero permissions.
        if is_oidc_human:
            binding = resolved_binding  # may be None → unbound / no authority
        else:
            # Machine identities: canonical credential-authority has already
            # validated the tenant binding on ``identity.tenant_binding``;
            # keep the resolver output when present, otherwise fall back to
            # that pre-validated binding.
            binding = resolved_binding or identity.tenant_binding

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
            if is_oidc_human and identity.tenant_binding is not None:
                # JWT carried a tenant_binding but no canonical membership
                # exists — refuse to promote the JWT claim to authority.
                log.warning(
                    "identity_authority.jwt_binding_rejected_no_membership",
                    extra={
                        "subject_prefix": identity.subject[:16],
                        "provider": identity.provider.name,
                        "jwt_declared_tenant": identity.tenant_binding.tenant_id,
                        "jwt_declared_roles": sorted(identity.tenant_binding.roles),
                    },
                )
            else:
                log.debug(
                    "identity_authority.no_tenant_binding",
                    extra={"subject_prefix": identity.subject[:16]},
                )

        # Scrub JWT-derived binding off the identity when no canonical
        # binding was produced, so downstream consumers of
        # ``AuthorizationContext.identity.tenant_binding`` cannot re-derive
        # permissions from JWT claims.
        if binding is None and identity.tenant_binding is not None:
            identity = _identity_with_binding(identity, None)
        elif binding is not None and binding is not identity.tenant_binding:
            identity = _identity_with_binding(identity, binding)

        return AuthorizationContext(
            identity=identity,
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
    """Return a new CanonicalIdentity with the resolved tenant_binding.

    Passing ``binding=None`` scrubs any JWT-derived binding off the identity;
    this is required by the P1-01-PR2 canonical-delegation invariant so
    downstream consumers cannot re-derive authority from JWT claims when
    no canonical membership row exists.
    """
    from dataclasses import replace

    return replace(identity, tenant_binding=binding)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_authority: Optional[IdentityAuthority] = None


def is_session_revoked(session_id: str) -> bool:
    """Check the live revocation store for *session_id*.

    Delegates to the singleton's ``SessionAuthority`` so the caller never
    touches the private ``_session`` attribute directly. Returns ``False``
    on any error so callers stay safe.
    """
    if not session_id:
        return False
    try:
        return get_identity_authority()._session.is_revoked(session_id)
    except Exception:
        return False


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
