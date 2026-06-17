"""services/identity_resolver/service.py — Canonical membership lookup.

Maps the identity triple (provider, issuer, subject) → IdentityPrincipal by
querying tenant_users. Used by:

  - Admin Gateway: determines whether an OIDC login earns a tenant_governed session.
  - Core API auth_dispatch: binds membership_id into ActorContext for human attribution.
  - Portal identity login: verifies membership before issuing a portal user session.

Uses raw SQL via SQLAlchemy text() so it is decoupled from both the admin_gateway
IdentityBase and the api DeclarativeBase — any Session connected to the shared DB works.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger("frostgate.identity_resolver")

_BOUND_STATUS = "bound"


class IdentityResolutionError(Exception):
    """Raised by resolve_or_deny() when membership is absent or blocked."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class IdentityPrincipal:
    """Resolved tenant membership for a verified OIDC identity triple.

    Fields:
        tenant_id    — FrostGate tenant the membership belongs to
        membership_id — tenant_users.id (stable, non-repudiable)
        subject      — OIDC sub claim (provider-scoped)
        issuer       — OIDC iss claim (provider URL)
        provider     — "auth0" | "entra" | custom (from tenant_identity_configs)
        email        — verified email at time of binding
        display_name — human-readable name (falls back to email)
        roles        — placeholder list; RBAC layer reads this in future
        status       — "active" | "inactive" (reflects tenant_users.active)
        trust_level  — "bound" | "pending" | "unbound" (identity_binding_status)
    """

    tenant_id: str
    membership_id: str
    subject: str
    issuer: str
    provider: str
    email: str
    display_name: str
    roles: list[str] = field(default_factory=list)
    status: str = "active"
    trust_level: str = "bound"
    membership_version: int = 1


_RESOLVE_SQL = text(
    """
    SELECT
        id,
        tenant_id,
        email,
        role,
        active,
        identity_type,
        identity_provider,
        identity_issuer,
        identity_subject,
        identity_email,
        identity_binding_status,
        membership_version
    FROM tenant_users
    WHERE identity_binding_status = :binding_status
      AND identity_provider       = :provider
      AND identity_issuer         = :issuer
      AND identity_subject        = :subject
      AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
    LIMIT 1
    """
)


class IdentityResolver:
    """Resolves (provider, issuer, subject) → IdentityPrincipal via tenant_users.

    Thread-safe and stateless; a single instance can be shared across requests.
    """

    def resolve(
        self,
        db: Session,
        *,
        provider: str,
        issuer: str,
        subject: str,
        tenant_id: str | None = None,
    ) -> IdentityPrincipal | None:
        """Return the membership bound to this identity triple, or None.

        Does NOT enforce active status — the caller decides how to handle
        inactive memberships. Use resolve_or_deny() for fail-closed enforcement.
        """
        row = db.execute(
            _RESOLVE_SQL,
            {
                "binding_status": _BOUND_STATUS,
                "provider": provider,
                "issuer": issuer,
                "subject": subject,
                "tenant_id": tenant_id,
            },
        ).one_or_none()

        if row is None:
            log.debug(
                "identity_resolver.no_match",
                extra={
                    "provider": provider,
                    "subject_prefix": subject[:16],
                    "tenant_id": tenant_id,
                },
            )
            return None

        status = "active" if row.active else "inactive"
        email = str(row.identity_email or row.email or "")
        return IdentityPrincipal(
            tenant_id=str(row.tenant_id),
            membership_id=str(row.id),
            subject=str(row.identity_subject or subject),
            issuer=str(row.identity_issuer or issuer),
            provider=str(row.identity_provider or provider),
            email=email,
            display_name=email,
            roles=[str(row.role)] if row.role else [],
            status=status,
            trust_level=str(row.identity_binding_status or "unbound"),
            membership_version=int(row.membership_version or 1),
        )

    def resolve_or_deny(
        self,
        db: Session,
        *,
        provider: str,
        issuer: str,
        subject: str,
        tenant_id: str | None = None,
    ) -> IdentityPrincipal:
        """Resolve membership and raise IdentityResolutionError on any denial.

        Raises:
            IdentityResolutionError(MEMBERSHIP_NOT_FOUND)  — no bound record
            IdentityResolutionError(MEMBERSHIP_INACTIVE)   — active=False
        """
        principal = self.resolve(
            db,
            provider=provider,
            issuer=issuer,
            subject=subject,
            tenant_id=tenant_id,
        )
        if principal is None:
            raise IdentityResolutionError(
                "MEMBERSHIP_NOT_FOUND",
                f"no bound membership for {provider}/{subject!r}"
                + (f" in tenant {tenant_id!r}" if tenant_id else ""),
            )
        if principal.status != "active":
            raise IdentityResolutionError(
                f"MEMBERSHIP_{principal.status.upper()}",
                f"membership {principal.membership_id!r} is {principal.status}",
            )
        log.info(
            "identity_resolver.resolved",
            extra={
                "membership_id": principal.membership_id,
                "tenant_id": principal.tenant_id,
                "subject_prefix": principal.subject[:16],
            },
        )
        return principal
