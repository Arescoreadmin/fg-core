"""api/identity_authority/tenant_resolver.py — Tenant binding resolution.

Resolves a FrostGate TenantBinding from an authenticated CanonicalIdentity.
Queries the tenant_users table using the identity triple
(identity_provider, identity_issuer, identity_subject).
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from sqlalchemy.orm import Session

from api.identity_authority.models import CanonicalIdentity, TenantBinding
from api.identity_authority.metrics import TENANT_RESOLUTION_LATENCY, TENANT_RESOLUTION_TOTAL

log = logging.getLogger("frostgate.identity_authority.tenant_resolver")


class TenantResolver:
    """Resolves FrostGate tenant binding for an authenticated identity."""

    def resolve(
        self,
        identity: CanonicalIdentity,
        db: Session,
        tenant_id_hint: Optional[str] = None,
    ) -> Optional[TenantBinding]:
        """Resolve tenant binding.

        Resolution order:
          1. Identity triple lookup (provider + issuer + subject → TenantUser)
          2. Tenant ID hint (from API key binding or X-Tenant-Id header)
          3. None — identity is unbound (platform admin without tenant context)

        Returns None for platform admins without a bound tenant.
        """
        t0 = time.monotonic()
        result = "not_found"
        try:
            binding = self._resolve_by_membership(identity, db)
            if binding:
                result = "resolved"
                return binding
            if tenant_id_hint:
                binding = self._resolve_by_hint(tenant_id_hint, identity, db)
                if binding:
                    result = "resolved"
                    return binding
            return None
        except Exception as exc:
            result = "error"
            log.error(
                "tenant_resolver.error",
                extra={"exc": str(exc), "subject_prefix": identity.subject[:16]},
            )
            raise
        finally:
            elapsed = time.monotonic() - t0
            TENANT_RESOLUTION_LATENCY.labels(result=result).observe(elapsed)
            TENANT_RESOLUTION_TOTAL.labels(result=result).inc()

    def _resolve_by_membership(
        self,
        identity: CanonicalIdentity,
        db: Session,
    ) -> Optional[TenantBinding]:
        """Look up TenantUser by identity triple."""
        try:
            from admin_gateway.identity.models import TenantUser
        except ImportError:
            # admin_gateway not available in this context — skip membership lookup
            log.debug("tenant_resolver.admin_gateway_not_available")
            return None

        try:
            member = (
                db.query(TenantUser)
                .filter(
                    TenantUser.identity_provider == identity.provider.name,
                    TenantUser.identity_issuer == identity.provider.issuer,
                    TenantUser.identity_subject == identity.subject,
                    TenantUser.identity_binding_status == "bound",
                    TenantUser.active.is_(True),
                )
                .first()
            )
        except Exception:
            # TenantUser may not be in this DB — return None gracefully
            return None

        if member is None:
            return None

        from api.actor_context import roles_to_permissions

        role = getattr(member, "role", None) or "viewer"
        roles_list = [role] if role else []
        perms = roles_to_permissions(roles_list)

        return TenantBinding(
            tenant_id=str(member.tenant_id),
            organization_id=None,
            membership_id=str(getattr(member, "id", "")),
            roles=frozenset(roles_list),
            permissions=perms,
        )

    def _resolve_by_hint(
        self,
        tenant_id: str,
        identity: CanonicalIdentity,
        db: Session,
    ) -> Optional[TenantBinding]:
        """Resolve a tenant by ID hint (e.g., from API key binding).

        For JWT identities, the hint only applies if it matches the tenant_binding
        already present on the identity (security: prevent cross-tenant escalation).
        """
        # For JWT identities with a tenant_binding, validate the hint matches
        if identity.tenant_binding:
            existing_tid = identity.tenant_binding.tenant_id
            if existing_tid and existing_tid != tenant_id:
                log.warning(
                    "tenant_resolver.cross_tenant_hint_denied",
                    extra={
                        "hint": tenant_id,
                        "bound": existing_tid,
                        "subject_prefix": identity.subject[:16],
                    },
                )
                return None
            return identity.tenant_binding

        # For machine identities (API keys), accept the hint directly
        if identity.identity_type in ("machine", "service"):
            from api.actor_context import roles_to_permissions
            roles = list(identity.tenant_binding.roles) if identity.tenant_binding else []
            perms = roles_to_permissions(roles)
            return TenantBinding(
                tenant_id=tenant_id,
                organization_id=None,
                membership_id=None,
                roles=frozenset(roles),
                permissions=perms,
            )

        return None
