"""Admin Gateway-only tenant session issuance."""

from __future__ import annotations

from typing import cast

from admin_gateway.identity.models import TenantUser
from admin_gateway.auth.session import Session, SessionManager
from admin_gateway.identity.identity_context import TenantSessionContext

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin": frozenset({"console:admin"}),
    "auditor": frozenset({"audit:read"}),
    "user": frozenset({"product:read"}),
}


class TenantSessionError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def build_tenant_session_context(membership: TenantUser) -> TenantSessionContext:
    if not membership.active:
        raise TenantSessionError("MEMBERSHIP_DISABLED")
    if membership.identity_binding_status != "bound":
        raise TenantSessionError("IDENTITY_NOT_BOUND")
    if membership.identity_type != "human":
        raise TenantSessionError("IDENTITY_TYPE_NOT_ALLOWED")
    if not all(
        (
            membership.identity_provider,
            membership.identity_issuer,
            membership.identity_subject,
        )
    ):
        raise TenantSessionError("IDENTITY_NOT_BOUND")
    scopes = ROLE_SCOPES.get(membership.role, frozenset())
    if not scopes:
        raise TenantSessionError("MISSING_SCOPES")
    return TenantSessionContext(
        tenant_id=membership.tenant_id,
        membership_id=membership.id,
        user_id=membership.id,
        email=membership.identity_email or membership.email,
        identity_provider=cast(str, membership.identity_provider),
        identity_issuer=cast(str, membership.identity_issuer),
        identity_subject=cast(str, membership.identity_subject),
        identity_type=membership.identity_type,
        role=membership.role,
        scopes=scopes,
        binding_status=membership.identity_binding_status,
    )


def issue_tenant_session(
    manager: SessionManager, context: TenantSessionContext
) -> Session:
    return manager.create_session(
        user_id=context.user_id,
        email=context.email,
        scopes=set(context.scopes),
        claims={"tenant_id": context.tenant_id, "roles": [context.role]},
        tenant_id=context.tenant_id,
        membership_id=context.membership_id,
        identity_provider=context.identity_provider,
        identity_issuer=context.identity_issuer,
        identity_subject=context.identity_subject,
        identity_type=context.identity_type,
        role=context.role,
        binding_status=context.binding_status,
        tenant_governed=True,
    )
