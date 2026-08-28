"""api/tenant_admin_authority.py — TENANT-ADMIN-001 Delegated Tenant Administration Authority.

Canonical server-side authority check answering:
  "Does principal P have tenant_admin authority over tenant T?"

The answer is DB-canonical, not JWT-derived: the JWT roles claim is treated as
an advisory hint. Real authorization is derived from the ``tenant_users`` row
plus a bound canonical principal (fg_principals via principal_id).

Also enforces the delegation ceiling: a tenant_admin may only assign a small
allowlist of client-facing roles, and may never grant itself or FrostGate
internal roles (Administrator, Operator, CISO, etc.).

Design principles:
  1. JWT/API-key role claims are ADVISORY. Every authority decision performs
     a fresh SELECT against ``tenant_users`` inside the request's DB session.
  2. Authority is scoped per-tenant. The route tenant is the only source of
     truth for the target tenant; the actor's session must agree.
  3. Delegation ceiling is a static allowlist. Adding a new client-side role
     is a code change, not a data change.
  4. Cross-tenant hard denial returns a uniform ``TENANT_ADMIN_DENIED`` error
     — no oracle differentiation between "wrong tenant" and "not admin".
  5. Bootstrap is platform-only (``platform.admin`` permission) and idempotent.

This module DOES NOT:
  - Introduce a new RBAC engine (uses the existing ROLE_PERMISSIONS map).
  - Replace ``require_permission()`` (composes with it).
  - Bypass ``resolve_authoritative_tenant()`` (calls it).
  - Grant tenant admins any platform authority.

TENANT-ADMIN-001. See docs/architecture/tenant-admin-001.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import resolve_authoritative_tenant
from api.deps import auth_ctx_db_session

log = logging.getLogger("frostgate.tenant_admin_authority")


# ---------------------------------------------------------------------------
# Delegation ceiling
# ---------------------------------------------------------------------------
#
# Tenant admins may only assign roles from this allowlist. Any other role
# (including 'tenant_admin' itself and any FrostGate internal role) is
# rejected with ROLE_NOT_DELEGATABLE.
#
# The list is deliberately narrow. Adding a role requires:
#   1. A code change here, and
#   2. A companion entry in ROLE_PERMISSIONS in api/actor_context.py so the
#      role actually resolves to a permission set.
#
# 'user' and 'auditor' are retained for backwards compatibility with the
# legacy workforce role labels. All 'client_*' roles are the canonical
# forward-facing labels for CLIENT-E2E-001.
DELEGATABLE_ROLES: frozenset[str] = frozenset(
    {
        # Legacy compatible labels — recognised by workforce.InviteUserPayload
        "user",
        "auditor",
        # Canonical client-side labels — recognised going forward
        "client_executive",
        "client_compliance",
        "client_auditor",
        "client_remediation_owner",
        "client_security_owner",
        "client_read_only",
    }
)

# Roles a tenant_admin can NEVER assign, even if listed elsewhere.
# Prevents self-replication (tenant_admin cannot grant tenant_admin) and
# prevents privilege elevation into FrostGate internal roles.
FORBIDDEN_DELEGATION_ROLES: frozenset[str] = frozenset(
    {
        "tenant_admin",
        # FrostGate internal roles
        "platform_admin",
        "Administrator",
        "Operator",
        "CISO",
        "Executive",
        "Auditor",
        "Developer",
        "Support",
        "Compliance",
        "AssessmentEngineer",
        "FieldAssessor",
        "Consultant",
        # Legacy governance roles that must not be delegated by tenant admins
        "compliance_reviewer",
        "qa_reviewer",
        "assessor",
    }
)


# ---------------------------------------------------------------------------
# Error contract
# ---------------------------------------------------------------------------


TENANT_ADMIN_DENIED = "TENANT_ADMIN_DENIED"
ROLE_NOT_DELEGATABLE = "ROLE_NOT_DELEGATABLE"
TARGET_USER_NOT_FOUND = "TARGET_USER_NOT_FOUND"


def _denied() -> HTTPException:
    """Uniform denial. Do NOT differentiate wrong-tenant from not-admin.

    Returning the same status + code for both cases prevents an oracle where
    a caller can enumerate other tenants' identities by observing distinct
    error responses.
    """
    return HTTPException(
        status_code=403,
        detail={
            "code": TENANT_ADMIN_DENIED,
            "message": "Tenant administration authority required.",
        },
    )


# ---------------------------------------------------------------------------
# Canonical authority check
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TenantAdminAuthority:
    """Proof that a principal is a canonical tenant_admin for a specific tenant.

    Emitted by ``check_tenant_admin_authority()`` after the DB-canonical check
    passes. Downstream code should treat this as an opaque token; do not
    reconstruct it manually.
    """

    tenant_id: str
    membership_id: str
    principal_id: str
    subject: str


def check_tenant_admin_authority(
    db: Session,
    *,
    actor_ctx: ActorContext,
    tenant_id: str,
) -> TenantAdminAuthority:
    """Verify the actor is a canonical tenant_admin for the given tenant.

    Verification is DB-authoritative: the JWT role claim is ignored. The DB
    must show:

      * A ``tenant_users`` row with the actor's ``membership_id`` (bound by
        ``_bind_membership()`` at JWT resolution time), OR the actor's
        canonical principal_id resolves to a ``tenant_users`` row for this
        tenant.
      * ``role = 'tenant_admin'``.
      * ``active = TRUE``.
      * ``identity_binding_status = 'bound'``.
      * ``principal_id IS NOT NULL`` (a bound canonical principal).
      * ``tenant_id`` matches the requested tenant (no cross-tenant admin).

    Any failure raises 403 with a uniform error code — no oracle.

    Args:
        db: Active DB session with tenant context already applied (RLS on).
        actor_ctx: Resolved ActorContext for the caller.
        tenant_id: The tenant against which authority is being asserted.

    Returns:
        A TenantAdminAuthority proof.

    Raises:
        HTTPException 403 TENANT_ADMIN_DENIED on any failure.
    """
    if not tenant_id or not actor_ctx or not actor_ctx.subject:
        raise _denied()

    # Prefer the pre-bound membership_id (populated by _bind_membership on
    # OIDC actors). Falls back to a principal-based lookup for actors whose
    # membership was not pre-bound in this request.
    row = None
    if actor_ctx.membership_id:
        row = db.execute(
            text(
                """
                SELECT id, tenant_id, role, active, principal_id,
                       identity_binding_status
                FROM tenant_users
                WHERE id = :mid AND tenant_id = :tid
                """
            ),
            {"mid": actor_ctx.membership_id, "tid": tenant_id},
        ).fetchone()

    # Fallback: resolve by (provider, subject) if we can't find via membership_id.
    # This handles first-time authority checks where _bind_membership did not run.
    if row is None:
        row = db.execute(
            text(
                """
                SELECT id, tenant_id, role, active, principal_id,
                       identity_binding_status
                FROM tenant_users
                WHERE tenant_id = :tid
                  AND identity_subject = :subject
                  AND identity_binding_status = 'bound'
                LIMIT 1
                """
            ),
            {"tid": tenant_id, "subject": actor_ctx.subject},
        ).fetchone()

    if row is None:
        log.info(
            "tenant_admin.authority_denied",
            extra={
                "reason": "membership_not_found",
                "tenant_id": tenant_id,
                "actor_subject": actor_ctx.subject[:16] if actor_ctx.subject else "",
            },
        )
        raise _denied()

    # Enforce all invariants. Any failure is the same uniform denial.
    if str(row.tenant_id) != str(tenant_id):
        # Belt and suspenders — the SELECT already filtered on tenant_id.
        log.warning(
            "tenant_admin.authority_denied",
            extra={"reason": "tenant_mismatch", "tenant_id": tenant_id},
        )
        raise _denied()
    if not row.active:
        log.info(
            "tenant_admin.authority_denied",
            extra={"reason": "membership_inactive", "tenant_id": tenant_id},
        )
        raise _denied()
    if str(row.role) != "tenant_admin":
        log.info(
            "tenant_admin.authority_denied",
            extra={
                "reason": "not_tenant_admin",
                "tenant_id": tenant_id,
                "role": str(row.role),
            },
        )
        raise _denied()
    if str(row.identity_binding_status) != "bound":
        log.info(
            "tenant_admin.authority_denied",
            extra={
                "reason": "unbound",
                "tenant_id": tenant_id,
                "status": str(row.identity_binding_status),
            },
        )
        raise _denied()
    if row.principal_id is None:
        log.info(
            "tenant_admin.authority_denied",
            extra={"reason": "missing_principal", "tenant_id": tenant_id},
        )
        raise _denied()

    return TenantAdminAuthority(
        tenant_id=str(tenant_id),
        membership_id=str(row.id),
        principal_id=str(row.principal_id),
        subject=actor_ctx.subject,
    )


# ---------------------------------------------------------------------------
# Delegation ceiling
# ---------------------------------------------------------------------------


def assert_role_delegatable(role: str) -> None:
    """Enforce the delegation ceiling for a role a tenant_admin is assigning.

    Raises HTTPException 403 with ``ROLE_NOT_DELEGATABLE`` if the role is
    either explicitly forbidden or not on the delegation allowlist.

    This function is the single authority for the delegation ceiling. All
    tenant_admin role-assignment paths must call it.
    """
    if not role or not isinstance(role, str):
        raise HTTPException(
            status_code=422,
            detail={
                "code": ROLE_NOT_DELEGATABLE,
                "message": "role is required",
            },
        )
    normalized = role.strip()
    # Forbidden list is authoritative and case-sensitive on purpose — FrostGate
    # internal roles use CamelCase, client roles use snake_case; both are
    # explicit.
    if normalized in FORBIDDEN_DELEGATION_ROLES:
        log.warning(
            "tenant_admin.delegation_ceiling_violated",
            extra={"role": normalized, "reason": "forbidden"},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": ROLE_NOT_DELEGATABLE,
                "message": ("Tenant administrators cannot delegate this role."),
                "role": normalized,
            },
        )
    if normalized not in DELEGATABLE_ROLES:
        log.info(
            "tenant_admin.delegation_ceiling_violated",
            extra={"role": normalized, "reason": "not_on_allowlist"},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": ROLE_NOT_DELEGATABLE,
                "message": (
                    "Tenant administrators may only delegate a restricted "
                    "set of client roles."
                ),
                "role": normalized,
            },
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


def require_tenant_admin(tenant_id_arg: str = "tenant_id"):
    """FastAPI dependency factory: caller must be tenant_admin for the path tenant.

    Uses the route path parameter named ``tenant_id_arg`` to identify the
    target tenant, resolves the ActorContext, cross-checks tenant binding via
    ``resolve_authoritative_tenant``, then performs the DB-canonical
    tenant_admin verification.

    Returns the TenantAdminAuthority proof for use in the route body.

    Usage:
        @router.post("/admin/tenants/{tenant_id}/users/invite")
        def invite(
            tenant_id: str,
            authority: TenantAdminAuthority = Depends(require_tenant_admin()),
        ): ...
    """

    def _dep(
        request: Request,
        tenant_id: str,
        actor_ctx: ActorContext = Depends(require_permission("user.invite")),
        db: Session = Depends(auth_ctx_db_session),
    ) -> TenantAdminAuthority:
        # bind_tenant_id + cross-check on actor session tenant.
        resolved = resolve_authoritative_tenant(request, actor_ctx, tenant_id)
        return check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=resolved)

    return _dep


def require_platform_admin_actor():
    """FastAPI dependency: caller has platform.admin permission.

    Used for the first-admin bootstrap endpoint. Returns the ActorContext.
    Delegates the actual check to ``require_permission("platform.admin")``.
    """
    return require_permission("platform.admin")


def get_tenant_admin_role_ceiling() -> tuple[str, ...]:
    """Public helper for tests / diagnostics: sorted list of delegatable roles."""
    return tuple(sorted(DELEGATABLE_ROLES))


def is_role_delegatable(role: Optional[str]) -> bool:
    """Non-raising variant of assert_role_delegatable. Useful in tests / audits."""
    if not role or not isinstance(role, str):
        return False
    normalized = role.strip()
    return (
        normalized not in FORBIDDEN_DELEGATION_ROLES and normalized in DELEGATABLE_ROLES
    )
