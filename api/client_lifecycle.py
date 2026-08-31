"""api/client_lifecycle.py — CLIENT-LIFECYCLE-001 canonical readiness evaluator.

Derives client-tenant operational readiness from durable canonical facts.
Pure function — no side effects, no stored state, no FastAPI imports.

Precedence (deterministic, multiple simultaneous failures):
    1. tenant_not_found   — FATAL; nothing else checkable
    2. tenant_suspended   — CRITICAL; admin state irrelevant
    3. admin_unset        — P0; no active tenant_admin row at all
    4. admin_unbound      — P1; admin exists but identity not bound
    5. operational        — all gates clear (warnings may apply)

Callers operating as fg_app under FORCE ROW LEVEL SECURITY must call
``set_tenant_context(db, tenant_id)`` BEFORE calling evaluate_client_lifecycle.

lifecycle_version: 1  (bumped when stable machine-contract fields change)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session


LIFECYCLE_VERSION = 1

# ---------------------------------------------------------------------------
# Lifecycle state labels — versioned machine contract
# ---------------------------------------------------------------------------

STATE_OPERATIONAL = "operational"
STATE_ADMIN_UNSET = "admin_unset"
STATE_ADMIN_UNBOUND = "admin_unbound"
STATE_TENANT_SUSPENDED = "tenant_suspended"
STATE_TENANT_NOT_FOUND = "tenant_not_found"

# ---------------------------------------------------------------------------
# Blocker codes — versioned machine contract
# ---------------------------------------------------------------------------

BLOCKER_TENANT_NOT_FOUND = "TENANT_NOT_FOUND"
BLOCKER_TENANT_SUSPENDED = "TENANT_SUSPENDED"
BLOCKER_NO_BOUND_ADMIN = "NO_BOUND_ADMIN"

# ---------------------------------------------------------------------------
# Warning codes — versioned machine contract
# ---------------------------------------------------------------------------

WARN_NO_ACTIVE_MEMBERS = "NO_ACTIVE_MEMBERS"

# ---------------------------------------------------------------------------
# Next-action codes — versioned machine contract
# ---------------------------------------------------------------------------

ACTION_PROVISION_TENANT = "PROVISION_TENANT"
ACTION_BOOTSTRAP_ADMIN = "BOOTSTRAP_ADMIN"
ACTION_BIND_ADMIN_IDENTITY = "BIND_ADMIN_IDENTITY"
ACTION_INVITE_MEMBERS = "INVITE_MEMBERS"


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientLifecycleResult:
    """Immutable snapshot of a tenant's operational readiness.

    All fields are versioned machine contracts — do not rename without bumping
    LIFECYCLE_VERSION and updating downstream consumers (Console, AI Workspace,
    automation pipelines).
    """

    lifecycle_version: int
    tenant_id: str
    lifecycle_state: str
    operational: bool
    repairable: bool
    blockers: tuple
    warnings: tuple
    next_actions: tuple
    # diagnostic fields
    tenant_canonical_state: Optional[str]
    has_bound_admin: bool
    active_member_count: int


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


def evaluate_client_lifecycle(
    db: Session,
    tenant_id: str,
) -> ClientLifecycleResult:
    """Derive operational readiness from canonical DB facts.

    Fail-closed: any unreadable or unknown state → operational=False.
    State precedence is deterministic regardless of DB ordering or set ordering.

    Does NOT set RLS tenant context — callers must call set_tenant_context(db,
    tenant_id) before invoking this function when running under Postgres FORCE
    ROW LEVEL SECURITY.
    """
    # --- 1. Tenant existence + canonical state ---
    tenant_row = db.execute(
        text("SELECT lifecycle_state FROM tenants WHERE tenant_id = :tid"),
        {"tid": tenant_id},
    ).fetchone()

    if tenant_row is None:
        return ClientLifecycleResult(
            lifecycle_version=LIFECYCLE_VERSION,
            tenant_id=tenant_id,
            lifecycle_state=STATE_TENANT_NOT_FOUND,
            operational=False,
            repairable=False,
            blockers=(BLOCKER_TENANT_NOT_FOUND,),
            warnings=(),
            next_actions=(ACTION_PROVISION_TENANT,),
            tenant_canonical_state=None,
            has_bound_admin=False,
            active_member_count=0,
        )

    tenant_canonical_state: str = str(tenant_row[0])

    # --- 2. Tenant must be active ---
    if tenant_canonical_state != "active":
        return ClientLifecycleResult(
            lifecycle_version=LIFECYCLE_VERSION,
            tenant_id=tenant_id,
            lifecycle_state=STATE_TENANT_SUSPENDED,
            operational=False,
            repairable=False,
            blockers=(BLOCKER_TENANT_SUSPENDED,),
            warnings=(),
            next_actions=(),
            tenant_canonical_state=tenant_canonical_state,
            has_bound_admin=False,
            active_member_count=0,
        )

    # --- 3. Admin rows — fetch all, filter in Python for cross-DB safety ---
    # Postgres boolean and SQLite integer (0/1) both coerce via bool().
    # LEFT JOIN fg_principals so a bound admin whose principal is suspended or
    # deactivated is NOT counted as a valid bound admin (canonical identity
    # resolution rejects inactive principals; evaluator must agree).
    admin_rows = db.execute(
        text(
            """
            SELECT tu.id, tu.role, tu.active, tu.identity_binding_status,
                   tu.principal_id,
                   COALESCE(fp.lifecycle_state, 'inactive') AS principal_lifecycle_state
            FROM tenant_users tu
            LEFT JOIN fg_principals fp ON fp.id = tu.principal_id
            WHERE tu.tenant_id = :tid AND tu.role = 'tenant_admin'
            ORDER BY tu.created_at ASC
            """
        ),
        {"tid": tenant_id},
    ).fetchall()

    active_admin_rows = [r for r in admin_rows if bool(r[2])]
    bound_admin_count = sum(
        1
        for r in active_admin_rows
        if str(r[3]) == "bound" and r[4] is not None and str(r[5]) == "active"
    )
    has_bound_admin = bound_admin_count > 0
    has_any_active_admin = len(active_admin_rows) > 0

    # --- 4. Non-admin active member count ---
    member_rows = db.execute(
        text(
            """
            SELECT active
            FROM tenant_users
            WHERE tenant_id = :tid AND role != 'tenant_admin'
            """
        ),
        {"tid": tenant_id},
    ).fetchall()
    active_member_count = sum(1 for r in member_rows if bool(r[0]))

    # --- Apply precedence ---

    # P0: No active admin at all
    if not has_any_active_admin:
        return ClientLifecycleResult(
            lifecycle_version=LIFECYCLE_VERSION,
            tenant_id=tenant_id,
            lifecycle_state=STATE_ADMIN_UNSET,
            operational=False,
            repairable=True,
            blockers=(BLOCKER_NO_BOUND_ADMIN,),
            warnings=(),
            next_actions=(ACTION_BOOTSTRAP_ADMIN,),
            tenant_canonical_state=tenant_canonical_state,
            has_bound_admin=False,
            active_member_count=active_member_count,
        )

    # P1: Active admin exists but none are bound
    if not has_bound_admin:
        return ClientLifecycleResult(
            lifecycle_version=LIFECYCLE_VERSION,
            tenant_id=tenant_id,
            lifecycle_state=STATE_ADMIN_UNBOUND,
            operational=False,
            repairable=False,
            blockers=(BLOCKER_NO_BOUND_ADMIN,),
            warnings=(),
            next_actions=(ACTION_BIND_ADMIN_IDENTITY,),
            tenant_canonical_state=tenant_canonical_state,
            has_bound_admin=False,
            active_member_count=active_member_count,
        )

    # P5: All gates clear — operational
    warnings: tuple = ()
    next_actions: tuple = ()
    if active_member_count == 0:
        warnings = (WARN_NO_ACTIVE_MEMBERS,)
        next_actions = (ACTION_INVITE_MEMBERS,)

    return ClientLifecycleResult(
        lifecycle_version=LIFECYCLE_VERSION,
        tenant_id=tenant_id,
        lifecycle_state=STATE_OPERATIONAL,
        operational=True,
        repairable=False,
        blockers=(),
        warnings=warnings,
        next_actions=next_actions,
        tenant_canonical_state=tenant_canonical_state,
        has_bound_admin=True,
        active_member_count=active_member_count,
    )
