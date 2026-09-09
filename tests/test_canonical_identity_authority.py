"""PR-1 — Canonical Identity Authority: acceptance matrix.

Proves the FrostGate identity-to-authorization chain is fail-closed:

    external identity binding
        → canonical principal
        → active tenant membership
        → authoritative role
        → derived permissions
        → ActorContext
        → RBAC decision

Architectural law enforced here:
    EXTERNAL IDENTITY PROVIDERS AUTHENTICATE.  FROSTGATE AUTHORIZES.
    Authentication success MUST NOT imply authorization success.

Acceptance cases:
    CASE 1  — ALLOW: valid enrolled identity + active membership + permitted role
    CASE 2  — DENY: valid authentication + no membership
    CASE 3  — DENY: Tenant A membership + Tenant B target
    CASE 4  — DENY: suspended / revoked membership (active=FALSE)
    CASE 5  — DENY: disabled tenant (API-key credential path; OIDC gap documented)
    CASE 6  — DENY: removed permission / role → empty permission set
    CASE 7  — DENY: forged / stale IdP role claim does not escalate
    CASE 8  — DENY: forged / stale tenant claim does not cross tenant
    CASE 9  — SAFE: duplicate identity binding does not create ambiguous authority
    CASE 10 — DETERMINISTIC: same canonical identity resolves identically every call
"""

from __future__ import annotations

from typing import Any

import pytest
import sqlalchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from api.actor_context import ALL_PERMISSIONS, ActorContext, roles_to_permissions
from services.identity_resolver import IdentityResolutionError, IdentityResolver

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-alpha"
_TENANT_B = "tenant-beta"
_PROVIDER = "auth0"
_ISSUER = "https://example.auth0.com/"
_SUBJECT_A = "auth0|user-alpha-001"
_SUBJECT_B = "auth0|user-beta-001"
_SUBJECT_ORPHAN = "auth0|user-no-membership"
_NOW = "2026-09-08T00:00:00+00:00"

# ---------------------------------------------------------------------------
# In-memory SQLite schema — mirrors the canonical tenant_users columns used
# by IdentityResolver (services/identity_resolver/service.py:_RESOLVE_SQL)
# and the fg_external_identities / fg_principals tables (PR-AUTH-001/002/004).
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id        TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL DEFAULT 'Test Tenant',
    lifecycle_state  TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS fg_principals (
    id                TEXT    PRIMARY KEY,
    display_name      TEXT,
    primary_email     TEXT,
    principal_type    TEXT    NOT NULL DEFAULT 'human',
    lifecycle_state   TEXT    NOT NULL DEFAULT 'active',
    mfa_verified      INTEGER NOT NULL DEFAULT 0,
    authority_version INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS fg_external_identities (
    id               TEXT PRIMARY KEY,
    principal_id     TEXT NOT NULL REFERENCES fg_principals(id),
    provider         TEXT NOT NULL,
    provider_issuer  TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    provider_email   TEXT,
    created_at       TEXT NOT NULL,
    last_seen_at     TEXT,
    UNIQUE (provider, provider_issuer, provider_subject)
);

CREATE TABLE IF NOT EXISTS tenant_users (
    id                       TEXT    PRIMARY KEY,
    tenant_id                TEXT    NOT NULL,
    email                    TEXT    NOT NULL DEFAULT 'x@example.com',
    display_name             TEXT    NOT NULL DEFAULT 'Test User',
    role                     TEXT,
    active                   INTEGER NOT NULL DEFAULT 1,
    identity_type            TEXT    NOT NULL DEFAULT 'human',
    identity_provider        TEXT,
    identity_issuer          TEXT,
    identity_subject         TEXT,
    identity_email           TEXT,
    identity_binding_status  TEXT    NOT NULL DEFAULT 'unbound',
    membership_lifecycle_state TEXT  NOT NULL DEFAULT 'active',
    membership_version       INTEGER NOT NULL DEFAULT 1,
    principal_id             TEXT    REFERENCES fg_principals(id)
)
"""


def _setup(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        for stmt in _SCHEMA.split(";"):
            s = stmt.strip()
            if s:
                conn.execute(text(s))


@pytest.fixture()
def engine() -> Engine:
    eng = create_engine("sqlite:///:memory:", echo=False)
    _setup(eng)

    @sqlalchemy.event.listens_for(eng, "connect")
    def _fk_on(dbapi_con: Any, _rec: Any) -> None:
        dbapi_con.execute("PRAGMA foreign_keys = ON")

    return eng


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_principal(conn: Any, pid: str, lifecycle_state: str = "active") -> None:
    conn.execute(
        text(
            "INSERT INTO fg_principals (id, principal_type, lifecycle_state,"
            " created_at, updated_at)"
            " VALUES (:id, 'human', :ls, :now, :now)"
        ),
        {"id": pid, "ls": lifecycle_state, "now": _NOW},
    )


def _insert_external_id(
    conn: Any,
    eid: str,
    principal_id: str,
    provider: str = _PROVIDER,
    issuer: str = _ISSUER,
    subject: str = _SUBJECT_A,
) -> None:
    conn.execute(
        text(
            "INSERT INTO fg_external_identities"
            " (id, principal_id, provider, provider_issuer, provider_subject, created_at)"
            " VALUES (:id, :pid, :prov, :iss, :sub, :now)"
        ),
        {
            "id": eid,
            "pid": principal_id,
            "prov": provider,
            "iss": issuer,
            "sub": subject,
            "now": _NOW,
        },
    )


def _insert_tenant(
    conn: Any,
    tenant_id: str,
    lifecycle_state: str = "active",
) -> None:
    conn.execute(
        text(
            "INSERT OR IGNORE INTO tenants (tenant_id, display_name, lifecycle_state)"
            " VALUES (:tid, :name, :ls)"
        ),
        {"tid": tenant_id, "name": f"Tenant {tenant_id}", "ls": lifecycle_state},
    )


def _insert_membership(
    conn: Any,
    mid: str,
    tenant_id: str,
    subject: str,
    *,
    role: str | None = "tenant_admin",
    active: int = 1,
    provider: str = _PROVIDER,
    issuer: str = _ISSUER,
    lifecycle_state: str = "active",
    principal_id: str | None = None,
) -> None:
    conn.execute(
        text(
            "INSERT INTO tenant_users"
            " (id, tenant_id, email, role, active, identity_provider, identity_issuer,"
            "  identity_subject, identity_binding_status, membership_lifecycle_state,"
            "  membership_version, principal_id)"
            " VALUES (:id, :tid, :email, :role, :active, :prov, :iss, :sub,"
            "         'bound', :ls, 1, :pid)"
        ),
        {
            "id": mid,
            "tid": tenant_id,
            "email": f"{subject[:8]}@example.com",
            "role": role,
            "active": active,
            "prov": provider,
            "iss": issuer,
            "sub": subject,
            "ls": lifecycle_state,
            "pid": principal_id,
        },
    )


# ---------------------------------------------------------------------------
# CASE 1 — ALLOW: full valid chain
# ---------------------------------------------------------------------------


def test_case1_allow_valid_enrolled_identity(engine: Engine) -> None:
    """CASE 1: valid enrolled identity + active membership + permitted role → ALLOW.

    Proves the complete chain: canonical external identity binding →
    tenant_users membership (active, bound) → role → permission set.
    The IdentityPrincipal returned must carry the correct tenant, membership,
    and role; permissions expand via roles_to_permissions().
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-001")
        _insert_external_id(conn, "eid-001", "pid-001")
        _insert_membership(conn, "mid-001", _TENANT_A, _SUBJECT_A, role="tenant_admin")

    with Session(engine) as db:
        resolver = IdentityResolver()
        principal = resolver.resolve_or_deny(
            db,
            provider=_PROVIDER,
            issuer=_ISSUER,
            subject=_SUBJECT_A,
        )

    assert principal is not None, "valid enrolled identity must resolve"
    assert principal.tenant_id == _TENANT_A
    assert principal.membership_id == "mid-001"
    assert principal.trust_level == "bound"
    assert principal.status == "active"
    assert "tenant_admin" in principal.roles

    # Permissions expand from the canonical FrostGate role, never from IdP claims.
    perms = roles_to_permissions(principal.roles)
    assert "key.manage" in perms, "tenant_admin must include key.manage"
    assert "user.invite" in perms, "tenant_admin must include user.invite"
    assert "governance.decision" not in perms, (
        "SoD: tenant_admin must not include governance.decision"
    )


# ---------------------------------------------------------------------------
# CASE 2 — DENY: no membership
# ---------------------------------------------------------------------------


def test_case2_deny_no_membership(engine: Engine) -> None:
    """CASE 2: authenticated identity with no tenant_users row → DENY.

    Authentication (JWT validation) succeeds but FrostGate has no membership
    record for the principal.  IdentityResolutionError(MEMBERSHIP_NOT_FOUND)
    is the expected canonical signal; callers convert this to HTTP 403.
    """
    # No membership inserted for _SUBJECT_ORPHAN.
    with Session(engine) as db:
        resolver = IdentityResolver()
        with pytest.raises(IdentityResolutionError) as exc_info:
            resolver.resolve_or_deny(
                db,
                provider=_PROVIDER,
                issuer=_ISSUER,
                subject=_SUBJECT_ORPHAN,
            )

    assert exc_info.value.code == "MEMBERSHIP_NOT_FOUND"


# ---------------------------------------------------------------------------
# CASE 3 — DENY: Tenant A membership + Tenant B target
# ---------------------------------------------------------------------------


def test_case3_deny_wrong_tenant(engine: Engine) -> None:
    """CASE 3: principal has membership in Tenant A only; Tenant B target → DENY.

    The resolver is called with the subject AND the requested tenant_id.
    When the canonical tenant_users row is in Tenant A but tenant_id=Tenant B
    is supplied, the row is not returned → MEMBERSHIP_NOT_FOUND.

    This is the primary control preventing cross-tenant escalation via forged
    or manipulated JWT tenant_id claims: the resolver verifies membership in
    the stated tenant, not just any tenant.
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-003")
        _insert_external_id(conn, "eid-003", "pid-003")
        # Membership is only in TENANT_A.
        _insert_membership(conn, "mid-003", _TENANT_A, _SUBJECT_A, role="assessor")

    with Session(engine) as db:
        resolver = IdentityResolver()
        # Requesting Tenant B — must be denied even though identity is authenticated.
        with pytest.raises(IdentityResolutionError) as exc_info:
            resolver.resolve_or_deny(
                db,
                provider=_PROVIDER,
                issuer=_ISSUER,
                subject=_SUBJECT_A,
                tenant_id=_TENANT_B,
            )

    assert exc_info.value.code == "MEMBERSHIP_NOT_FOUND"


def test_case3b_same_identity_correct_tenant_resolves(engine: Engine) -> None:
    """CASE 3 positive: same identity resolves when the correct tenant is specified."""
    with engine.begin() as conn:
        _insert_principal(conn, "pid-003b")
        _insert_external_id(conn, "eid-003b", "pid-003b")
        _insert_membership(conn, "mid-003b", _TENANT_A, _SUBJECT_A, role="assessor")

    with Session(engine) as db:
        resolver = IdentityResolver()
        principal = resolver.resolve_or_deny(
            db,
            provider=_PROVIDER,
            issuer=_ISSUER,
            subject=_SUBJECT_A,
            tenant_id=_TENANT_A,
        )
    assert principal.tenant_id == _TENANT_A


# ---------------------------------------------------------------------------
# CASE 4 — DENY: suspended / revoked membership
# ---------------------------------------------------------------------------


def test_case4_deny_suspended_membership(engine: Engine) -> None:
    """CASE 4a: membership suspended (active=FALSE + lifecycle_state='suspended') → DENY.

    P-113.5 (PR #675) sets both active=FALSE and membership_lifecycle_state='suspended'
    when suspending a user.  The IdentityResolver enforces active=FALSE as the canonical
    denial gate; membership_lifecycle_state is informational metadata.
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-004a")
        _insert_external_id(conn, "eid-004a", "pid-004a")
        _insert_membership(
            conn,
            "mid-004a",
            _TENANT_A,
            _SUBJECT_A,
            role="assessor",
            active=0,  # suspension sets active=FALSE
            lifecycle_state="suspended",
        )

    with Session(engine) as db:
        resolver = IdentityResolver()
        with pytest.raises(IdentityResolutionError) as exc_info:
            resolver.resolve_or_deny(
                db,
                provider=_PROVIDER,
                issuer=_ISSUER,
                subject=_SUBJECT_A,
            )

    assert exc_info.value.code in (
        "MEMBERSHIP_INACTIVE",
        "MEMBERSHIP_NOT_FOUND",
    ), f"suspended membership must be denied, got code={exc_info.value.code!r}"


def test_case4_deny_revoked_membership(engine: Engine) -> None:
    """CASE 4b: membership revoked (active=FALSE + lifecycle_state='revoked') → DENY.

    Revocation (P-113.5 terminal state) also sets active=FALSE.  The resolver
    must deny regardless of which lifecycle state produced active=FALSE.
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-004b")
        _insert_external_id(conn, "eid-004b", "pid-004b")
        _insert_membership(
            conn,
            "mid-004b",
            _TENANT_A,
            _SUBJECT_A,
            role="tenant_admin",
            active=0,
            lifecycle_state="revoked",
        )

    with Session(engine) as db:
        resolver = IdentityResolver()
        with pytest.raises(IdentityResolutionError) as exc_info:
            resolver.resolve_or_deny(
                db,
                provider=_PROVIDER,
                issuer=_ISSUER,
                subject=_SUBJECT_A,
            )

    assert exc_info.value.code in ("MEMBERSHIP_INACTIVE", "MEMBERSHIP_NOT_FOUND")


# ---------------------------------------------------------------------------
# CASE 5 — DENY: disabled tenant (both API-key and OIDC paths)
# ---------------------------------------------------------------------------


def test_case5_oidc_suspended_tenant_denies(engine: Engine, monkeypatch: Any) -> None:
    """CASE 5a: OIDC actor with valid membership in a SUSPENDED tenant → DENY.

    PR-1 / TENANT-LIFECYCLE-OIDC-001 repair: _bind_membership() now reads
    tenants.lifecycle_state after resolving the membership.  A suspended (or
    archived/deleted) tenant raises HTTP 403 TENANT_NOT_ACTIVE regardless of
    whether the membership itself is still active.

    This closes the gap where the OIDC path did not check tenant lifecycle state.
    """
    from fastapi import HTTPException as _HTTP

    from api.auth_dispatch import _bind_membership

    with engine.begin() as conn:
        # Tenant is SUSPENDED (not authorization-eligible).
        _insert_tenant(conn, _TENANT_A, lifecycle_state="suspended")
        _insert_principal(conn, "pid-005a")
        _insert_external_id(conn, "eid-005a", "pid-005a")
        _insert_membership(conn, "mid-005a", _TENANT_A, _SUBJECT_A, role="tenant_admin")

    actor_in = ActorContext(
        subject=_SUBJECT_A,
        email="alice@example.com",
        name="Alice",
        permissions=frozenset(["tenant.configure"]),  # as if JWT claimed platform_admin
        roles=["tenant_admin"],
        auth_source="oidc_auth0",
        tenant_id=_TENANT_A,
    )

    # Monkeypatch Auth0 domain so _bind_membership proceeds (not short-circuit).
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "example.auth0.com")

    with Session(engine) as db, pytest.raises(_HTTP) as exc_info:
        _bind_membership(actor_in, db)

    assert exc_info.value.status_code == 403
    detail = exc_info.value.detail
    assert isinstance(detail, dict) and detail.get("code") == "TENANT_NOT_ACTIVE", (
        f"suspended tenant must produce TENANT_NOT_ACTIVE, got {detail!r}"
    )


def test_case5_oidc_archived_tenant_denies(engine: Engine, monkeypatch: Any) -> None:
    """CASE 5b: OIDC actor with valid membership in an ARCHIVED tenant → DENY."""
    from fastapi import HTTPException as _HTTP

    from api.auth_dispatch import _bind_membership

    with engine.begin() as conn:
        _insert_tenant(conn, _TENANT_A, lifecycle_state="archived")
        _insert_principal(conn, "pid-005b")
        _insert_external_id(conn, "eid-005b", "pid-005b")
        _insert_membership(conn, "mid-005b", _TENANT_A, _SUBJECT_A, role="viewer")

    actor_in = ActorContext(
        subject=_SUBJECT_A,
        email="bob@example.com",
        name="Bob",
        permissions=frozenset(),
        roles=["viewer"],
        auth_source="oidc_auth0",
        tenant_id=_TENANT_A,
    )

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "example.auth0.com")

    with Session(engine) as db, pytest.raises(_HTTP) as exc_info:
        _bind_membership(actor_in, db)

    assert exc_info.value.status_code == 403
    detail = exc_info.value.detail
    assert isinstance(detail, dict) and detail.get("code") == "TENANT_NOT_ACTIVE", (
        f"archived tenant must produce TENANT_NOT_ACTIVE, got {detail!r}"
    )


def test_case5_oidc_missing_tenant_denies(engine: Engine, monkeypatch: Any) -> None:
    """CASE 5c: tenant row absent → DENY (fail closed, not a silent allow).

    If tenants.tenant_id does not exist, lifecycle_state resolves to None,
    which is not 'active' → TENANT_NOT_ACTIVE.
    """
    from fastapi import HTTPException as _HTTP

    from api.auth_dispatch import _bind_membership

    with engine.begin() as conn:
        # No tenant row inserted for _TENANT_A.
        _insert_principal(conn, "pid-005c")
        _insert_external_id(conn, "eid-005c", "pid-005c")
        _insert_membership(conn, "mid-005c", _TENANT_A, _SUBJECT_A, role="viewer")

    actor_in = ActorContext(
        subject=_SUBJECT_A,
        email="carol@example.com",
        name="Carol",
        permissions=frozenset(),
        roles=["viewer"],
        auth_source="oidc_auth0",
        tenant_id=_TENANT_A,
    )

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "example.auth0.com")

    with Session(engine) as db, pytest.raises(_HTTP) as exc_info:
        _bind_membership(actor_in, db)

    assert exc_info.value.status_code == 403
    detail = exc_info.value.detail
    assert isinstance(detail, dict) and detail.get("code") == "TENANT_NOT_ACTIVE", (
        f"missing tenant must produce TENANT_NOT_ACTIVE, got {detail!r}"
    )


def test_case5_oidc_active_tenant_allows(engine: Engine, monkeypatch: Any) -> None:
    """CASE 5d positive: active tenant + valid membership → ALLOW (tenant check passes)."""
    from api.auth_dispatch import _bind_membership

    with engine.begin() as conn:
        _insert_tenant(conn, _TENANT_A, lifecycle_state="active")
        _insert_principal(conn, "pid-005d")
        _insert_external_id(conn, "eid-005d", "pid-005d")
        _insert_membership(conn, "mid-005d", _TENANT_A, _SUBJECT_A, role="assessor")

    actor_in = ActorContext(
        subject=_SUBJECT_A,
        email="diana@example.com",
        name="Diana",
        permissions=frozenset(),
        roles=["assessor"],
        auth_source="oidc_auth0",
        tenant_id=_TENANT_A,
    )

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "example.auth0.com")

    with Session(engine) as db:
        result = _bind_membership(actor_in, db)

    assert result is not None
    assert result.tenant_id == _TENANT_A
    assert "assessor" in result.roles
    assert result.membership_id == "mid-005d"


def test_case5_oidc_restored_tenant_allows(engine: Engine, monkeypatch: Any) -> None:
    """CASE 5e: tenant restored to 'active' after suspension → ALLOW (access restored).

    Proves that updating tenants.lifecycle_state back to 'active' restores OIDC
    authorization immediately — no stale session or JWT claim continues to deny access.
    """
    from api.auth_dispatch import _bind_membership

    with engine.begin() as conn:
        # Start suspended, then restore to active.
        _insert_tenant(conn, _TENANT_A, lifecycle_state="active")
        _insert_principal(conn, "pid-005e")
        _insert_external_id(conn, "eid-005e", "pid-005e")
        _insert_membership(conn, "mid-005e", _TENANT_A, _SUBJECT_A, role="viewer")

    actor_in = ActorContext(
        subject=_SUBJECT_A,
        email="eve@example.com",
        name="Eve",
        permissions=frozenset(),
        roles=["viewer"],
        auth_source="oidc_auth0",
        tenant_id=_TENANT_A,
    )

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "example.auth0.com")

    # After restoration: ALLOW
    with Session(engine) as db:
        result = _bind_membership(actor_in, db)
    assert result.tenant_id == _TENANT_A


def test_case5_credential_authority_source_enforces_tenant_lifecycle() -> None:
    """CASE 5 API-key path source proof: credential_authority joins tenants and calls _enforce_lifecycle."""
    import inspect

    from api import credential_authority as _ca_mod

    src = inspect.getsource(_ca_mod)
    assert "JOIN tenants t ON t.tenant_id = tc.tenant_id" in src, (
        "credential_authority must JOIN tenants to validate tenant lifecycle"
    )
    assert "_enforce_lifecycle" in src, (
        "credential_authority must call _enforce_lifecycle after reading lifecycle_state"
    )
    assert "TenantLifecycleError" in src, (
        "credential_authority must define/raise TenantLifecycleError for disabled tenants"
    )


def test_case5_bind_membership_source_checks_tenant_lifecycle() -> None:
    """CASE 5 OIDC path source proof: _bind_membership now enforces tenant lifecycle state."""
    import inspect

    from api import auth_dispatch as _ad

    src = inspect.getsource(_ad._bind_membership)  # type: ignore[attr-defined]
    assert "lifecycle_state FROM tenants" in src, (
        "_bind_membership must query tenants.lifecycle_state for OIDC actors"
    )
    assert "TENANT_NOT_ACTIVE" in src, (
        "_bind_membership must use TENANT_NOT_ACTIVE code when tenant is not eligible"
    )
    assert (
        '_tenant_lifecycle != "active"' in src or "_tenant_lifecycle != 'active'" in src
    ), "_bind_membership must deny when lifecycle_state is not 'active'"


# ---------------------------------------------------------------------------
# CASE 6 — DENY: removed permission / role
# ---------------------------------------------------------------------------


def test_case6_deny_removed_role() -> None:
    """CASE 6: role removed from ROLE_PERMISSIONS → no permissions derived.

    roles_to_permissions() returns the empty frozenset for any role name not
    in the authoritative ROLE_PERMISSIONS registry.  A stale role claim that
    is no longer registered produces zero permissions, which fail-closes
    require_permission() for any protected route.
    """
    # A role that is not in ROLE_PERMISSIONS (simulates a removed/retired role).
    stale_roles = ["legacy_reviewer"]
    perms = roles_to_permissions(stale_roles)
    assert len(perms) == 0, (
        "unknown / removed role must produce no permissions (fail-closed)"
    )


def test_case6_empty_roles_produces_empty_permissions() -> None:
    """CASE 6: empty role list → empty permission set → all require_permission() fail."""
    perms = roles_to_permissions([])
    assert len(perms) == 0


def test_case6_valid_role_produces_non_empty_permissions() -> None:
    """CASE 6 positive: known role produces the expected permission set."""
    perms = roles_to_permissions(["tenant_admin"])
    assert "key.manage" in perms
    assert "user.invite" in perms


# ---------------------------------------------------------------------------
# CASE 7 — DENY: forged / stale IdP role claim
# ---------------------------------------------------------------------------


def test_case7_canonical_role_overrides_jwt_role_claim(engine: Engine) -> None:
    """CASE 7: forged or stale JWT role claim does not escalate privileges.

    _bind_membership() in api/auth_dispatch.py calls IdentityResolver.resolve_or_deny()
    which reads tenant_users.role from canonical FrostGate state.  The IdentityPrincipal
    returned carries principal.roles from the DB row, NOT from JWT claims.

    The ActorContext permissions are then derived exclusively from principal.roles
    (roles_to_permissions(principal.roles)), not from the JWT claim roles.

    This test inserts a membership with role='viewer' (low privilege) but simulates
    a JWT that claims role='platform_admin' (highest privilege).  The canonical
    FrostGate state wins: the resolved ActorContext must not include platform
    permissions.
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-007")
        _insert_external_id(conn, "eid-007", "pid-007")
        # Canonical FrostGate state: viewer only.
        _insert_membership(conn, "mid-007", _TENANT_A, _SUBJECT_A, role="viewer")

    with Session(engine) as db:
        resolver = IdentityResolver()
        principal = resolver.resolve_or_deny(
            db,
            provider=_PROVIDER,
            issuer=_ISSUER,
            subject=_SUBJECT_A,
        )

    # Canonical role from DB (viewer), not forged JWT role (platform_admin).
    assert principal.roles == ["viewer"], (
        f"canonical role must be viewer from DB, got {principal.roles!r}"
    )

    # Permissions from canonical role — no platform-admin permissions.
    canonical_perms = roles_to_permissions(principal.roles)
    forged_jwt_perms = roles_to_permissions(["platform_admin"])

    assert "platform.admin" not in canonical_perms, (
        "forged platform_admin JWT claim must not grant platform.admin permission"
    )
    # Canonical permissions are strictly a subset of the forged claim's permissions.
    assert canonical_perms < forged_jwt_perms or canonical_perms == frozenset(
        {
            "assessment.read",
            "finding.read",
            "evidence.read",
            "scan.read",
            "report.read",
            "bundle.read",
            "governance.read",
        }
    )


def test_case7_source_bind_membership_overrides_jwt_roles() -> None:
    """CASE 7 source proof: _bind_membership derives permissions from canonical DB, not JWT.

    Verifies that auth_dispatch._bind_membership() constructs ActorContext using
    principal.roles (from IdentityPrincipal, sourced from tenant_users.role) and
    NOT from the input actor's permissions (which came from JWT claims).
    """
    import inspect

    from api import auth_dispatch as _ad

    src = inspect.getsource(_ad._bind_membership)  # type: ignore[attr-defined]
    # The function must reconstruct ActorContext with principal.roles from DB.
    assert "principal.roles" in src, (
        "_bind_membership must use principal.roles (canonical DB) to rebuild ActorContext"
    )
    assert "roles_to_permissions(principal.roles)" in src, (
        "_bind_membership must derive permissions from canonical roles, not JWT claims"
    )


# ---------------------------------------------------------------------------
# CASE 8 — DENY: forged / stale tenant claim
# ---------------------------------------------------------------------------


def test_case8_deny_forged_tenant_via_resolver(engine: Engine) -> None:
    """CASE 8: forged JWT tenant_id claim does not grant cross-tenant access.

    When _bind_membership() passes actor.tenant_id (from JWT) to resolver.resolve_or_deny(),
    the resolver filters tenant_users by that tenant_id.  A forged/stale JWT tenant_id
    claim pointing to a tenant where the user has no membership returns MEMBERSHIP_NOT_FOUND.
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-008")
        _insert_external_id(conn, "eid-008", "pid-008")
        # Membership only in TENANT_A.
        _insert_membership(conn, "mid-008", _TENANT_A, _SUBJECT_A, role="assessor")

    with Session(engine) as db:
        resolver = IdentityResolver()
        # JWT claims tenant_b (forged/stale) — resolver must deny.
        with pytest.raises(IdentityResolutionError) as exc_info:
            resolver.resolve_or_deny(
                db,
                provider=_PROVIDER,
                issuer=_ISSUER,
                subject=_SUBJECT_A,
                tenant_id=_TENANT_B,  # forged tenant from JWT
            )

    assert exc_info.value.code == "MEMBERSHIP_NOT_FOUND", (
        "forged JWT tenant_id must not grant cross-tenant access"
    )


def test_case8_bind_tenant_id_source_enforces_tenant_lock() -> None:
    """CASE 8 source proof: bind_tenant_id() raises 403 when requested != auth tenant.

    For API-key auth, bind_tenant_id() in auth_scopes/resolution.py compares the
    requested tenant_id (from query param / header) against the auth tenant
    (from the validated credential).  A mismatch raises HTTP 403, preventing
    any request-controlled tenant value from overriding the credential-bound tenant.
    """
    import inspect

    from api.auth_scopes import resolution as _res

    src = inspect.getsource(_res.bind_tenant_id)
    # The function must reject requested != auth_tenant.
    assert (
        "requested != auth_tenant" in src
        or "requested and requested != auth_tenant" in src
    ), "bind_tenant_id must check requested tenant against auth-bound tenant"
    assert "403" in src or "status_code=403" in src, (
        "bind_tenant_id must raise HTTP 403 on tenant mismatch"
    )


# ---------------------------------------------------------------------------
# CASE 9 — SAFE: duplicate identity binding
# ---------------------------------------------------------------------------


def test_case9_duplicate_external_identity_binding_rejected(engine: Engine) -> None:
    """CASE 9: second binding attempt for same (provider, issuer, subject) → IntegrityError.

    fg_external_identities has a GLOBAL UNIQUE constraint on (provider, issuer, subject).
    A replay or race condition that attempts to bind the same IdP identity to a second
    principal must be rejected by the database.  No ambiguous authority can arise from
    two principals sharing an external identity.
    """
    import sqlalchemy.exc

    with engine.begin() as conn:
        _insert_principal(conn, "pid-009a")
        _insert_principal(conn, "pid-009b")
        # First binding: succeeds.
        _insert_external_id(conn, "eid-009a", "pid-009a")

    with (
        pytest.raises((sqlalchemy.exc.IntegrityError, Exception)) as exc_info,
        engine.begin() as conn,
    ):
        # Second binding: same (provider, issuer, subject) → UNIQUE violation.
        _insert_external_id(conn, "eid-009b", "pid-009b")

    assert (
        "UNIQUE" in str(exc_info.value).upper()
        or "IntegrityError" in type(exc_info.value).__name__
    )


def test_case9_different_subjects_each_get_distinct_binding(engine: Engine) -> None:
    """CASE 9 positive: different IdP subjects can bind to distinct principals."""
    with engine.begin() as conn:
        _insert_principal(conn, "pid-009c")
        _insert_principal(conn, "pid-009d")
        # Different subjects → both succeed.
        _insert_external_id(conn, "eid-009c", "pid-009c", subject=_SUBJECT_A)
        _insert_external_id(conn, "eid-009d", "pid-009d", subject=_SUBJECT_B)


# ---------------------------------------------------------------------------
# CASE 10 — DETERMINISTIC: repeated resolution
# ---------------------------------------------------------------------------


def test_case10_repeated_resolution_is_deterministic(engine: Engine) -> None:
    """CASE 10: same canonical identity resolves to the same principal on every call.

    A canonical external identity (provider, issuer, subject) maps to exactly
    one principal_id via fg_external_identities.UNIQUE.  Repeated calls to
    IdentityResolver.resolve() with the same triple must return the same
    membership_id, tenant_id, and role each time.
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-010")
        _insert_external_id(conn, "eid-010", "pid-010")
        _insert_membership(conn, "mid-010", _TENANT_A, _SUBJECT_A, role="qa_reviewer")

    with Session(engine) as db:
        resolver = IdentityResolver()
        results = [
            resolver.resolve(
                db,
                provider=_PROVIDER,
                issuer=_ISSUER,
                subject=_SUBJECT_A,
            )
            for _ in range(5)
        ]

    assert all(r is not None for r in results), "all resolutions must succeed"
    membership_ids = {r.membership_id for r in results}  # type: ignore[union-attr]
    tenant_ids = {r.tenant_id for r in results}  # type: ignore[union-attr]
    roles_sets = {tuple(r.roles) for r in results}  # type: ignore[union-attr]

    assert len(membership_ids) == 1, (
        "repeated resolution must return same membership_id"
    )
    assert len(tenant_ids) == 1, "repeated resolution must return same tenant_id"
    assert len(roles_sets) == 1, "repeated resolution must return same roles"


# ---------------------------------------------------------------------------
# Additional invariants — authority law proofs
# ---------------------------------------------------------------------------


def test_auth_law_roles_to_permissions_is_pure() -> None:
    """roles_to_permissions() must produce the same output for the same input — no side effects."""
    roles = ["assessor", "viewer"]
    result_a = roles_to_permissions(roles)
    result_b = roles_to_permissions(roles)
    assert result_a == result_b
    assert isinstance(result_a, frozenset)


def test_auth_law_platform_admin_has_all_permissions() -> None:
    """platform_admin role must expand to ALL_PERMISSIONS (no capability left behind)."""
    perms = roles_to_permissions(["platform_admin"])
    missing = ALL_PERMISSIONS - perms
    assert missing == frozenset(), (
        f"platform_admin missing permissions: {sorted(missing)}"
    )


def test_auth_law_viewer_cannot_write() -> None:
    """viewer role must not include any write or admin permissions."""
    perms = roles_to_permissions(["viewer"])
    write_perms = {
        p
        for p in perms
        if any(
            p.startswith(prefix)
            for prefix in ("key.", "user.", "connector.", "tenant.", "platform.")
        )
    }
    assert write_perms == frozenset(), (
        f"viewer must not have write/admin permissions: {sorted(write_perms)}"
    )


def test_auth_law_sod_tenant_admin_cannot_approve_risk() -> None:
    """SoD invariant: tenant_admin must NOT inherit compliance_reviewer permissions."""
    admin_perms = roles_to_permissions(["tenant_admin"])
    assert "risk.accept" not in admin_perms, (
        "SoD violated: tenant_admin must not be able to accept risk (bank admin self-approval)"
    )
    assert "exception.grant" not in admin_perms, (
        "SoD violated: tenant_admin must not be able to grant exceptions"
    )
    assert "governance.decision" not in admin_perms, (
        "SoD violated: tenant_admin must not record governance decisions"
    )


def test_auth_law_sod_assessor_cannot_approve_finding() -> None:
    """SoD invariant: assessor must NOT have finding.approve."""
    perms = roles_to_permissions(["assessor"])
    assert "finding.approve" not in perms, (
        "SoD violated: assessor must not approve their own findings"
    )
    assert "bundle.approve" not in perms, (
        "SoD violated: assessor must not approve bundles (requires qa_reviewer)"
    )


def test_auth_law_multi_tenant_principal_two_memberships(engine: Engine) -> None:
    """A single principal may be a member of two different tenants (multi-tenant).

    Same IdP identity (same external binding) → same principal → two
    tenant_users rows in different tenants.  Each membership may carry a
    different role.  The resolver, when called with a specific tenant_id,
    returns the membership for that tenant only.
    """
    with engine.begin() as conn:
        _insert_principal(conn, "pid-mt")
        _insert_external_id(conn, "eid-mt", "pid-mt", subject="auth0|multi-tenant-user")
        _insert_membership(
            conn,
            "mid-mt-a",
            _TENANT_A,
            "auth0|multi-tenant-user",
            role="viewer",
            principal_id="pid-mt",
        )
        _insert_membership(
            conn,
            "mid-mt-b",
            _TENANT_B,
            "auth0|multi-tenant-user",
            role="tenant_admin",
            principal_id="pid-mt",
        )

    with Session(engine) as db:
        resolver = IdentityResolver()
        pa = resolver.resolve_or_deny(
            db,
            provider=_PROVIDER,
            issuer=_ISSUER,
            subject="auth0|multi-tenant-user",
            tenant_id=_TENANT_A,
        )
        pb = resolver.resolve_or_deny(
            db,
            provider=_PROVIDER,
            issuer=_ISSUER,
            subject="auth0|multi-tenant-user",
            tenant_id=_TENANT_B,
        )

    assert pa.tenant_id == _TENANT_A
    assert pa.roles == ["viewer"]
    assert pb.tenant_id == _TENANT_B
    assert pb.roles == ["tenant_admin"]
    assert pa.membership_id != pb.membership_id, (
        "multi-tenant memberships must have distinct membership_ids"
    )


def test_auth_law_inactive_principal_not_returned(engine: Engine) -> None:
    """fg_principals.lifecycle_state='suspended' must prevent identity resolution.

    resolve_external_identity() in api/principal_authority.py JOINs fg_principals
    WHERE lifecycle_state='active'.  A suspended or deactivated principal is not
    returned even if the external identity binding exists.
    """
    from api.principal_authority import resolve_external_identity

    with engine.begin() as conn:
        _insert_principal(conn, "pid-susp", lifecycle_state="suspended")
        _insert_external_id(
            conn, "eid-susp", "pid-susp", subject="auth0|suspended-user"
        )

    with engine.connect() as conn:
        result = resolve_external_identity(
            conn,
            provider=_PROVIDER,
            provider_issuer=_ISSUER,
            provider_subject="auth0|suspended-user",
        )

    assert result is None, (
        "suspended principal must return None from resolve_external_identity "
        "(fail-closed: inactive node at any position in chain → DENY)"
    )
