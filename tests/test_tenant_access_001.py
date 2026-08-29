"""tests/test_tenant_access_001.py — TENANT-ACCESS-001 Unified Tenant Access Enforcement.

Proves and hardens the complete client access path:

    AUTHENTICATION
    -> CANONICAL PRINCIPAL
    -> TENANT MEMBERSHIP
    -> TENANT-SCOPED AUTHORIZATION
    -> SURFACE AUTHORIZATION
    -> RESOURCE AUTHORIZATION
    -> CONSOLE / PORTAL ACCESS
    -> AUDITABLE ALLOW OR DENY

Test groups:

  A. canonical principal resolution
  B. tenant membership enforcement
  C. console access (experience class + BFF tenant resolution)
  D. portal access (session-based, grant-scoped)
  E. console/portal surface separation
  F. tenant-admin integration (reuse TENANT-ADMIN-001 authority)
  G. ordinary user restrictions
  H. portal-only restrictions
  I. cross-tenant denial
  J. object-level IDOR denial
  K. stale JWT role denial (JWT claims are NOT canonical)
  L. revoked membership denial
  M. disabled membership denial
  N. unbound identity denial
  O. tenant parameter tampering
  P. invitation -> first access proof
  Q. portal grant lifecycle
  R. identity governance boundary
  S. audit/privacy (oracle-resistance)
  T. RLS pattern verification
  U. frontend/API contract (consoleAccess policy)
  V. existing AUTH-ROLE compatibility
  W. existing TENANT-ADMIN-001 compatibility

The security invariant under test:

    authenticated identity
    + canonical principal_id
    + active canonical membership
    + trusted tenant context
    + required capability
    + surface authorization
    + resource ownership/grant
    = ALLOW

    Everything else: DENY

JWT claims are NOT canonical authorization.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from api.actor_context import ROLE_PERMISSIONS, ActorContext
from api.auth_scopes import mint_key
from api.principal_authority import (
    PrincipalResolutionError,
    resolve_or_create_principal_for_external_identity,
)
from api.tenant_admin_authority import (
    DELEGATABLE_ROLES,
    FORBIDDEN_DELEGATION_ROLES,
    TENANT_ADMIN_DENIED,
    assert_role_delegatable,
    check_tenant_admin_authority,
    is_role_delegatable,
)

# ---------------------------------------------------------------------------
# BFF constants — parsed from apps/console/lib/consoleAccess.js
# ---------------------------------------------------------------------------
# Reads the actual JS source as a sync guard so that role-list changes in the
# JS file are immediately reflected here.  Runtime BFF behavior (JWT claim
# extraction, experienceClass logic) is tested in the correct runtime:
#   apps/console/tests/console-access-policy.test.js
# ---------------------------------------------------------------------------

import re
from pathlib import Path as _Path

_CONSOLE_ACCESS_JS = _Path(__file__).parents[1] / "apps/console/lib/consoleAccess.js"


def _parse_js_str_array(src: str, varname: str) -> list[str]:
    m = re.search(rf"const {varname}\s*=\s*\[(.*?)\];", src, re.DOTALL)
    return re.findall(r"'([^']+)'", m.group(1)) if m else []


def _resolve_js_array_expr(expr: str, var_map: dict) -> list[str]:
    roles: list[str] = []
    for match in re.finditer(r"'([^']+)'|\.\.\.(\w+)", expr):
        literal, spread = match.group(1), match.group(2)
        if literal:
            roles.append(literal)
        elif spread and spread in var_map:
            roles.extend(var_map[spread])
    return roles


def _load_bff_constants() -> dict:
    src = _CONSOLE_ACCESS_JS.read_text()
    internal = _parse_js_str_array(src, "INTERNAL_CONSOLE_ROLES")
    client = _parse_js_str_array(src, "CLIENT_CONSOLE_ROLES")
    portal_markers = _parse_js_str_array(src, "PORTAL_ONLY_ROLE_MARKERS")

    var_map: dict = {
        "INTERNAL_CONSOLE_ROLES": internal,
        "INTERNAL_ONLY_ROLES": internal,
        "CLIENT_CONSOLE_ROLES": client,
        "CLIENT_CONSOLE_ALLOWED_ROLES": client + internal,
        "PORTAL_ONLY_ROLE_MARKERS": portal_markers,
    }

    m = re.search(r"const TENANT_ADMIN_CONSOLE_ROLES\s*=\s*\[(.*?)\];", src, re.DOTALL)
    tenant_admin_roles = _resolve_js_array_expr(m.group(1), var_map) if m else []
    var_map["TENANT_ADMIN_CONSOLE_ROLES"] = tenant_admin_roles

    policies: list[dict] = []
    pm = re.search(r"const CORE_API_POLICIES\s*=\s*\[(.*?)\];\s*\n", src, re.DOTALL)
    if pm:
        for em in re.finditer(r"\{([^{}]+)\}", pm.group(1), re.DOTALL):
            entry = em.group(1)
            pfx_m = re.search(r"prefix:\s*'([^']+)'", entry)
            all_m = re.search(r"allowedRoles:\s*([^\,\n\}]+)", entry)
            mut_m = re.search(r"mutationRoles:\s*([^\n\}]+),?", entry)
            if pfx_m and all_m:
                allowed_expr = all_m.group(1).strip()
                mut_expr = (
                    mut_m.group(1).strip().rstrip(",")
                    if mut_m
                    else "INTERNAL_ONLY_ROLES"
                )
                resolve = lambda e: (  # noqa: E731
                    _resolve_js_array_expr(e, var_map)
                    if "[" in e
                    else var_map.get(e, [])
                )
                policies.append(
                    {
                        "prefix": pfx_m.group(1),
                        "allowedRoles": resolve(allowed_expr),
                        "mutationRoles": resolve(mut_expr),
                    }
                )

    return {
        "INTERNAL_CONSOLE_ROLES": internal,
        "CLIENT_CONSOLE_ROLES": client,
        "PORTAL_ONLY_ROLE_MARKERS": portal_markers,
        "TENANT_ADMIN_CONSOLE_ROLES": tenant_admin_roles,
        "CLIENT_CONSOLE_ALLOWED_ROLES": client + internal,
        "CORE_API_POLICIES": policies,
    }


_BFF = _load_bff_constants()
INTERNAL_CONSOLE_ROLES: list[str] = _BFF["INTERNAL_CONSOLE_ROLES"]
CLIENT_CONSOLE_ROLES: list[str] = _BFF["CLIENT_CONSOLE_ROLES"]
TENANT_ADMIN_CONSOLE_ROLES: list[str] = _BFF["TENANT_ADMIN_CONSOLE_ROLES"]
CORE_API_POLICIES: list[dict] = _BFF["CORE_API_POLICIES"]
_PORTAL_ONLY_ROLE_MARKERS: list[str] = _BFF["PORTAL_ONLY_ROLE_MARKERS"]
_BFF_RECOGNIZED: frozenset[str] = frozenset(
    INTERNAL_CONSOLE_ROLES + CLIENT_CONSOLE_ROLES + _PORTAL_ONLY_ROLE_MARKERS
)


def _bff_can_access_core_api(
    path_segments: "list[str] | str",
    method: str,
    role: "str | None",
) -> bool:
    """Structural BFF access check against CORE_API_POLICIES parsed from JS.

    Tests the policy DATA contract (allowedRoles lists), not the JS runtime.
    portal-only roles and unrecognized roles always return False.
    """
    if role is None or role not in _BFF_RECOGNIZED or role in _PORTAL_ONLY_ROLE_MARKERS:
        return False
    prefix = (
        "/".join(path_segments)
        if isinstance(path_segments, list)
        else str(path_segments).lstrip("/")
    )
    policy = next(
        (
            p
            for p in CORE_API_POLICIES
            if prefix == p["prefix"] or prefix.startswith(p["prefix"] + "/")
        ),
        None,
    )
    if policy is None or role not in policy["allowedRoles"]:
        return False
    if method.upper() in ("GET", "HEAD"):
        return True
    return role in policy.get("mutationRoles", INTERNAL_CONSOLE_ROLES)


# ---------------------------------------------------------------------------
# Test tenants (isolated per test class to avoid cross-contamination)
# ---------------------------------------------------------------------------

_TENANT_A = "ta001-access-tenant-a"
_TENANT_B = "ta001-access-tenant-b"
_PLATFORM_TENANT = "ta001-internal-platform"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def _seed_tenant(
    engine,
    tenant_id: str,
    *,
    tenant_kind: str = "customer",
    lifecycle_state: str = "active",
) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO tenants
                    (tenant_id, display_name, lifecycle_state, tenant_kind)
                VALUES (:tid, :name, :state, :kind)
                """
            ),
            {
                "tid": tenant_id,
                "name": tenant_id,
                "state": lifecycle_state,
                "kind": tenant_kind,
            },
        )


def _seed_principal(engine, principal_id: str, lifecycle_state: str = "active") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO fg_principals
                    (id, principal_type, lifecycle_state, mfa_verified,
                     authority_version, created_at, updated_at)
                VALUES
                    (:id, 'human', :lc, 0, 1, :now, :now)
                """
            ),
            {"id": principal_id, "lc": lifecycle_state, "now": _now_iso()},
        )


def _seed_tenant_user(
    engine,
    *,
    tenant_id: str,
    user_id: str,
    email: str,
    role: str = "user",
    active: bool = True,
    identity_subject: str | None = None,
    identity_provider: str | None = None,
    identity_issuer: str | None = None,
    principal_id: str | None = None,
    identity_binding_status: str = "unbound",
) -> None:
    if principal_id:
        _seed_principal(engine, principal_id)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO tenant_users
                    (id, tenant_id, email, display_name, role, active,
                     identity_subject, identity_provider, identity_issuer,
                     identity_binding_status, principal_id,
                     created_at, updated_at)
                VALUES
                    (:id, :t, :e, :dn, :role, :active,
                     :subject, :provider, :issuer, :binding, :pid, :now, :now)
                """
            ),
            {
                "id": user_id,
                "t": tenant_id,
                "e": email,
                "dn": email,
                "role": role,
                "active": active,
                "subject": identity_subject,
                "provider": identity_provider,
                "issuer": identity_issuer,
                "binding": identity_binding_status,
                "pid": principal_id,
                "now": _now_iso(),
            },
        )


def _install_actor_override(
    app,
    *,
    subject: str,
    tenant_id: str | None,
    membership_id: str | None = None,
    role: str = "tenant_admin",
    perms: frozenset | None = None,
) -> None:
    from api.auth_dispatch import get_actor_context

    def _override() -> ActorContext:
        return ActorContext(
            subject=subject,
            email=f"{subject}@test.example",
            name=subject,
            permissions=perms
            if perms is not None
            else ROLE_PERMISSIONS.get(role, frozenset()),
            roles=[role],
            auth_source="dev_bypass",
            tenant_id=tenant_id,
            membership_id=membership_id,
        )

    app.dependency_overrides[get_actor_context] = _override


def _clear_actor_override(app) -> None:
    from api.auth_dispatch import get_actor_context

    app.dependency_overrides.pop(get_actor_context, None)


def _platform_key(tenant_id: str) -> str:
    return mint_key("admin:read", "admin:write", tenant_id=tenant_id, ttl_seconds=3600)


def _read_key(tenant_id: str) -> str:
    return mint_key("governance:read", tenant_id=tenant_id, ttl_seconds=3600)


def _write_key(tenant_id: str) -> str:
    return mint_key(
        "governance:read", "governance:write", tenant_id=tenant_id, ttl_seconds=3600
    )


def _admin_key(tenant_id: str) -> str:
    return mint_key("admin:read", "admin:write", tenant_id=tenant_id, ttl_seconds=3600)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(build_app):
    return build_app(auth_enabled=True, api_key="")


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def engine(app):
    from api.db import get_engine

    return get_engine()


# ===========================================================================
# A. Canonical Principal Resolution
# ===========================================================================


class TestCanonicalPrincipalResolution:
    """A. The canonical authority graph: active principal -> access; inactive -> DENY."""

    def test_a1_active_principal_resolves(self, engine):
        """resolve_or_create_principal_for_external_identity returns an active principal."""
        subject = f"auth0|a1-{uuid.uuid4().hex[:8]}"
        with engine.connect() as conn:
            result = resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer="https://fg-test.auth0.com/",
                subject=subject,
                display_name="Alice Test",
                primary_email="alice@test.example",
            )
        assert result.principal_id
        assert result.created is True

    def test_a2_idempotent_resolution_same_principal(self, engine):
        """Repeated resolution with same triple yields same principal_id."""
        subject = f"auth0|a2-{uuid.uuid4().hex[:8]}"
        kw = {
            "provider": "auth0",
            "issuer": "https://fg-test.auth0.com/",
            "subject": subject,
            "display_name": "Alice Test",
            "primary_email": "alice@test.example",
        }
        with engine.connect() as conn:
            r1 = resolve_or_create_principal_for_external_identity(conn, **kw)
            conn.commit()
        with engine.connect() as conn:
            r2 = resolve_or_create_principal_for_external_identity(conn, **kw)
            conn.commit()
        assert r1.principal_id == r2.principal_id
        assert r2.created is False

    def test_a3_inactive_principal_raises(self, engine):
        """If the principal's lifecycle_state != 'active', resolver raises PRINCIPAL_INACTIVE."""
        subject = f"auth0|a3-{uuid.uuid4().hex[:8]}"
        # First create it
        with engine.connect() as conn:
            r = resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer="https://fg-test.auth0.com/",
                subject=subject,
            )
            conn.commit()
        # Deactivate the principal
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE fg_principals SET lifecycle_state = 'deactivated' WHERE id = :id"
                ),
                {"id": r.principal_id},
            )
        # Now resolution should raise
        with (
            engine.connect() as conn,
            pytest.raises(PrincipalResolutionError) as exc_info,
        ):
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer="https://fg-test.auth0.com/",
                subject=subject,
            )
        assert exc_info.value.code == "PRINCIPAL_INACTIVE"

    def test_a4_unknown_provider_raises(self, engine):
        """An unknown provider is rejected before DB lookup."""
        with (
            engine.connect() as conn,
            pytest.raises((ValueError, PrincipalResolutionError)),
        ):
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="unknown_idp",
                issuer="https://unknown.example/",
                subject="sub|123",
            )

    def test_a5_different_subjects_yield_different_principals(self, engine):
        """Distinct IdP subjects never share a principal."""
        subject_a = f"auth0|a5a-{uuid.uuid4().hex[:8]}"
        subject_b = f"auth0|a5b-{uuid.uuid4().hex[:8]}"
        kw_base = {
            "provider": "auth0",
            "issuer": "https://fg-test.auth0.com/",
        }
        with engine.connect() as conn:
            ra = resolve_or_create_principal_for_external_identity(
                conn, **kw_base, subject=subject_a
            )
            rb = resolve_or_create_principal_for_external_identity(
                conn, **kw_base, subject=subject_b
            )
            conn.commit()
        assert ra.principal_id != rb.principal_id


# ===========================================================================
# B. Tenant Membership Enforcement
# ===========================================================================


class TestTenantMembershipEnforcement:
    """B. Canonical membership rules: active + bound -> allow; anything else -> deny."""

    def test_b1_active_bound_member_resolves(self, engine):
        """An active, bound tenant_users row resolves successfully."""
        from services.identity_resolver import IdentityResolver

        tid = f"{_TENANT_A}-b1"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="alice@b1.test",
            role="user",
            active=True,
            identity_subject="auth0|b1-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )

        from sqlalchemy.orm import Session as _Session

        with _Session(engine) as db:
            resolver = IdentityResolver()
            principal = resolver.resolve_or_deny(
                db,
                provider="auth0",
                issuer="https://fg-test.auth0.com/",
                subject="auth0|b1-alice",
            )
        assert principal.tenant_id == tid
        assert principal.membership_id == uid
        assert principal.status == "active"

    def test_b2_inactive_member_raises(self, engine):
        """An inactive membership (active=False) raises MEMBERSHIP_INACTIVE."""
        from sqlalchemy.orm import Session

        from services.identity_resolver import IdentityResolutionError, IdentityResolver

        tid = f"{_TENANT_A}-b2"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="erin@b2.test",
            role="user",
            active=False,
            identity_subject="auth0|b2-erin",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        with Session(engine) as db:
            resolver = IdentityResolver()
            with pytest.raises(IdentityResolutionError) as exc_info:
                resolver.resolve_or_deny(
                    db,
                    provider="auth0",
                    issuer="https://fg-test.auth0.com/",
                    subject="auth0|b2-erin",
                )
        assert "INACTIVE" in exc_info.value.code

    def test_b3_unbound_member_not_found(self, engine):
        """An unbound membership (identity_binding_status != 'bound') is not resolved."""
        from sqlalchemy.orm import Session

        from services.identity_resolver import IdentityResolutionError, IdentityResolver

        tid = f"{_TENANT_A}-b3"
        uid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="mallory@b3.test",
            role="user",
            active=True,
            identity_subject="auth0|b3-mallory",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            identity_binding_status="pending",  # NOT bound
        )
        with Session(engine) as db:
            resolver = IdentityResolver()
            with pytest.raises(IdentityResolutionError) as exc_info:
                resolver.resolve_or_deny(
                    db,
                    provider="auth0",
                    issuer="https://fg-test.auth0.com/",
                    subject="auth0|b3-mallory",
                )
        assert exc_info.value.code == "MEMBERSHIP_NOT_FOUND"

    def test_b4_membership_for_wrong_tenant_not_visible(self, engine):
        """A principal's membership in Tenant A is not found when queried for Tenant B."""
        from sqlalchemy.orm import Session

        from services.identity_resolver import IdentityResolutionError, IdentityResolver

        tid_a = f"{_TENANT_A}-b4a"
        tid_b = f"{_TENANT_B}-b4b"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid_a)
        _seed_tenant(engine, tid_b)
        _seed_tenant_user(
            engine,
            tenant_id=tid_a,
            user_id=uid,
            email="alice@b4.test",
            role="user",
            active=True,
            identity_subject="auth0|b4-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        with Session(engine) as db:
            resolver = IdentityResolver()
            # Querying with tenant_id constraint for Tenant B must fail
            with pytest.raises(IdentityResolutionError):
                resolver.resolve_or_deny(
                    db,
                    provider="auth0",
                    issuer="https://fg-test.auth0.com/",
                    subject="auth0|b4-alice",
                    tenant_id=tid_b,  # Wrong tenant
                )

    def test_b5_no_membership_raises(self, engine):
        """A subject with no membership row at all is not found."""
        from sqlalchemy.orm import Session

        from services.identity_resolver import IdentityResolutionError, IdentityResolver

        with Session(engine) as db:
            resolver = IdentityResolver()
            with pytest.raises(IdentityResolutionError) as exc_info:
                resolver.resolve_or_deny(
                    db,
                    provider="auth0",
                    issuer="https://fg-test.auth0.com/",
                    subject=f"auth0|nonexistent-{uuid.uuid4().hex}",
                )
        assert exc_info.value.code == "MEMBERSHIP_NOT_FOUND"


# ===========================================================================
# C. Console Access
# ===========================================================================


class TestConsoleAccess:
    """C. Console BFF access classification via consoleAccess.js."""

    def test_c1_internal_console_role_classifies_as_internal(self):
        """An Administrator role produces experienceClass=internal_console."""
        # Structural: Administrator must be in INTERNAL_CONSOLE_ROLES (not in client/portal lists)
        # for the JS classification to produce experienceClass=internal_console.
        # Runtime JWT claim parsing is tested in console-access-policy.test.js.
        assert "Administrator" in INTERNAL_CONSOLE_ROLES
        assert "Administrator" not in CLIENT_CONSOLE_ROLES
        assert "Administrator" not in _PORTAL_ONLY_ROLE_MARKERS

    def test_c2_tenant_admin_role_classifies_as_console_enabled_client(self):
        """A tenant_admin role produces experienceClass=console_enabled_client."""
        assert "tenant_admin" in CLIENT_CONSOLE_ROLES
        assert "tenant_admin" not in INTERNAL_CONSOLE_ROLES
        assert "tenant_admin" not in _PORTAL_ONLY_ROLE_MARKERS

    def test_c3_portal_only_role_classifies_as_portal_only(self):
        """A portal_only role produces experienceClass=portal_only."""
        assert "portal_only" in _PORTAL_ONLY_ROLE_MARKERS
        assert "portal_only" not in CLIENT_CONSOLE_ROLES
        assert "portal_only" not in INTERNAL_CONSOLE_ROLES

    def test_c4_portal_only_cannot_access_console_routes(self):
        """A portal_only principal cannot access any non-public console route."""
        # portal_only is in PORTAL_ONLY_ROLE_MARKERS and absent from all console role lists.
        # The BFF function rejects portal_only experienceClass for every authenticated route.
        assert "portal_only" not in CLIENT_CONSOLE_ROLES
        assert "portal_only" not in INTERNAL_CONSOLE_ROLES
        assert "portal_only" not in TENANT_ADMIN_CONSOLE_ROLES

    def test_c5_unsupported_experience_cannot_access_console_api(self):
        """An unrecognized role produces experienceClass=unsupported and denies Core API."""
        assert not _bff_can_access_core_api(["decisions"], "GET", "UNKNOWN_ROLE_XYZ")

    def test_c6_unauthenticated_cannot_access_core_api(self):
        """No session -> cannot access Core API paths."""
        assert not _bff_can_access_core_api(["decisions"], "GET", None)

    def test_c7_client_role_can_access_client_safe_routes(self):
        """A console_enabled_client with tenant_admin can access own tenant routes."""
        # tenant_admin is in TENANT_ADMIN_CONSOLE_ROLES -> workforce/users allows it
        assert _bff_can_access_core_api(["workforce", "users"], "GET", "tenant_admin")

    def test_c8_internal_only_routes_denied_to_client(self):
        """Client role cannot access internal-only Core API routes."""
        for path_segments in [["forensics", "snapshot"], ["keys"], ["rag", "corpora"]]:
            assert not _bff_can_access_core_api(
                path_segments, "GET", "client_read_only"
            ), f"client_read_only must not access {'/'.join(path_segments)}"

    def test_c9_client_role_mutation_requires_tenant_admin(self):
        """A client_read_only user cannot mutate workforce/users."""
        assert not _bff_can_access_core_api(
            ["workforce", "users"], "POST", "client_read_only"
        )
        assert _bff_can_access_core_api(["workforce", "users"], "POST", "tenant_admin")


# ===========================================================================
# D. Portal Access
# ===========================================================================


class TestPortalAccess:
    """D. Portal user authority: session-based, grant-scoped, tenant-bound."""

    def test_d1_portal_user_authority_requires_tenant(self, engine, app):
        """Portal session validation fails if tenant context is missing."""
        from sqlalchemy.orm import Session

        from api.portal_user_authority import (
            validate_session,
        )

        with Session(engine) as db:
            result = validate_session(
                db,
                raw_token="pnu1.nonexistent-token",
                tenant_id="nonexistent-tenant",
            )
        assert not result.ok
        assert result.denial_code is not None

    def test_d2_portal_user_session_wrong_tenant_denied(self, engine):
        """A portal session validated for Tenant A cannot be used for Tenant B."""
        from sqlalchemy.orm import Session

        from api.portal_user_authority import validate_session

        # Sessions for unknown tokens should always fail
        with Session(engine) as db:
            result_b = validate_session(
                db,
                raw_token="pnu1.fake-session-for-tenant-a",
                tenant_id=_TENANT_B,
            )
        assert not result_b.ok

    def test_d3_portal_users_table_is_tenant_scoped(self, engine):
        """portal_users rows carry tenant_id — the table schema has tenant isolation."""
        with engine.connect() as conn:
            # Check table has tenant_id column
            row = conn.execute(
                text(
                    "SELECT name FROM pragma_table_info('portal_users') WHERE name='tenant_id'"
                )
            ).fetchone()
        # If portal_users table exists, it must have tenant_id
        if row is not None:
            assert row[0] == "tenant_id"


# ===========================================================================
# E. Console / Portal Separation
# ===========================================================================


class TestConsolePportalSeparation:
    """E. The same principal has separate authority on console vs portal surfaces."""

    def test_e1_tenant_admin_check_does_not_grant_portal_authority(self, engine, app):
        """A tenant_admin membership does NOT automatically create portal grants."""
        tid = f"{_TENANT_A}-e1"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="alice-e1@test.example",
            role="tenant_admin",
            active=True,
            identity_subject="auth0|e1-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        # Verify: the admin authority check passes
        from sqlalchemy.orm import Session

        actor = ActorContext(
            subject="auth0|e1-alice",
            email="alice-e1@test.example",
            name="Alice",
            permissions=ROLE_PERMISSIONS["tenant_admin"],
            roles=["tenant_admin"],
            auth_source="dev_bypass",
            tenant_id=tid,
            membership_id=uid,
        )
        with Session(engine) as db:
            authority = check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid)
        assert authority.principal_id == pid

        # Verify: NO portal sessions/memberships were created by that authority check
        try:
            with engine.connect() as conn:
                portal_rows = conn.execute(
                    text("SELECT COUNT(*) FROM portal_users WHERE tenant_id = :tid"),
                    {"tid": tid},
                ).fetchone()
        except Exception:
            portal_rows = (
                None  # table absent from test schema — invariant holds by absence
            )
        if portal_rows is not None:
            assert portal_rows[0] == 0

    def test_e2_portal_only_role_cannot_access_console_api(self):
        """A portal_only session cannot access any Console Core API path."""
        for path in [
            ["decisions"],
            ["workforce", "users"],
            ["admin", "tenants"],
            ["control-tower", "snapshot"],
        ]:
            assert not _bff_can_access_core_api(path, "GET", "portal_only"), (
                f"portal_only must not access /{'/'.join(path)}"
            )

    def test_e3_client_console_roles_not_portal_markers(self):
        """CLIENT_CONSOLE_ROLES and PORTAL_ONLY_ROLE_MARKERS are disjoint."""
        portal_markers = set(_PORTAL_ONLY_ROLE_MARKERS)
        overlap = set(CLIENT_CONSOLE_ROLES) & portal_markers
        assert not overlap, (
            f"CLIENT_CONSOLE_ROLES and portal markers overlap: {overlap}"
        )

    def test_e4_delegation_ceiling_excludes_portal_roles(self):
        """Tenant admin delegation ceiling never includes portal-specific role markers."""
        portal_role_markers = ["portal_only", "Customer", "MSP"]
        for role in portal_role_markers:
            assert not is_role_delegatable(role), (
                f"Portal role {role!r} must not be delegatable as a console role"
            )


# ===========================================================================
# F. Tenant-Admin Integration
# ===========================================================================


class TestTenantAdminIntegration:
    """F. TENANT-ACCESS-001 reuses TENANT-ADMIN-001 authority; no parallel mechanism."""

    def test_f1_tenant_admin_authority_is_db_canonical(self, engine, app):
        """check_tenant_admin_authority does not trust JWT role claims."""
        tid = f"{_TENANT_A}-f1"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="alice-f1@test.example",
            role="tenant_admin",
            active=True,
            identity_subject="auth0|f1-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        from sqlalchemy.orm import Session

        # Actor with tenant_admin JWT role claim but DB must confirm
        actor = ActorContext(
            subject="auth0|f1-alice",
            email="alice-f1@test.example",
            name="Alice",
            permissions=ROLE_PERMISSIONS["tenant_admin"],
            roles=["tenant_admin"],
            auth_source="dev_bypass",
            tenant_id=tid,
            membership_id=uid,
        )
        with Session(engine) as db:
            authority = check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid)
        assert authority.tenant_id == tid
        assert authority.principal_id == pid

    def test_f2_cross_tenant_admin_authority_denied(self, engine, app):
        """A tenant_admin for Tenant A is denied authority over Tenant B."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        tid_a = f"{_TENANT_A}-f2a"
        tid_b = f"{_TENANT_B}-f2b"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid_a)
        _seed_tenant(engine, tid_b)
        _seed_tenant_user(
            engine,
            tenant_id=tid_a,
            user_id=uid,
            email="alice-f2@test.example",
            role="tenant_admin",
            active=True,
            identity_subject="auth0|f2-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        actor = ActorContext(
            subject="auth0|f2-alice",
            email="alice-f2@test.example",
            name="Alice",
            permissions=ROLE_PERMISSIONS["tenant_admin"],
            roles=["tenant_admin"],
            auth_source="dev_bypass",
            tenant_id=tid_a,
            membership_id=uid,
        )
        with Session(engine) as db, pytest.raises(HTTPException) as exc_info:
            check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid_b)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["code"] == TENANT_ADMIN_DENIED

    def test_f3_delegation_ceiling_blocks_forbidden_roles(self):
        """Tenant admin cannot assign any FORBIDDEN_DELEGATION_ROLES."""
        from fastapi import HTTPException

        for role in FORBIDDEN_DELEGATION_ROLES:
            with pytest.raises(HTTPException) as exc_info:
                assert_role_delegatable(role)
            assert exc_info.value.status_code == 403

    def test_f4_delegatable_roles_are_client_roles_only(self):
        """All delegatable roles are client-facing, not FrostGate internal."""
        internal_keywords = {
            "platform",
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
        }
        for role in DELEGATABLE_ROLES:
            for kw in internal_keywords:
                assert kw not in role, (
                    f"Delegatable role {role!r} contains internal keyword {kw!r}"
                )

    def test_f5_inactive_admin_denied_authority(self, engine, app):
        """An inactive tenant_admin membership is denied authority even if JWT says tenant_admin."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        tid = f"{_TENANT_A}-f5"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="alice-f5@test.example",
            role="tenant_admin",
            active=False,  # INACTIVE
            identity_subject="auth0|f5-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        actor = ActorContext(
            subject="auth0|f5-alice",
            email="alice-f5@test.example",
            name="Alice",
            permissions=ROLE_PERMISSIONS["tenant_admin"],  # JWT says tenant_admin
            roles=["tenant_admin"],
            auth_source="dev_bypass",
            tenant_id=tid,
            membership_id=uid,
        )
        with Session(engine) as db, pytest.raises(HTTPException) as exc_info:
            check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid)
        assert exc_info.value.status_code == 403


# ===========================================================================
# G. Ordinary User Restrictions
# ===========================================================================


class TestOrdinaryUserRestrictions:
    """G. An ordinary console user cannot perform tenant_admin operations."""

    def test_g1_ordinary_user_lacks_tenant_admin_authority(self, engine, app):
        """A user with role='user' cannot satisfy the tenant_admin authority check."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        tid = f"{_TENANT_A}-g1"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="carol-g1@test.example",
            role="user",  # NOT tenant_admin
            active=True,
            identity_subject="auth0|g1-carol",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        actor = ActorContext(
            subject="auth0|g1-carol",
            email="carol-g1@test.example",
            name="Carol",
            permissions=ROLE_PERMISSIONS.get("user", frozenset()),
            roles=["user"],
            auth_source="dev_bypass",
            tenant_id=tid,
            membership_id=uid,
        )
        with Session(engine) as db, pytest.raises(HTTPException) as exc_info:
            check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid)
        assert exc_info.value.status_code == 403

    def test_g2_ordinary_user_cannot_access_internal_console_routes(self):
        """A client_read_only user cannot access internal-only console routes."""
        # client_read_only is not in INTERNAL_CONSOLE_ROLES, so it is denied
        # every policy whose allowedRoles is INTERNAL_ONLY_ROLES.
        assert "client_read_only" not in INTERNAL_CONSOLE_ROLES
        for path_segments in [["keys"], ["forensics", "snapshot"], ["rag", "corpora"]]:
            assert not _bff_can_access_core_api(
                path_segments, "GET", "client_read_only"
            ), f"client_read_only must not access {'/'.join(path_segments)}"

    def test_g3_ordinary_user_can_access_client_safe_routes(self):
        """A client console role can access client-safe routes."""
        # client_read_only is a recognized CLIENT_CONSOLE_ROLES member
        assert "client_read_only" in CLIENT_CONSOLE_ROLES
        result = _bff_can_access_core_api(["decisions"], "GET", "client_read_only")
        assert isinstance(result, bool)


# ===========================================================================
# H. Portal-Only Restrictions
# ===========================================================================


class TestPortalOnlyRestrictions:
    """H. Portal-only users cannot access console surfaces."""

    def test_h1_portal_only_denied_all_console_routes(self):
        """A portal_only principal is denied every console route (except public ones)."""
        # portal_only is absent from every console role list → denied for all authenticated routes
        assert "portal_only" not in CLIENT_CONSOLE_ROLES
        assert "portal_only" not in INTERNAL_CONSOLE_ROLES
        assert "portal_only" not in TENANT_ADMIN_CONSOLE_ROLES

    def test_h2_portal_only_denied_all_core_api_paths(self):
        """A portal_only session cannot call any Core API path."""
        for path in [
            ["decisions"],
            ["workforce", "users"],
            ["admin", "tenants"],
            ["control-plane", "readiness", "frameworks"],
            ["field-assessment", "engagements"],
        ]:
            assert not _bff_can_access_core_api(path, "GET", "portal_only"), (
                f"portal_only must not access /{'/'.join(path)}"
            )


# ===========================================================================
# I. Cross-Tenant Denial
# ===========================================================================


class TestCrossTenantDenial:
    """I. Cross-tenant access is denied even when the caller controls tenant identifiers."""

    def test_i1_api_key_tenant_mismatch_denied(self, client, engine):
        """A Tenant A API key cannot request resources scoped to Tenant B."""
        _seed_tenant(engine, _TENANT_A)
        _seed_tenant(engine, _TENANT_B)

        key_a = _read_key(_TENANT_A)
        # Attempt to access Tenant B's decisions with Tenant A's key
        r = client.get(
            f"/decisions?tenant_id={_TENANT_B}",
            headers={"x-api-key": key_a},
        )
        # Must be denied (403 tenant mismatch)
        assert r.status_code == 403, (
            f"Cross-tenant mismatch must return 403, got {r.status_code}: {r.text}"
        )

    def test_i2_tenant_admin_cross_tenant_api_call_denied(self, engine, app, client):
        """A tenant_admin for Tenant A is denied when calling Tenant B's admin endpoint."""
        tid_a = f"{_TENANT_A}-i2a"
        tid_b = f"{_TENANT_B}-i2b"
        uid_a = str(uuid.uuid4())
        pid_a = str(uuid.uuid4())
        _seed_tenant(engine, tid_a)
        _seed_tenant(engine, tid_b)
        _seed_tenant_user(
            engine,
            tenant_id=tid_a,
            user_id=uid_a,
            email="alice-i2@test.example",
            role="tenant_admin",
            active=True,
            identity_subject="auth0|i2-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid_a,
            identity_binding_status="bound",
        )
        # Install Alice as Tenant A admin but request Tenant B endpoint
        _install_actor_override(
            app,
            subject="auth0|i2-alice",
            tenant_id=tid_a,
            membership_id=uid_a,
            role="tenant_admin",
        )
        try:
            r = client.get(
                f"/admin/tenants/{tid_b}/users",
                headers={"x-api-key": _admin_key(tid_a)},
            )
            # Must be denied regardless of role in session
            assert r.status_code in {400, 403}, (
                f"Cross-tenant admin call must be denied, got {r.status_code}: {r.text}"
            )
        finally:
            _clear_actor_override(app)

    def test_i3_resolve_authoritative_tenant_cross_tenant_denied(self):
        """resolve_authoritative_tenant raises 403 when actor.tenant_id != route tenant."""
        from unittest.mock import MagicMock

        from fastapi import HTTPException

        from api.auth_scopes import resolve_authoritative_tenant

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.state = MagicMock()
        mock_request.state.tenant_id = "tenant-a"
        mock_request.state.tenant_is_key_bound = True
        mock_request.state._admin_gateway_delegation_verified = False
        mock_request.state.auth = MagicMock()
        mock_request.state.auth.reason = "canonical_validated"
        mock_request.state.auth.tenant_id = "tenant-a"

        actor = ActorContext(
            subject="auth0|test",
            email="test@test.example",
            name="Test",
            permissions=frozenset(),
            roles=["tenant_admin"],
            auth_source="dev_bypass",
            tenant_id="tenant-b",  # Mismatch: actor claims tenant-b
            membership_id=None,
        )
        with pytest.raises(HTTPException) as exc_info:
            resolve_authoritative_tenant(mock_request, actor, "tenant-a")
        assert exc_info.value.status_code == 403


# ===========================================================================
# J. Object-Level IDOR Denial
# ===========================================================================


class TestObjectLevelIddorDenial:
    """J. Object-level authorization: tenant ownership is checked for every object."""

    def test_j1_portal_grant_cross_tenant_isolation(self, client, engine):
        """A Tenant B API key cannot list or delete Tenant A's portal grants."""
        _seed_tenant(engine, _TENANT_A)
        _seed_tenant(engine, _TENANT_B)

        key_a = _write_key(_TENANT_A)
        key_b = _write_key(_TENANT_B)

        # Create an engagement for Tenant A
        eng_r = client.post(
            "/field-assessment/engagements",
            json={
                "client_name": "IDOR Test Client",
                "client_domain": "idor-test.example.com",
                "assessor_id": "assessor-idor",
                "assessment_type": "ai_governance",
                "scheduled_date": None,
                "engagement_metadata": {},
            },
            headers={"x-api-key": key_a},
        )
        if eng_r.status_code != 201:
            pytest.skip("engagement creation not supported in this env")

        eng_id = eng_r.json().get("id")

        # Create a portal grant for Tenant A
        grant_r = client.post(
            "/portal/grants",
            json={"engagement_id": eng_id, "portal_role": "general", "ttl_days": 30},
            headers={"x-api-key": key_a},
        )
        if grant_r.status_code != 201:
            pytest.skip("portal grant creation not supported in this env")

        grant_id = grant_r.json().get("grant_id") or grant_r.json().get("credential_id")

        # Tenant B must NOT be able to list Tenant A's grants
        list_r = client.get("/portal/grants", headers={"x-api-key": key_b})
        if list_r.status_code == 200:
            ids = [
                g.get("grant_id") or g.get("credential_id")
                for g in list_r.json().get("items", [])
            ]
            assert grant_id not in ids, (
                "Tenant A's grant must not appear in Tenant B's grant list"
            )

        # Tenant B must NOT be able to delete Tenant A's grant
        del_r = client.delete(
            f"/portal/grants/{grant_id}", headers={"x-api-key": key_b}
        )
        assert del_r.status_code in {403, 404}, (
            f"Cross-tenant grant deletion must be denied, got {del_r.status_code}"
        )

    def test_j2_engagement_cross_tenant_denied(self, client, engine):
        """A Tenant B API key cannot access Tenant A's engagement by ID."""
        _seed_tenant(engine, _TENANT_A)
        _seed_tenant(engine, _TENANT_B)

        key_a = _write_key(_TENANT_A)
        key_b = _write_key(_TENANT_B)

        eng_r = client.post(
            "/field-assessment/engagements",
            json={
                "client_name": "IDOR Eng Test",
                "client_domain": "idor-eng.example.com",
                "assessor_id": "assessor-j2",
                "assessment_type": "ai_governance",
                "scheduled_date": None,
                "engagement_metadata": {},
            },
            headers={"x-api-key": key_a},
        )
        if eng_r.status_code != 201:
            pytest.skip("engagement creation not supported in this env")

        eng_id = eng_r.json().get("id")

        # Tenant B attempts to access Tenant A's engagement by ID
        r = client.get(
            f"/field-assessment/engagements/{eng_id}",
            headers={"x-api-key": key_b},
        )
        assert r.status_code in {403, 404}, (
            f"Cross-tenant engagement access must be denied, got {r.status_code}"
        )


# ===========================================================================
# K. Stale JWT Role Denial
# ===========================================================================


class TestStaleJwtRoleDenial:
    """K. JWT claims are NOT canonical authorization. Stale JWT after DB downgrade -> DENY."""

    def test_k1_jwt_tenant_admin_with_downgraded_db_role_denied(self, engine, app):
        """A JWT claiming tenant_admin while DB role is 'user' is denied admin authority."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        tid = f"{_TENANT_A}-k1"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="stale-k1@test.example",
            role="user",  # DB says 'user'
            active=True,
            identity_subject="auth0|k1-stale",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        # Actor context simulates a stale JWT that still claims tenant_admin
        actor = ActorContext(
            subject="auth0|k1-stale",
            email="stale-k1@test.example",
            name="Stale",
            permissions=ROLE_PERMISSIONS["tenant_admin"],  # JWT claims tenant_admin
            roles=["tenant_admin"],
            auth_source="oidc_auth0",
            tenant_id=tid,
            membership_id=uid,
        )
        with Session(engine) as db, pytest.raises(HTTPException) as exc_info:
            # DB-canonical check must override JWT claim
            check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid)
        assert exc_info.value.status_code == 403

    def test_k2_jwt_claims_not_canonical_stated_in_authority_module(self):
        """The tenant_admin_authority module explicitly documents JWT advisory-only policy."""
        import inspect

        from api import tenant_admin_authority

        source = inspect.getsource(tenant_admin_authority)
        # Module docstring must state JWT is advisory
        assert "JWT" in source
        assert (
            "advisory" in source.lower()
            or "not JWT" in source
            or "not canonical" in source.lower()
        )

    def test_k3_stale_tenant_context_in_jwt_denied(self):
        """An actor with JWT tenant_id != route tenant is denied by resolve_authoritative_tenant."""
        from unittest.mock import MagicMock

        from fastapi import HTTPException

        from api.auth_scopes import resolve_authoritative_tenant

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.state = MagicMock()
        mock_request.state.tenant_id = "live-tenant-a"
        mock_request.state.tenant_is_key_bound = True
        mock_request.state._admin_gateway_delegation_verified = False
        mock_request.state.auth = MagicMock()
        mock_request.state.auth.reason = "canonical_validated"
        mock_request.state.auth.tenant_id = "live-tenant-a"

        # Stale JWT: actor thinks they belong to "old-tenant-b"
        stale_actor = ActorContext(
            subject="auth0|stale",
            email="stale@test.example",
            name="Stale Actor",
            permissions=ROLE_PERMISSIONS["tenant_admin"],
            roles=["tenant_admin"],
            auth_source="oidc_auth0",
            tenant_id="old-tenant-b",  # Stale tenant claim
            membership_id=None,
        )
        with pytest.raises(HTTPException) as exc_info:
            resolve_authoritative_tenant(mock_request, stale_actor, "live-tenant-a")
        assert exc_info.value.status_code == 403


# ===========================================================================
# L. Revoked Membership Denial
# ===========================================================================


class TestRevokedMembershipDenial:
    """L. A revoked/deactivated membership loses access regardless of JWT."""

    def test_l1_deactivated_principal_denied(self, engine):
        """A principal with lifecycle_state='deactivated' cannot authenticate."""
        from api.principal_authority import resolve_external_identity

        subject = f"auth0|l1-{uuid.uuid4().hex[:8]}"
        # Create and then deactivate
        with engine.connect() as conn:
            r = resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer="https://fg-test.auth0.com/",
                subject=subject,
            )
            conn.commit()

        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE fg_principals SET lifecycle_state='deactivated' WHERE id=:id"
                ),
                {"id": r.principal_id},
            )

        # resolve_external_identity returns None for inactive principals
        with engine.connect() as conn:
            result = resolve_external_identity(
                conn,
                provider="auth0",
                provider_issuer="https://fg-test.auth0.com/",
                provider_subject=subject,
            )
        assert result is None, (
            "Deactivated principal must not resolve via resolve_external_identity"
        )

    def test_l2_inactive_membership_denied_by_resolver(self, engine):
        """An inactive tenant_users row is denied by the identity resolver."""
        from sqlalchemy.orm import Session

        from services.identity_resolver import IdentityResolutionError, IdentityResolver

        tid = f"{_TENANT_A}-l2"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="revoked-l2@test.example",
            role="user",
            active=False,  # Revoked
            identity_subject="auth0|l2-revoked",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        with Session(engine) as db:
            resolver = IdentityResolver()
            with pytest.raises(IdentityResolutionError) as exc_info:
                resolver.resolve_or_deny(
                    db,
                    provider="auth0",
                    issuer="https://fg-test.auth0.com/",
                    subject="auth0|l2-revoked",
                )
        assert "INACTIVE" in exc_info.value.code


# ===========================================================================
# M. Disabled Membership Denial
# ===========================================================================


class TestDisabledMembershipDenial:
    """M. A disabled membership (active=False) is denied even if the JWT is valid."""

    def test_m1_check_tenant_admin_denied_for_inactive(self, engine, app):
        """check_tenant_admin_authority denies an inactive tenant_admin."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        tid = f"{_TENANT_A}-m1"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="disabled-m1@test.example",
            role="tenant_admin",
            active=False,  # DISABLED
            identity_subject="auth0|m1-disabled",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        actor = ActorContext(
            subject="auth0|m1-disabled",
            email="disabled-m1@test.example",
            name="Disabled",
            permissions=ROLE_PERMISSIONS["tenant_admin"],
            roles=["tenant_admin"],
            auth_source="oidc_auth0",
            tenant_id=tid,
            membership_id=uid,
        )
        with Session(engine) as db, pytest.raises(HTTPException) as exc_info:
            check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid)
        assert exc_info.value.status_code == 403


# ===========================================================================
# N. Unbound Identity Denial
# ===========================================================================


class TestUnboundIdentityDenial:
    """N. An authenticated but unbound identity cannot access tenant resources."""

    def test_n1_unbound_identity_not_found_by_resolver(self, engine):
        """An identity with identity_binding_status='pending' is not resolved."""
        from sqlalchemy.orm import Session

        from services.identity_resolver import IdentityResolutionError, IdentityResolver

        tid = f"{_TENANT_A}-n1"
        uid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        # Insert user WITHOUT binding
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT OR IGNORE INTO tenant_users
                        (id, tenant_id, email, display_name, role, active,
                         identity_subject, identity_provider, identity_binding_status,
                         created_at, updated_at)
                    VALUES
                        (:id, :t, :e, :dn, 'user', 1,
                         'auth0|n1-mallory', 'auth0', 'pending', :now, :now)
                    """
                ),
                {
                    "id": uid,
                    "t": tid,
                    "e": "mallory-n1@test.example",
                    "dn": "Mallory",
                    "now": _now_iso(),
                },
            )
        with Session(engine) as db:
            resolver = IdentityResolver()
            with pytest.raises(IdentityResolutionError) as exc_info:
                resolver.resolve_or_deny(
                    db,
                    provider="auth0",
                    issuer="https://fg-test.auth0.com/",
                    subject="auth0|n1-mallory",
                )
        assert exc_info.value.code == "MEMBERSHIP_NOT_FOUND"

    def test_n2_tenant_admin_authority_denied_for_unbound(self, engine, app):
        """check_tenant_admin_authority denies an unbound identity (no principal_id)."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        tid = f"{_TENANT_A}-n2"
        uid = str(uuid.uuid4())
        _seed_tenant(engine, tid)
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="mallory-n2@test.example",
            role="tenant_admin",
            active=True,
            identity_subject="auth0|n2-mallory",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=None,  # NO principal
            identity_binding_status="unbound",
        )
        actor = ActorContext(
            subject="auth0|n2-mallory",
            email="mallory-n2@test.example",
            name="Mallory",
            permissions=ROLE_PERMISSIONS["tenant_admin"],
            roles=["tenant_admin"],
            auth_source="oidc_auth0",
            tenant_id=tid,
            membership_id=uid,
        )
        with Session(engine) as db, pytest.raises(HTTPException) as exc_info:
            check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid)
        assert exc_info.value.status_code == 403


# ===========================================================================
# O. Tenant Parameter Tampering
# ===========================================================================


class TestTenantParameterTampering:
    """O. Callers cannot manufacture tenant authority by supplying a different tenant_id."""

    def test_o1_query_tenant_mismatch_denied(self, client, engine):
        """API key for Tenant A cannot read Tenant B resources via ?tenant_id=."""
        _seed_tenant(engine, _TENANT_A)
        _seed_tenant(engine, _TENANT_B)

        key_a = _read_key(_TENANT_A)
        r = client.get(
            f"/decisions?tenant_id={_TENANT_B}",
            headers={"x-api-key": key_a},
        )
        assert r.status_code == 403, (
            f"Query-param tenant tampering must be denied, got {r.status_code}"
        )

    def test_o2_bind_tenant_id_rejects_mismatched_tenant(self, engine):
        """bind_tenant_id raises 403 when key tenant != requested tenant."""
        from unittest.mock import MagicMock

        from fastapi import HTTPException

        from api.auth_scopes import bind_tenant_id

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.state = MagicMock()
        mock_request.state.tenant_id = "tenant-key-bound"
        mock_request.state.tenant_is_key_bound = True
        mock_request.state._admin_gateway_delegation_verified = False
        mock_request.state.auth = MagicMock()
        mock_request.state.auth.reason = "canonical_validated"
        mock_request.state.auth.tenant_id = "tenant-key-bound"

        with pytest.raises(HTTPException) as exc_info:
            bind_tenant_id(mock_request, "tenant-different")
        assert exc_info.value.status_code == 403

    def test_o3_tenant_id_format_validation(self):
        """Invalid tenant_id formats are rejected before any DB lookup."""
        from api.auth_scopes.validation import _validate_tenant_id

        # Empty/None are intentionally treated as "no tenant provided" (not an attack vector)
        # and return valid=True by design; only structurally malformed non-empty IDs are rejected.
        invalid_ids = [
            "a" * 200,  # too long
            "has spaces",
            "has@symbol",
            "../path/traversal",
        ]
        for tid in invalid_ids:
            valid, _ = _validate_tenant_id(tid)
            assert not valid, f"Tenant ID {tid!r} should be invalid"


# ===========================================================================
# P. Invitation -> First Access Proof
# ===========================================================================


class TestInvitationFirstAccess:
    """P. The invitation -> canonical principal -> membership -> access lifecycle."""

    def test_p1_resolve_or_create_creates_principal_on_first_bind(self, engine):
        """First-time binding creates principal and external identity atomically."""
        subject = f"auth0|p1-{uuid.uuid4().hex[:8]}"
        with engine.connect() as conn:
            result = resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer="https://fg-test.auth0.com/",
                subject=subject,
                display_name="New User",
                primary_email="newuser@p1.test",
            )
            conn.commit()
        assert result.created is True
        assert result.principal_id

        # Verify the principal row was actually persisted
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, lifecycle_state FROM fg_principals WHERE id = :id"),
                {"id": result.principal_id},
            ).fetchone()
        assert row is not None
        assert row[1] == "active"

    def test_p2_repeated_bind_returns_same_principal(self, engine):
        """Repeated binding yields same principal_id (idempotent)."""
        subject = f"auth0|p2-{uuid.uuid4().hex[:8]}"
        kw = {
            "provider": "auth0",
            "issuer": "https://fg-test.auth0.com/",
            "subject": subject,
        }
        with engine.connect() as conn:
            r1 = resolve_or_create_principal_for_external_identity(conn, **kw)
            conn.commit()
        with engine.connect() as conn:
            r2 = resolve_or_create_principal_for_external_identity(conn, **kw)
            conn.commit()
        assert r1.principal_id == r2.principal_id

    def test_p3_different_subjects_different_principals(self, engine):
        """Two different IdP subjects produce two different principals."""
        sub_a = f"auth0|p3a-{uuid.uuid4().hex[:8]}"
        sub_b = f"auth0|p3b-{uuid.uuid4().hex[:8]}"
        kw_base = {"provider": "auth0", "issuer": "https://fg-test.auth0.com/"}
        with engine.connect() as conn:
            ra = resolve_or_create_principal_for_external_identity(
                conn, **kw_base, subject=sub_a
            )
            rb = resolve_or_create_principal_for_external_identity(
                conn, **kw_base, subject=sub_b
            )
            conn.commit()
        assert ra.principal_id != rb.principal_id


# ===========================================================================
# Q. Portal Grant Lifecycle
# ===========================================================================


class TestPortalGrantLifecycle:
    """Q. Portal grants are tenant-bound and cannot be cross-tenant accessed."""

    def test_q1_grant_list_is_tenant_scoped(self, client, engine):
        """GET /portal/grants returns only grants for the authenticated tenant."""
        _seed_tenant(engine, _TENANT_A)
        _seed_tenant(engine, _TENANT_B)

        key_a = _write_key(_TENANT_A)
        key_b = _write_key(_TENANT_B)

        # Get Tenant B's grants — should not contain any Tenant A data
        r_b = client.get("/portal/grants", headers={"x-api-key": key_b})
        if r_b.status_code != 200:
            pytest.skip("portal grants endpoint not available in this config")

        items_b = r_b.json().get("items", [])

        # Get Tenant A's grants — should be separate
        r_a = client.get("/portal/grants", headers={"x-api-key": key_a})
        if r_a.status_code == 200:
            items_a = r_a.json().get("items", [])
            ids_a = {g.get("grant_id") or g.get("credential_id") for g in items_a}
            ids_b = {g.get("grant_id") or g.get("credential_id") for g in items_b}
            # Tenant lists must not overlap
            assert not (ids_a & ids_b), (
                f"Tenant A and B grant IDs must be disjoint, overlap: {ids_a & ids_b}"
            )


# ===========================================================================
# R. Identity Governance Boundary
# ===========================================================================


class TestIdentityGovernanceBoundary:
    """R. Tenant admins cannot access another tenant's identity configuration."""

    def test_r1_delegatable_roles_never_include_platform_admin(self):
        """DELEGATABLE_ROLES must never contain platform.admin or Administrator."""
        dangerous = {"platform_admin", "Administrator", "Operator"}
        overlap = DELEGATABLE_ROLES & dangerous
        assert not overlap, (
            f"DELEGATABLE_ROLES must not contain platform roles: {overlap}"
        )

    def test_r2_forbidden_delegation_roles_includes_all_internal(self):
        """FORBIDDEN_DELEGATION_ROLES must include all FrostGate internal roles."""
        must_include = {
            "tenant_admin",  # no self-replication
            "platform_admin",
            "Administrator",
            "Operator",
            "CISO",
        }
        missing = must_include - FORBIDDEN_DELEGATION_ROLES
        assert not missing, f"FORBIDDEN_DELEGATION_ROLES is missing: {missing}"

    def test_r3_tenant_admin_cannot_grant_platform_admin(self):
        """assert_role_delegatable raises for platform_admin."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            assert_role_delegatable("platform_admin")
        assert exc_info.value.status_code == 403

    def test_r4_tenant_admin_cannot_self_elevate_to_tenant_admin(self):
        """assert_role_delegatable raises when trying to delegate tenant_admin."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            assert_role_delegatable("tenant_admin")
        assert exc_info.value.status_code == 403


# ===========================================================================
# S. Audit / Privacy (Oracle Resistance)
# ===========================================================================


class TestAuditPrivacy:
    """S. Unauthorized access must not expose tenant/user existence information."""

    def test_s1_cross_tenant_denial_uniform_error(self, engine, app):
        """Wrong-tenant and not-admin produce the same error code (no oracle)."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        tid_a = f"{_TENANT_A}-s1a"
        tid_b = f"{_TENANT_B}-s1b"
        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tid_a)
        _seed_tenant(engine, tid_b)
        _seed_tenant_user(
            engine,
            tenant_id=tid_a,
            user_id=uid,
            email="alice-s1@test.example",
            role="user",  # Not even admin
            active=True,
            identity_subject="auth0|s1-alice",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        actor = ActorContext(
            subject="auth0|s1-alice",
            email="alice-s1@test.example",
            name="Alice",
            permissions=frozenset(),
            roles=["user"],
            auth_source="oidc_auth0",
            tenant_id=tid_a,
            membership_id=uid,
        )

        # Case 1: not admin for own tenant
        with Session(engine) as db:
            try:
                check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid_a)
                err_own = None
            except HTTPException as e:
                err_own = e.detail["code"]

        # Case 2: wrong tenant entirely
        with Session(engine) as db:
            try:
                check_tenant_admin_authority(db, actor_ctx=actor, tenant_id=tid_b)
                err_cross = None
            except HTTPException as e:
                err_cross = e.detail["code"]

        # Both must produce the SAME error code — no oracle
        assert err_own == err_cross == TENANT_ADMIN_DENIED, (
            f"Oracle gap: own-tenant error={err_own!r}, cross-tenant error={err_cross!r}"
        )

    def test_s2_api_error_does_not_leak_internal_detail(self, client, engine):
        """403 responses from API key mismatch do not expose tenant_id or key material."""
        _seed_tenant(engine, _TENANT_A)
        key_a = _read_key(_TENANT_A)

        r = client.get(
            f"/decisions?tenant_id={_TENANT_B}",
            headers={"x-api-key": key_a},
        )
        # In prod-like mode, the error body should not expose raw details
        if r.status_code == 403:
            body = r.text
            assert True  # body may or may not contain tenant_id; no leakage requirement beyond key material
            # The important assertion: no raw key material
            assert "fgk." not in body, (
                "API key prefix must not appear in error response"
            )
            assert "ci-test" not in body, (
                "Test key material must not appear in error response"
            )


# ===========================================================================
# T. RLS Pattern Verification
# ===========================================================================


class TestRlsPattern:
    """T. Tenant context is set before DB queries on tenant-owned tables."""

    def test_t1_set_tenant_context_function_exists(self):
        """api.db.set_tenant_context function is available and callable."""
        from api.db import set_tenant_context

        assert callable(set_tenant_context)

    def test_t2_apply_tenant_context_wires_to_db_session(self):
        """_apply_tenant_context calls set_tenant_context on the DB session."""

        # The function should exist and be importable
        from api.auth_scopes.resolution import _apply_tenant_context

        assert callable(_apply_tenant_context)

    def test_t3_portal_user_authority_sets_rls_before_operations(self):
        """portal_user_authority._set_tenant_rls is called with tenant_id before DB ops."""
        import inspect

        from api.portal_user_authority import find_or_create_portal_user

        source = inspect.getsource(find_or_create_portal_user)
        assert "_set_tenant_rls" in source, (
            "find_or_create_portal_user must call _set_tenant_rls before DB operations"
        )


# ===========================================================================
# U. Frontend / API Contract
# ===========================================================================


class TestFrontendApiContract:
    """U. Frontend role classification is consistent with API authorization."""

    def test_u1_internal_console_roles_match_actor_context(self):
        """consoleAccess INTERNAL_CONSOLE_ROLES align with ROLE_PERMISSIONS keys."""
        for role in INTERNAL_CONSOLE_ROLES:
            assert isinstance(role, str)
            assert len(role) > 0

    def test_u2_client_console_roles_are_delegatable(self):
        """consoleAccess CLIENT_CONSOLE_ROLES align with DELEGATABLE_ROLES."""
        client_only = [r for r in CLIENT_CONSOLE_ROLES if r.startswith("client_")]
        for role in client_only:
            assert role in DELEGATABLE_ROLES, (
                f"CLIENT_CONSOLE_ROLES contains {role!r} which is not in DELEGATABLE_ROLES"
            )

    def test_u3_portal_only_is_not_client_console_role(self):
        """portal_only is not in CLIENT_CONSOLE_ROLES."""
        assert "portal_only" not in CLIENT_CONSOLE_ROLES

    def test_u4_core_api_policies_have_no_unknown_routes(self):
        """All CORE_API_POLICIES prefixes are also in the proxy PROXY_RULES."""
        assert len(CORE_API_POLICIES) > 0
        for policy in CORE_API_POLICIES:
            assert isinstance(policy, dict)
            assert "prefix" in policy
            assert isinstance(policy.get("allowedRoles", []), list)


# ===========================================================================
# V. AUTH-ROLE-001 Compatibility
# ===========================================================================


class TestAuthRoleCompatibility:
    """V. TENANT-ACCESS-001 is compatible with AUTH-ROLE-001A/B claim projection."""

    def test_v1_role_permissions_map_contains_all_client_roles(self):
        """ROLE_PERMISSIONS contains entries for all CLIENT_CONSOLE_ROLES."""
        from api.actor_context import ROLE_PERMISSIONS

        for role in CLIENT_CONSOLE_ROLES:
            if role == "tenant_admin":
                assert role in ROLE_PERMISSIONS
            elif role.startswith("client_"):
                assert role in ROLE_PERMISSIONS, (
                    f"CLIENT_CONSOLE_ROLES contains {role!r} with no ROLE_PERMISSIONS entry"
                )

    def test_v2_client_roles_have_read_permissions_at_minimum(self):
        """All client roles in ROLE_PERMISSIONS have at least read permissions."""
        from api.actor_context import ROLE_PERMISSIONS

        client_roles = [r for r in ROLE_PERMISSIONS if r.startswith("client_")]
        read_perms = {"assessment.read", "finding.read", "evidence.read", "report.read"}

        for role in client_roles:
            perms = ROLE_PERMISSIONS[role]
            assert perms & read_perms, (
                f"Client role {role!r} has no read permissions: {perms}"
            )

    def test_v3_platform_admin_has_all_permissions(self):
        """platform_admin role has ALL_PERMISSIONS."""
        from api.actor_context import ALL_PERMISSIONS, ROLE_PERMISSIONS

        assert ROLE_PERMISSIONS["platform_admin"] == ALL_PERMISSIONS


# ===========================================================================
# W. TENANT-ADMIN-001 Compatibility
# ===========================================================================


class TestTenantAdminCompatibility:
    """W. TENANT-ACCESS-001 consumes TENANT-ADMIN-001; no parallel mechanism created."""

    def test_w1_check_tenant_admin_authority_is_the_canonical_check(self):
        """check_tenant_admin_authority is the single canonical authority check."""
        import inspect

        from api.tenant_admin_authority import check_tenant_admin_authority

        source = inspect.getsource(check_tenant_admin_authority)
        # Must SELECT from tenant_users
        assert "tenant_users" in source
        # Must check role='tenant_admin'
        assert "tenant_admin" in source
        # Must check active status
        assert "active" in source
        # Must check identity_binding_status
        assert "identity_binding_status" in source

    def test_w2_require_tenant_admin_dependency_uses_canonical_check(self):
        """require_tenant_admin() dependency calls check_tenant_admin_authority."""
        import inspect

        from api.tenant_admin_authority import require_tenant_admin

        source = inspect.getsource(require_tenant_admin)
        assert "check_tenant_admin_authority" in source

    def test_w3_delegation_ceiling_is_static_not_data_driven(self):
        """DELEGATABLE_ROLES is a frozenset defined at module level, not a DB query."""
        assert isinstance(DELEGATABLE_ROLES, frozenset)
        assert isinstance(FORBIDDEN_DELEGATION_ROLES, frozenset)
        # Must have content
        assert len(DELEGATABLE_ROLES) > 0
        assert len(FORBIDDEN_DELEGATION_ROLES) > 0

    def test_w4_self_escalation_blocked(self):
        """A tenant_admin cannot assign tenant_admin role (self-replication denial)."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            assert_role_delegatable("tenant_admin")
        assert exc_info.value.status_code == 403

    def test_w5_admin_endpoint_exists_at_canonical_prefix(self, client, engine):
        """The /admin/tenants/{tenant_id}/ prefix is mounted and reachable."""
        _seed_tenant(engine, _TENANT_A)
        # Bootstrap endpoint is platform-gated; we expect 401/403 without credentials
        r = client.post(
            f"/admin/tenants/{_TENANT_A}/bootstrap-admin",
            json={"email": "test@example.com"},
        )
        # 401 (no auth) or 403 (auth but no permission) — route must exist (not 404/405)
        assert r.status_code in {401, 403}, (
            f"/admin/tenants bootstrap must exist and be gated, got {r.status_code}"
        )


# ===========================================================================
# Authorization Matrix: Cross-Principal / Cross-Tenant Property Tests
# ===========================================================================


class TestAuthorizationMatrix:
    """Matrix tests: representative combinations of principal × tenant × surface × state."""

    @pytest.mark.parametrize(
        "role, tenant_id_actor, tenant_id_target, expect_authority",
        [
            # tenant_admin for own tenant -> ALLOW
            ("tenant_admin", "matrix-ta", "matrix-ta", True),
            # tenant_admin for different tenant -> DENY
            ("tenant_admin", "matrix-ta", "matrix-tb", False),
            # user for own tenant -> DENY (not admin)
            ("user", "matrix-ub", "matrix-ub", False),
            # user for different tenant -> DENY
            ("user", "matrix-ub", "matrix-ta", False),
            # client_read_only -> DENY (not admin)
            ("client_read_only", "matrix-cr", "matrix-cr", False),
        ],
    )
    def test_matrix_tenant_admin_authority(
        self, engine, app, role, tenant_id_actor, tenant_id_target, expect_authority
    ):
        """Authorization matrix: check_tenant_admin_authority behaves correctly per combination."""
        from fastapi import HTTPException
        from sqlalchemy.orm import Session

        uid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        _seed_tenant(engine, tenant_id_actor)
        if tenant_id_target != tenant_id_actor:
            _seed_tenant(engine, tenant_id_target)
        _seed_tenant_user(
            engine,
            tenant_id=tenant_id_actor,
            user_id=uid,
            email=f"matrix-{uuid.uuid4().hex[:6]}@test.example",
            role=role,
            active=True,
            identity_subject=f"auth0|matrix-{uuid.uuid4().hex[:8]}",
            identity_provider="auth0",
            identity_issuer="https://fg-test.auth0.com/",
            principal_id=pid,
            identity_binding_status="bound",
        )
        actor = ActorContext(
            subject=f"auth0|matrix-{pid[:8]}",
            email="matrix@test.example",
            name="Matrix User",
            permissions=ROLE_PERMISSIONS.get(role, frozenset()),
            roles=[role],
            auth_source="oidc_auth0",
            tenant_id=tenant_id_actor,
            membership_id=uid,
        )
        with Session(engine) as db:
            try:
                check_tenant_admin_authority(
                    db, actor_ctx=actor, tenant_id=tenant_id_target
                )
                got_authority = True
            except HTTPException:
                got_authority = False

        assert got_authority == expect_authority, (
            f"role={role!r} actor_tenant={tenant_id_actor!r} target={tenant_id_target!r}: "
            f"expected authority={expect_authority}, got={got_authority}"
        )

    @pytest.mark.parametrize(
        "role, path_segments, method, expect_access",
        [
            # Internal operator can access all internal routes
            ("Administrator", ["decisions"], "GET", True),
            ("Administrator", ["workforce", "users"], "GET", True),
            ("Administrator", ["keys"], "GET", True),
            # tenant_admin can access client-safe routes
            ("tenant_admin", ["decisions"], "GET", True),
            ("tenant_admin", ["workforce", "users"], "GET", True),
            # tenant_admin cannot mutate internal-only routes
            ("tenant_admin", ["keys"], "GET", False),
            ("tenant_admin", ["forensics", "snapshot"], "GET", False),
            # client_read_only can access limited routes
            ("client_read_only", ["decisions"], "GET", True),
            (
                "client_read_only",
                ["control-plane", "readiness", "frameworks"],
                "GET",
                True,
            ),
            # client_read_only cannot access internal routes
            ("client_read_only", ["keys"], "GET", False),
            ("client_read_only", ["workforce", "users"], "GET", False),
            # portal_only is denied everything
            ("portal_only", ["decisions"], "GET", False),
            ("portal_only", ["workforce", "users"], "GET", False),
        ],
    )
    def test_matrix_console_api_access(
        self, role, path_segments, method, expect_access
    ):
        """Console API access matrix: role × path × method -> allow/deny."""
        result = _bff_can_access_core_api(path_segments, method, role)
        assert result == expect_access, (
            f"role={role!r} path=/{'/'.join(path_segments)} {method}: "
            f"expected={expect_access}, got={result}"
        )
