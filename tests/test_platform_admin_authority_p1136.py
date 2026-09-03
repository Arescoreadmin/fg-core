"""
P-113.6 — Canonical Platform Administrator Credential Authority — negative security test matrix.

Test matrix:
  N-01  platform_admin role NOT assignable via self-service /rbac/assignments
  N-02  platform_admin role returns 403 ROLE_NOT_DELEGATABLE via tenant credential-admin
  N-03  VALID_ROLE_NAMES includes platform_admin (Defect 1 regression guard)
  N-04  TENANT_ASSIGNABLE_ROLES does NOT include platform_admin
  N-05  PLATFORM_CREDENTIAL_ROLES includes platform_admin and tenant_admin
  N-06  VALID_ROLE_NAMES == TENANT_ASSIGNABLE_ROLES | PLATFORM_CREDENTIAL_ROLES
  N-07  bootstrap endpoint: 409 if active credential already exists
  N-08  bootstrap endpoint: plaintext_key present on first bootstrap
  N-09  rotate endpoint: 404 if no active credential exists
  N-10  PSP credential does NOT grant platform.admin permission
  N-11  CORE_API_KEY does NOT grant platform.admin via wildcard scope
  N-12  assign_role accepts platform_admin (Defect 1 fix verification)
  N-13  tenant admin CANNOT assign platform_admin role
  N-14  bootstrap returns status=bootstrapped on first call
  N-15  rotate carries platform_admin role to new credential generation
"""

from __future__ import annotations

import uuid
from typing import Iterator

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient


# ---------------------------------------------------------------------------
# N-03 / N-04 / N-05 / N-06 — Constants contract (no app needed)
# ---------------------------------------------------------------------------


def test_n03_valid_role_names_includes_platform_admin():
    """Defect 1 regression guard: VALID_ROLE_NAMES must include platform_admin."""
    from api.tenant_rbac import VALID_ROLE_NAMES

    assert "platform_admin" in VALID_ROLE_NAMES, (
        "platform_admin must be in VALID_ROLE_NAMES so assign_role() can store it. "
        "This was Defect 1 in P-113.6."
    )


def test_n04_tenant_assignable_roles_excludes_platform_admin():
    """platform_admin must NOT be self-service assignable."""
    from api.tenant_rbac import TENANT_ASSIGNABLE_ROLES

    assert "platform_admin" not in TENANT_ASSIGNABLE_ROLES, (
        "platform_admin must not be in TENANT_ASSIGNABLE_ROLES — "
        "it must never become tenant-self-assignable (Security Invariant 1)."
    )


def test_n04b_tenant_assignable_roles_excludes_tenant_admin():
    """tenant_admin must NOT be in TENANT_ASSIGNABLE_ROLES (prevents privilege escalation)."""
    from api.tenant_rbac import TENANT_ASSIGNABLE_ROLES

    assert "tenant_admin" not in TENANT_ASSIGNABLE_ROLES, (
        "tenant_admin must not be in TENANT_ASSIGNABLE_ROLES."
    )


def test_n05_platform_credential_roles_contains_expected():
    """PLATFORM_CREDENTIAL_ROLES must contain platform_admin and tenant_admin."""
    from api.tenant_rbac import PLATFORM_CREDENTIAL_ROLES

    assert "platform_admin" in PLATFORM_CREDENTIAL_ROLES
    assert "tenant_admin" in PLATFORM_CREDENTIAL_ROLES


def test_n06_valid_role_names_is_union():
    """VALID_ROLE_NAMES == TENANT_ASSIGNABLE_ROLES | PLATFORM_CREDENTIAL_ROLES."""
    from api.tenant_rbac import (
        PLATFORM_CREDENTIAL_ROLES,
        TENANT_ASSIGNABLE_ROLES,
        VALID_ROLE_NAMES,
    )

    expected = TENANT_ASSIGNABLE_ROLES | PLATFORM_CREDENTIAL_ROLES
    assert VALID_ROLE_NAMES == expected, (
        f"VALID_ROLE_NAMES={VALID_ROLE_NAMES!r} does not match "
        f"TENANT_ASSIGNABLE_ROLES | PLATFORM_CREDENTIAL_ROLES={expected!r}"
    )


def test_n06b_namespaces_are_disjoint():
    """TENANT_ASSIGNABLE_ROLES and PLATFORM_CREDENTIAL_ROLES must not overlap."""
    from api.tenant_rbac import PLATFORM_CREDENTIAL_ROLES, TENANT_ASSIGNABLE_ROLES

    overlap = TENANT_ASSIGNABLE_ROLES & PLATFORM_CREDENTIAL_ROLES
    assert not overlap, (
        f"TENANT_ASSIGNABLE_ROLES and PLATFORM_CREDENTIAL_ROLES overlap: {overlap!r}. "
        "This would allow privilege escalation."
    )


# ---------------------------------------------------------------------------
# N-10 — PSP credential does NOT grant platform.admin
# ---------------------------------------------------------------------------


def test_n10_psp_does_not_grant_platform_admin():
    """PSP_CREDENTIAL_SCOPES must NOT include platform.admin (Security Invariant 2)."""
    from api.platform_service_principal import PSP_CREDENTIAL_SCOPES

    assert "platform.admin" not in PSP_CREDENTIAL_SCOPES, (
        "PSP must never hold platform.admin — it has explicit restricted scopes only."
    )


def test_n10b_psp_permissions_exclude_platform_admin():
    """PLATFORM_SERVICE_DEFAULT_PERMISSIONS must NOT include platform.admin."""
    from api.platform_service_principal import PLATFORM_SERVICE_DEFAULT_PERMISSIONS

    assert "platform.admin" not in PLATFORM_SERVICE_DEFAULT_PERMISSIONS, (
        "PSP default permissions must not include platform.admin."
    )


# ---------------------------------------------------------------------------
# N-11 — CORE_API_KEY wildcard does NOT grant platform.admin
# ---------------------------------------------------------------------------


def test_n11_wildcard_scope_does_not_grant_platform_admin():
    """'*' in scopes must NOT be treated as all-scopes by _permissions_from_legacy_scopes.

    FG_API_KEY / CORE_API_KEY uses '*' as its scope string. The legacy scope
    bridge function explicitly checks for 'admin:write' in the set — and
    {'*'} does not contain the string 'admin:write', so no platform.admin.
    """
    from api.identity_providers.api_key import _permissions_from_legacy_scopes

    scopes_with_wildcard = {"*"}
    perms = _permissions_from_legacy_scopes(scopes_with_wildcard)
    assert "platform.admin" not in perms, (
        "Wildcard '*' scope must NOT grant platform.admin via _permissions_from_legacy_scopes. "
        "Security Invariant 3: CORE_API_KEY must not become platform-admin authority."
    )


# ---------------------------------------------------------------------------
# N-12 — assign_role accepts platform_admin (Defect 1 fix)
# ---------------------------------------------------------------------------


def test_n12_assign_role_accepts_platform_admin(tmp_path, monkeypatch):
    """assign_role() must accept platform_admin now that VALID_ROLE_NAMES includes it."""
    db_path = str(tmp_path / "n12.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=db_path)

    from api.db import get_engine
    from api.credential_authority import issue_credential
    from api.tenant_rbac import assign_role
    from sqlalchemy.orm import Session

    engine = get_engine()

    # Seed frostgate-internal tenant (required by credential authority)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal Platform', 'active', 'internal_platform')"
            )
        )

    # Issue a credential under frostgate-internal
    result = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot="platform-admin-credential:v1",
        actor_id="test",
    )
    cred_id = result.record.credential_id
    assert cred_id

    # This should NOT raise ValueError (Defect 1 fix)
    with Session(engine) as session:
        from api.db import set_tenant_context

        set_tenant_context(session, "frostgate-internal")
        result = assign_role(
            session,
            tenant_id="frostgate-internal",
            actor_key_prefix="test:operator",
            credential_id=cred_id,
            role_name="platform_admin",
        )
    assert result["role"] == "platform_admin"


# ---------------------------------------------------------------------------
# Fixtures for app-based tests
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


def _set_platform_actor(app, *, tenant_id: str = "frostgate-internal") -> None:
    """Install a platform_admin ActorContext override for tests that need platform.admin."""
    from api.actor_context import ActorContext, ALL_PERMISSIONS
    from api.auth_dispatch import get_actor_context

    def _override() -> ActorContext:
        return ActorContext(
            subject="test:platform-admin",
            email="platform@frostgate.internal",
            name="Platform Admin Test",
            permissions=ALL_PERMISSIONS,
            roles=["platform_admin"],
            auth_source="dev_bypass",
            tenant_id=tenant_id,
        )

    app.dependency_overrides[get_actor_context] = _override


def _clear_actor(app) -> None:
    from api.auth_dispatch import get_actor_context

    app.dependency_overrides.pop(get_actor_context, None)


def _set_tenant_admin_actor(app, *, tenant_id: str) -> None:
    """Install a tenant_admin ActorContext override."""
    from api.actor_context import ActorContext, ROLE_PERMISSIONS
    from api.auth_dispatch import get_actor_context

    def _override() -> ActorContext:
        return ActorContext(
            subject="test:tenant-admin",
            email="admin@example.com",
            name="Tenant Admin Test",
            permissions=ROLE_PERMISSIONS.get("tenant_admin", frozenset()),
            roles=["tenant_admin"],
            auth_source="dev_bypass",
            tenant_id=tenant_id,
        )

    app.dependency_overrides[get_actor_context] = _override


def _seed_tenant(engine, tenant_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES (:tid, :tid, 'active', 'customer')"
            ),
            {"tid": tenant_id},
        )


def _seed_internal_tenant(engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal Platform', 'active', 'internal_platform')"
            )
        )


def _seed_credential(engine, tenant_id: str) -> str:
    """Issue a tenant_api_key credential. Returns credential_id."""
    from api.credential_authority import issue_credential

    result = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=str(uuid.uuid4()),
        actor_id="test-setup",
    )
    return result.record.credential_id


# ---------------------------------------------------------------------------
# N-01 — platform_admin NOT assignable via self-service /rbac/assignments
# ---------------------------------------------------------------------------


def test_n01_rbac_assignment_rejects_platform_admin(app, engine):
    """platform_admin must be rejected by the RBAC self-service assignment endpoint.

    The /rbac/assignments endpoint gates on require_role("tenant_admin") and calls
    assign_role() directly.  Even though VALID_ROLE_NAMES now includes platform_admin,
    the endpoint itself must not be a vector for platform escalation.  The test
    verifies that the endpoint returns 422 (role not found in self-service context)
    or the role store rejects the attempt without a platform.admin actor.
    """
    from api.auth_scopes import mint_key

    tid = f"n01-{uuid.uuid4().hex[:8]}"
    _seed_tenant(engine, tid)
    cred_id = _seed_credential(engine, tid)

    # Mint a tenant_admin key — has keys:write scope
    key = mint_key("admin:read", "admin:write", "keys:read", "keys:write", tenant_id=tid)
    headers = {"X-API-Key": key, "X-Tenant-ID": tid}

    try:
        _set_platform_actor(app, tenant_id=tid)
        # Override the actor to be tenant_admin, not platform_admin
        _set_tenant_admin_actor(app, tenant_id=tid)
        r = client_for(app).post(
            "/rbac/assignments",
            json={"credential_id": cred_id, "role": "platform_admin"},
            headers=headers,
        )
    finally:
        _clear_actor(app)

    # Must not succeed — platform_admin requires platform.admin permission to assign
    assert r.status_code in (403, 422), (
        f"Expected 403 or 422 for platform_admin self-assignment attempt, got {r.status_code}: {r.text}"
    )


def client_for(app):
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# N-02 — platform_admin returns 403 via tenant credential-admin
# ---------------------------------------------------------------------------


def test_n02_credential_admin_rejects_platform_admin():
    """Assigning platform_admin via /credential-administration returns 403 ROLE_NOT_DELEGATABLE.

    Verified at the source level: the assign_service_credential_role handler in
    tenant_admin.py checks PLATFORM_ONLY_CREDENTIAL_ROLES first and returns
    ROLE_NOT_DELEGATABLE (403) before any DB call.
    """
    import inspect
    import api.tenant_admin as tenant_admin

    from api.tenant_admin import PLATFORM_ONLY_CREDENTIAL_ROLES

    # Constants check
    assert "platform_admin" in PLATFORM_ONLY_CREDENTIAL_ROLES, (
        "platform_admin must be in PLATFORM_ONLY_CREDENTIAL_ROLES for the 403 guard to apply."
    )

    # Source check — handler must check PLATFORM_ONLY_CREDENTIAL_ROLES before proceeding
    source = inspect.getsource(tenant_admin.assign_service_credential_role)
    assert "PLATFORM_ONLY_CREDENTIAL_ROLES" in source, (
        "assign_service_credential_role must check PLATFORM_ONLY_CREDENTIAL_ROLES first."
    )
    assert "ROLE_NOT_DELEGATABLE" in source, (
        "assign_service_credential_role must return ROLE_NOT_DELEGATABLE for platform roles."
    )
    assert "403" in source, (
        "assign_service_credential_role must use HTTP 403 for platform role delegation attempt."
    )


# ---------------------------------------------------------------------------
# N-07 — bootstrap 409 if active credential already exists
# N-08 — bootstrap returns plaintext_key on first call
# N-14 — bootstrap returns status=bootstrapped
# ---------------------------------------------------------------------------


def test_n07_n08_n14_bootstrap_lifecycle(app, engine, monkeypatch):
    """Bootstrap is idempotent: first call returns plaintext_key + status=bootstrapped;
    second call returns 409 PLATFORM_ADMIN_ALREADY_EXISTS.
    """
    monkeypatch.setenv("FG_ENV", "test")  # disable prod-mode gateway enforcement
    _seed_internal_tenant(engine)
    _set_platform_actor(app)

    try:
        c = client_for(app)

        # First bootstrap: should succeed with 201
        r1 = c.post(
            "/admin/system/platform-admin/bootstrap",
            headers={
                "X-API-Key": "ci-test-key-00000000000000000000000000000000",
                "X-FG-Internal-Token": "",
            },
        )
        assert r1.status_code == 201, (
            f"Expected 201 on first bootstrap, got {r1.status_code}: {r1.text}"
        )
        body1 = r1.json()
        assert body1["status"] == "bootstrapped"
        assert body1["credential_id"]
        assert body1["plaintext_key"], "plaintext_key must be present on first bootstrap"
        assert body1["plaintext_key"].startswith("fgk."), (
            f"Canonical credential must start with 'fgk.', got: {body1['plaintext_key'][:20]!r}"
        )

        # Second bootstrap: must return 409
        r2 = c.post(
            "/admin/system/platform-admin/bootstrap",
            headers={
                "X-API-Key": "ci-test-key-00000000000000000000000000000000",
                "X-FG-Internal-Token": "",
            },
        )
        assert r2.status_code == 409, (
            f"Expected 409 on duplicate bootstrap, got {r2.status_code}: {r2.text}"
        )
        body2 = r2.json()
        assert body2.get("detail", {}).get("code") == "PLATFORM_ADMIN_ALREADY_EXISTS"

    finally:
        _clear_actor(app)


# ---------------------------------------------------------------------------
# N-09 — rotate returns 404 if no active credential exists
# ---------------------------------------------------------------------------


def test_n09_rotate_404_when_no_credential(app, engine, monkeypatch):
    """Rotate must return 404 if no active platform_admin credential exists."""
    monkeypatch.setenv("FG_ENV", "test")
    _seed_internal_tenant(engine)
    _set_platform_actor(app)

    try:
        c = client_for(app)
        r = c.post(
            "/admin/system/platform-admin/rotate",
            headers={
                "X-API-Key": "ci-test-key-00000000000000000000000000000000",
                "X-FG-Internal-Token": "",
            },
        )
        assert r.status_code == 404, (
            f"Expected 404 when no credential exists for rotation, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert body.get("detail", {}).get("code") == "PLATFORM_ADMIN_NOT_FOUND"
    finally:
        _clear_actor(app)


# ---------------------------------------------------------------------------
# N-13 — tenant admin cannot assign platform_admin
# ---------------------------------------------------------------------------


def test_n13_tenant_admin_cannot_assign_platform_admin():
    """Security Invariant 1: platform_admin must NOT become tenant-self-assignable.

    Verified at the constants level: PLATFORM_ONLY_CREDENTIAL_ROLES catches
    platform_admin before SELF_SERVICE_CREDENTIAL_ROLES check.
    """
    from api.tenant_admin import PLATFORM_ONLY_CREDENTIAL_ROLES, SELF_SERVICE_CREDENTIAL_ROLES

    assert "platform_admin" in PLATFORM_ONLY_CREDENTIAL_ROLES, (
        "platform_admin must be in PLATFORM_ONLY_CREDENTIAL_ROLES"
    )
    assert "platform_admin" not in SELF_SERVICE_CREDENTIAL_ROLES, (
        "platform_admin must NOT be in SELF_SERVICE_CREDENTIAL_ROLES"
    )


# ---------------------------------------------------------------------------
# N-15 — rotate carries platform_admin role to new credential generation
# ---------------------------------------------------------------------------


def test_n15_rotate_carries_platform_admin_role(app, engine, monkeypatch):
    """After rotation, the new credential must have platform_admin role assigned."""
    monkeypatch.setenv("FG_ENV", "test")
    _seed_internal_tenant(engine)
    _set_platform_actor(app)

    try:
        c = client_for(app)

        # Bootstrap first
        r1 = c.post(
            "/admin/system/platform-admin/bootstrap",
            headers={
                "X-API-Key": "ci-test-key-00000000000000000000000000000000",
                "X-FG-Internal-Token": "",
            },
        )
        assert r1.status_code == 201, r1.text
        original_cred_id = r1.json()["credential_id"]

        # Rotate
        r2 = c.post(
            "/admin/system/platform-admin/rotate",
            headers={
                "X-API-Key": "ci-test-key-00000000000000000000000000000000",
                "X-FG-Internal-Token": "",
            },
        )
        assert r2.status_code == 200, (
            f"Expected 200 on rotate, got {r2.status_code}: {r2.text}"
        )
        body2 = r2.json()
        assert body2["action"] == "rotated"
        new_cred_id = body2["credential_id"]
        assert new_cred_id != original_cred_id, "Rotation must produce a new credential_id"
        assert body2["plaintext_key"], "Rotation must return plaintext_key"

        # Verify new credential has platform_admin role in tenant_credential_roles
        from api.tenant_rbac import get_credential_role
        from sqlalchemy.orm import Session

        with Session(engine) as session:
            role = get_credential_role(
                session,
                tenant_id="frostgate-internal",
                credential_id=new_cred_id,
            )
        assert role == "platform_admin", (
            f"New credential after rotation must have platform_admin role, got: {role!r}"
        )

    finally:
        _clear_actor(app)
