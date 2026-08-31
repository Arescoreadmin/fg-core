"""tests/test_client_lifecycle_001.py — CLIENT-LIFECYCLE-001 test suite.

Covers the canonical client readiness evaluator and its HTTP surface.

  A. Evaluator unit tests — pure function, direct DB calls
  B. Precedence determinism — simultaneous failures yield stable primary state
  C. API route tests — dual-path auth, schema, HTTP semantics

Auth modes:
  - Platform admin: API key with ``admin:write`` scope resolves to platform_admin.
  - Tenant admin: dependency_override installs ActorContext with role=tenant_admin
    and a DB-seeded bound tenant_users row.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Iterator

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from api.actor_context import ActorContext, ROLE_PERMISSIONS
from api.auth_scopes import mint_key
from api.client_lifecycle import (
    ACTION_BIND_ADMIN_IDENTITY,
    ACTION_BOOTSTRAP_ADMIN,
    ACTION_INVITE_MEMBERS,
    BLOCKER_NO_BOUND_ADMIN,
    BLOCKER_TENANT_NOT_FOUND,
    BLOCKER_TENANT_SUSPENDED,
    LIFECYCLE_VERSION,
    STATE_ADMIN_UNBOUND,
    STATE_ADMIN_UNSET,
    STATE_OPERATIONAL,
    STATE_TENANT_NOT_FOUND,
    STATE_TENANT_SUSPENDED,
    WARN_NO_ACTIVE_MEMBERS,
    evaluate_client_lifecycle,
)


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

_TENANT_CL = "cl001-tenant-a"
_TENANT_CL_B = "cl001-tenant-b"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_tenant(engine, tenant_id: str, lifecycle_state: str = "active") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO tenants
                    (tenant_id, display_name, lifecycle_state,
                     created_at, updated_at)
                VALUES
                    (:tid, :name, :state, :now, :now)
                """
            ),
            {
                "tid": tenant_id,
                "name": f"Test {tenant_id}",
                "state": lifecycle_state,
                "now": _now_iso(),
            },
        )


def _seed_principal(engine, principal_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO fg_principals
                    (id, principal_type, lifecycle_state, mfa_verified,
                     authority_version, created_at, updated_at)
                VALUES
                    (:id, 'human', 'active', 0, 1, :now, :now)
                """
            ),
            {"id": principal_id, "now": _now_iso()},
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
    principal_id: str | None = None,
    identity_binding_status: str = "unbound",
    identity_provider: str | None = None,
) -> None:
    if principal_id:
        _seed_principal(engine, principal_id)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO tenant_users
                    (id, tenant_id, email, display_name, role, active,
                     identity_subject, identity_provider,
                     identity_binding_status, principal_id,
                     created_at, updated_at)
                VALUES
                    (:id, :t, :e, :dn, :role, :active,
                     :subject, :provider, :binding, :pid, :now, :now)
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
                "binding": identity_binding_status,
                "pid": principal_id,
                "now": _now_iso(),
            },
        )


def _install_actor_override(
    app,
    *,
    subject: str,
    tenant_id: str,
    membership_id: str | None = None,
    role: str = "tenant_admin",
) -> None:
    from api.auth_dispatch import get_actor_context

    def _override() -> ActorContext:
        return ActorContext(
            subject=subject,
            email=f"{subject}@example.com",
            name=subject,
            permissions=ROLE_PERMISSIONS.get(role, frozenset()),
            roles=[role],
            auth_source="dev_bypass",
            tenant_id=tenant_id,
            membership_id=membership_id,
        )

    app.dependency_overrides[get_actor_context] = _override


def _clear_actor_override(app) -> None:
    from api.auth_dispatch import get_actor_context

    app.dependency_overrides.pop(get_actor_context, None)


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


def _platform_headers(tenant_id: str) -> dict[str, str]:
    key = mint_key("admin:read", "admin:write", tenant_id=tenant_id)
    return {"x-api-key": key}


def _tenant_admin_headers(tenant_id: str) -> dict[str, str]:
    key = mint_key("admin:read", "admin:write", tenant_id=tenant_id)
    return {"x-api-key": key}


def _get_db_session(app):
    from api.db import get_sessionmaker

    return get_sessionmaker()()


# ---------------------------------------------------------------------------
# A. Evaluator unit tests — pure function
# ---------------------------------------------------------------------------


class TestEvaluatorUnit:
    def test_a1_tenant_not_found(self, engine, app):
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "no-such-tenant-cl001")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_TENANT_NOT_FOUND
        assert result.operational is False
        assert result.repairable is False
        assert BLOCKER_TENANT_NOT_FOUND in result.blockers
        assert result.lifecycle_version == LIFECYCLE_VERSION
        assert result.has_bound_admin is False

    def test_a2_tenant_suspended(self, engine, app):
        _seed_tenant(engine, _TENANT_CL, lifecycle_state="suspended")
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, _TENANT_CL)
        finally:
            db.close()

        assert result.lifecycle_state == STATE_TENANT_SUSPENDED
        assert result.operational is False
        assert result.repairable is False
        assert BLOCKER_TENANT_SUSPENDED in result.blockers
        assert result.tenant_canonical_state == "suspended"

    def test_a2b_tenant_archived(self, engine, app):
        _seed_tenant(engine, "cl001-archived", lifecycle_state="archived")
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-archived")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_TENANT_SUSPENDED
        assert result.operational is False

    def test_a3_no_admin_row(self, engine, app):
        _seed_tenant(engine, "cl001-no-admin")
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-no-admin")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_ADMIN_UNSET
        assert result.operational is False
        assert result.repairable is True
        assert BLOCKER_NO_BOUND_ADMIN in result.blockers
        assert ACTION_BOOTSTRAP_ADMIN in result.next_actions
        assert result.has_bound_admin is False

    def test_a4_admin_unbound(self, engine, app):
        _seed_tenant(engine, "cl001-unbound")
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-unbound",
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="unbound",
            principal_id=None,
        )
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-unbound")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_ADMIN_UNBOUND
        assert result.operational is False
        assert result.repairable is False
        assert BLOCKER_NO_BOUND_ADMIN in result.blockers
        assert ACTION_BIND_ADMIN_IDENTITY in result.next_actions
        assert result.has_bound_admin is False

    def test_a5_operational_no_members(self, engine, app):
        _seed_tenant(engine, "cl001-op-no-members")
        pid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-op-no-members",
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
            identity_subject="auth0|admin",
            identity_provider="auth0",
        )
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-op-no-members")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_OPERATIONAL
        assert result.operational is True
        assert result.repairable is False
        assert len(result.blockers) == 0
        assert WARN_NO_ACTIVE_MEMBERS in result.warnings
        assert ACTION_INVITE_MEMBERS in result.next_actions
        assert result.has_bound_admin is True
        assert result.active_member_count == 0

    def test_a6_fully_operational(self, engine, app):
        _seed_tenant(engine, "cl001-full-op")
        pid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-full-op",
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
            identity_subject="auth0|admin",
            identity_provider="auth0",
        )
        member_id = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-full-op",
            user_id=member_id,
            email="user@example.com",
            role="user",
            active=True,
        )
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-full-op")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_OPERATIONAL
        assert result.operational is True
        assert len(result.blockers) == 0
        assert len(result.warnings) == 0
        assert len(result.next_actions) == 0
        assert result.active_member_count == 1

    def test_a7_inactive_admin_not_counted(self, engine, app):
        _seed_tenant(engine, "cl001-inactive-admin")
        pid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-inactive-admin",
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=False,
            identity_binding_status="bound",
            principal_id=pid,
        )
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-inactive-admin")
        finally:
            db.close()

        # Inactive admin → treated as no active admin
        assert result.lifecycle_state == STATE_ADMIN_UNSET
        assert result.operational is False

    def test_a8_mixed_admins_one_bound(self, engine, app):
        _seed_tenant(engine, "cl001-mixed-admin")
        # Unbound admin
        _seed_tenant_user(
            engine,
            tenant_id="cl001-mixed-admin",
            user_id=str(uuid.uuid4()),
            email="unbound@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="unbound",
        )
        # Bound admin
        pid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-mixed-admin",
            user_id=str(uuid.uuid4()),
            email="bound@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
            identity_subject="auth0|bound",
            identity_provider="auth0",
        )
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-mixed-admin")
        finally:
            db.close()

        # At least one bound → operational
        assert result.lifecycle_state == STATE_OPERATIONAL
        assert result.operational is True
        assert result.has_bound_admin is True

    def test_a9_inactive_member_not_counted(self, engine, app):
        _seed_tenant(engine, "cl001-inactive-member")
        pid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-inactive-member",
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
        )
        # Inactive non-admin member
        _seed_tenant_user(
            engine,
            tenant_id="cl001-inactive-member",
            user_id=str(uuid.uuid4()),
            email="inactive@example.com",
            role="user",
            active=False,
        )
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-inactive-member")
        finally:
            db.close()

        assert result.operational is True
        assert result.active_member_count == 0
        assert WARN_NO_ACTIVE_MEMBERS in result.warnings

    def test_a10_inactive_principal_not_counted_as_bound(self, engine, app):
        # A bound admin whose fg_principals row is suspended must NOT make
        # the evaluator report operational=True. Canonical identity resolution
        # rejects inactive principals; the evaluator must agree.
        _seed_tenant(engine, "cl001-inactive-principal")
        pid = str(uuid.uuid4())
        # Seed the principal as active first (FK requirement)
        _seed_principal(engine, pid)
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-inactive-principal",
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
            identity_subject="auth0|inactive-principal",
            identity_provider="auth0",
        )
        # Deactivate the principal after seeding the tenant_user FK
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE fg_principals SET lifecycle_state = 'suspended' "
                    "WHERE id = :pid"
                ),
                {"pid": pid},
            )
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-inactive-principal")
        finally:
            db.close()

        # Suspended principal → admin not counted as bound → admin_unbound
        assert result.lifecycle_state == STATE_ADMIN_UNBOUND
        assert result.operational is False
        assert result.has_bound_admin is False


# ---------------------------------------------------------------------------
# B. Precedence determinism
# ---------------------------------------------------------------------------


class TestPrecedenceDeterminism:
    def test_b1_suspended_beats_no_admin(self, engine, app):
        # Tenant is suspended AND has no admin — suspended takes precedence
        _seed_tenant(engine, "cl001-b1", lifecycle_state="suspended")
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-b1")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_TENANT_SUSPENDED
        assert BLOCKER_TENANT_SUSPENDED in result.blockers

    def test_b2_not_found_beats_all(self, engine, app):
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-b2-never-seeded")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_TENANT_NOT_FOUND

    def test_b3_unset_beats_unbound(self, engine, app):
        # Tenant is active, no admin at all (not even unbound)
        _seed_tenant(engine, "cl001-b3")
        db = _get_db_session(app)
        try:
            result = evaluate_client_lifecycle(db, "cl001-b3")
        finally:
            db.close()

        assert result.lifecycle_state == STATE_ADMIN_UNSET

    def test_b4_result_is_deterministic_on_repeated_calls(self, engine, app):
        # Same DB state → identical result on repeated evaluations
        _seed_tenant(engine, "cl001-b4")
        pid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id="cl001-b4",
            user_id=str(uuid.uuid4()),
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
        )
        db = _get_db_session(app)
        try:
            r1 = evaluate_client_lifecycle(db, "cl001-b4")
            r2 = evaluate_client_lifecycle(db, "cl001-b4")
        finally:
            db.close()

        assert r1 == r2

    def test_b5_operational_false_never_on_unknown_state(self, engine, app):
        # Tenant with any non-active lifecycle_state must NOT be operational
        for state in ("suspended", "archived", "deleted"):
            tid = f"cl001-b5-{state}"
            _seed_tenant(engine, tid, lifecycle_state=state)
            db = _get_db_session(app)
            try:
                result = evaluate_client_lifecycle(db, tid)
            finally:
                db.close()
            assert result.operational is False, (
                f"unexpected operational=True for state={state}"
            )


# ---------------------------------------------------------------------------
# C. API route tests
# ---------------------------------------------------------------------------


class TestLifecycleRoute:
    def test_c1_platform_admin_reads_any_tenant(self, engine, app, client):
        _seed_tenant(engine, _TENANT_CL_B)
        resp = client.get(
            f"/admin/tenants/{_TENANT_CL_B}/lifecycle",
            headers=_platform_headers(_TENANT_CL_B),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == _TENANT_CL_B
        assert "lifecycle_state" in data
        assert "operational" in data
        assert "lifecycle_version" in data
        assert isinstance(data["blockers"], list)
        assert isinstance(data["warnings"], list)
        assert isinstance(data["next_actions"], list)
        assert "diagnostics" in data

    def test_c2_tenant_admin_reads_own_tenant(self, engine, app, client):
        tid = "cl001-c2"
        _seed_tenant(engine, tid)
        pid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id=tid,
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
            identity_subject="auth0|c2admin",
            identity_provider="auth0",
        )
        _install_actor_override(
            app, subject="auth0|c2admin", tenant_id=tid, membership_id=uid
        )
        try:
            resp = client.get(
                f"/admin/tenants/{tid}/lifecycle",
                headers=_tenant_admin_headers(tid),
            )
        finally:
            _clear_actor_override(app)

        assert resp.status_code == 200
        data = resp.json()
        assert data["lifecycle_state"] == STATE_OPERATIONAL
        assert data["operational"] is True

    def test_c3_tenant_admin_denied_cross_tenant(self, engine, app, client):
        tid_own = "cl001-c3-own"
        tid_other = "cl001-c3-other"
        _seed_tenant(engine, tid_own)
        _seed_tenant(engine, tid_other)
        pid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        _seed_tenant_user(
            engine,
            tenant_id=tid_own,
            user_id=uid,
            email="admin@example.com",
            role="tenant_admin",
            active=True,
            identity_binding_status="bound",
            principal_id=pid,
            identity_subject="auth0|c3admin",
            identity_provider="auth0",
        )
        # Actor is bound to tid_own but tries to read tid_other
        _install_actor_override(
            app, subject="auth0|c3admin", tenant_id=tid_own, membership_id=uid
        )
        try:
            resp = client.get(
                f"/admin/tenants/{tid_other}/lifecycle",
                headers=_tenant_admin_headers(tid_own),
            )
        finally:
            _clear_actor_override(app)

        assert resp.status_code == 403

    def test_c4_unauthenticated_denied(self, engine, app, client):
        _seed_tenant(engine, "cl001-c4")
        resp = client.get("/admin/tenants/cl001-c4/lifecycle")
        assert resp.status_code in (401, 403)

    def test_c5_tenant_not_found_returns_404(self, engine, app, client):
        # Mint the platform key under a real seeded tenant (mint_key creates the
        # tenant row for its tenant_id). Query a different, never-seeded tenant.
        _seed_tenant(engine, "cl001-c5-platform")
        resp = client.get(
            "/admin/tenants/cl001-c5-query-never-exists/lifecycle",
            headers=_platform_headers("cl001-c5-platform"),
        )
        assert resp.status_code == 404
        data = resp.json()
        assert data["detail"]["code"] == "TENANT_NOT_FOUND"

    def test_c6_lifecycle_state_admin_unset_in_response(self, engine, app, client):
        tid = "cl001-c6"
        _seed_tenant(engine, tid)
        resp = client.get(
            f"/admin/tenants/{tid}/lifecycle",
            headers=_platform_headers(tid),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["lifecycle_state"] == STATE_ADMIN_UNSET
        assert data["operational"] is False
        assert data["repairable"] is True
        assert "NO_BOUND_ADMIN" in data["blockers"]

    def test_c7_diagnostics_field_shape(self, engine, app, client):
        tid = "cl001-c7"
        _seed_tenant(engine, tid)
        resp = client.get(
            f"/admin/tenants/{tid}/lifecycle",
            headers=_platform_headers(tid),
        )
        assert resp.status_code == 200
        diag = resp.json()["diagnostics"]
        assert "tenant_canonical_state" in diag
        assert "has_bound_admin" in diag
        assert "active_member_count" in diag

    def test_c8_lifecycle_version_is_integer(self, engine, app, client):
        tid = "cl001-c8"
        _seed_tenant(engine, tid)
        resp = client.get(
            f"/admin/tenants/{tid}/lifecycle",
            headers=_platform_headers(tid),
        )
        assert resp.status_code == 200
        assert isinstance(resp.json()["lifecycle_version"], int)

    def test_c9_platform_admin_reads_suspended_tenant(self, engine, app, client):
        # Mint key under a separate active tenant; platform admin can read any tenant.
        _seed_tenant(engine, "cl001-c9-platform")
        _seed_tenant(engine, "cl001-c9-target", lifecycle_state="suspended")
        resp = client.get(
            "/admin/tenants/cl001-c9-target/lifecycle",
            headers=_platform_headers("cl001-c9-platform"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["lifecycle_state"] == STATE_TENANT_SUSPENDED
        assert data["operational"] is False
