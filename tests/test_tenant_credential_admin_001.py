"""
P-113.4 — Tenant Service Credential Administration — proof matrix.

All tests run against a SQLite in-process DB using the standard build_app fixtures.
Live production proof requires FG_LIVE_PROOF=1 (post-merge step).

Test matrix:
  C1-01  List returns empty for new tenant (no service credentials yet)
  C1-02  Issue returns plaintext_secret exactly once
  C1-03  Issued credential appears in list with correct name
  C1-04  Get credential by ID returns same record; no plaintext
  C1-05  Rotate returns new plaintext_secret; old credential becomes rotated
  C1-06  Suspend active credential → status=suspended
  C1-07  Resume suspended credential → status=active
  C1-08  Revoke active credential → revoked=True, idempotent
  C1-09  Revoke a rotated credential → 409 CREDENTIAL_STATE_CONFLICT
  C1-10  Assign self-service role → 200
  C1-11  Assign tenant_admin role → 403 ROLE_NOT_DELEGATABLE
  C1-12  Assign platform_admin role → 403 ROLE_NOT_DELEGATABLE
  C1-13  Assign unknown role → 422 INVALID_ROLE
  C1-14  List /rbac shows assignment after assign
  C1-15  Cross-tenant isolation: credential from tenant B → 404 when queried via tenant A
  C1-16  No plaintext_secret in list response
  C1-17  No plaintext_secret in get response
  C1-18  portal_access credential → 404 via credential-administration (type guard)
  C1-19  SELF_SERVICE_CREDENTIAL_ROLES ⊆ VALID_ROLE_NAMES (constants contract)
  C1-20  PLATFORM_ONLY_CREDENTIAL_ROLES ∩ SELF_SERVICE_CREDENTIAL_ROLES = ∅
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterator

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from api.actor_context import ActorContext, ROLE_PERMISSIONS
from api.auth_scopes import mint_key
from api.tenant_admin import (
    PLATFORM_ONLY_CREDENTIAL_ROLES,
    SELF_SERVICE_CREDENTIAL_ROLES,
)

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


# ---------------------------------------------------------------------------
# Helpers — DB seeding
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tid() -> str:
    return f"cred-admin-{uuid.uuid4().hex[:8]}"


def _ensure_tenant(engine, tenant_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, tenant_kind, lifecycle_state, display_name) "
                "VALUES (:tid, 'customer', 'active', :tid)"
            ),
            {"tid": tenant_id},
        )


def _seed_principal(engine, principal_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO fg_principals "
                "(id, principal_type, lifecycle_state, mfa_verified, "
                "authority_version, created_at, updated_at) "
                "VALUES (:id, 'human', 'active', 0, 1, :now, :now)"
            ),
            {"id": principal_id, "now": _now_iso()},
        )


def _seed_tenant_user(
    engine,
    *,
    tenant_id: str,
    user_id: str,
    email: str,
    role: str = "tenant_admin",
    active: bool = True,
    principal_id: str | None = None,
    identity_binding_status: str = "unbound",
    identity_provider: str | None = None,
    identity_subject: str | None = None,
) -> None:
    if principal_id:
        _seed_principal(engine, principal_id)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_users "
                "(id, tenant_id, email, display_name, role, active, identity_subject, "
                "identity_provider, identity_binding_status, principal_id, "
                "created_at, updated_at) "
                "VALUES (:id, :t, :e, :dn, :role, :active, :subject, :provider, "
                ":binding, :pid, :now, :now)"
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


def _seat_admin(engine, tenant_id: str) -> tuple[str, str, str]:
    """Create tenant + fg_principal + tenant_admin user. Returns (uid, pid, subject)."""
    _ensure_tenant(engine, tenant_id)
    pid = str(uuid.uuid4())
    uid = str(uuid.uuid4())
    subject = f"auth0|admin-{uid[:8]}"
    _seed_tenant_user(
        engine,
        tenant_id=tenant_id,
        user_id=uid,
        email=f"admin-{uid[:8]}@example.com",
        role="tenant_admin",
        principal_id=pid,
        identity_binding_status="bound",
        identity_provider="auth0",
        identity_subject=subject,
    )
    return uid, pid, subject


# ---------------------------------------------------------------------------
# Helpers — Auth override
# ---------------------------------------------------------------------------


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


def _admin_hdrs(tenant_id: str) -> dict[str, str]:
    return {"x-api-key": mint_key("admin:read", "admin:write", tenant_id=tenant_id)}


def _path(tenant_id: str, suffix: str = "") -> str:
    return f"/admin/tenants/{tenant_id}/credential-administration{suffix}"


def _qs(tenant_id: str) -> str:
    return f"?tenant_id={tenant_id}"


def _direct_issue(engine, tenant_id: str, name: str = "setup-key") -> str:
    """Issue a tenant_api_key via credential_authority. Returns credential_id."""
    from api.credential_authority import issue_credential

    result = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=str(uuid.uuid4()),
        metadata={"name": name},
        actor_id="test-setup",
    )
    return result.record.credential_id


# ---------------------------------------------------------------------------
# C1-01 — list returns empty for new tenant
# ---------------------------------------------------------------------------


def test_c1_01_list_empty(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.get(_path(tid) + _qs(tid), headers=_admin_hdrs(tid))
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["tenant_id"] == tid
    # mint_key() creates nameless tenant_api_key credentials for scope auth;
    # no user-named service credential should exist yet.
    named_items = [c for c in data["items"] if c.get("name") is not None]
    assert named_items == []


# ---------------------------------------------------------------------------
# C1-02 — issue returns plaintext_secret exactly once
# ---------------------------------------------------------------------------


def test_c1_02_issue_returns_plaintext_once(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.post(
                _path(tid) + _qs(tid),
                json={"name": "my-ci-key"},
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["plaintext_secret"] is not None
    assert data["name"] == "my-ci-key"
    assert data["status"] == "active"
    assert data["tenant_id"] == tid


# ---------------------------------------------------------------------------
# C1-03 — issued credential appears in list with correct name
# ---------------------------------------------------------------------------


def test_c1_03_issued_appears_in_list(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            issue_r = c.post(
                _path(tid) + _qs(tid),
                json={"name": "list-test-key"},
                headers=_admin_hdrs(tid),
            )
            assert issue_r.status_code == 200, issue_r.text
            cred_id = issue_r.json()["credential_id"]

            list_r = c.get(_path(tid) + _qs(tid), headers=_admin_hdrs(tid))
    finally:
        _clear_actor_override(app)
    assert list_r.status_code == 200, list_r.text
    items = list_r.json()["items"]
    ids = [c["credential_id"] for c in items]
    assert cred_id in ids
    match = next(c for c in items if c["credential_id"] == cred_id)
    assert match["name"] == "list-test-key"


# ---------------------------------------------------------------------------
# C1-04 — get credential by ID returns same record; no plaintext
# ---------------------------------------------------------------------------


def test_c1_04_get_by_id(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "get-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.get(
                _path(tid, f"/{cred_id}") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["credential_id"] == cred_id
    assert data["name"] == "get-test"
    assert "plaintext_secret" not in data


# ---------------------------------------------------------------------------
# C1-05 — rotate returns new plaintext_secret; old becomes rotated
# ---------------------------------------------------------------------------


def test_c1_05_rotate(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    old_id = _direct_issue(engine, tid, "rotate-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.post(
                _path(tid, f"/{old_id}/rotate") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["plaintext_secret"] is not None
    assert data["credential_id"] != old_id
    assert data["rotated_from_credential_id"] == old_id
    assert data["status"] == "active"


# ---------------------------------------------------------------------------
# C1-06 — suspend active credential → status=suspended
# ---------------------------------------------------------------------------


def test_c1_06_suspend(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "suspend-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.post(
                _path(tid, f"/{cred_id}/suspend") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "suspended"


# ---------------------------------------------------------------------------
# C1-07 — resume suspended credential → status=active
# ---------------------------------------------------------------------------


def test_c1_07_resume(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "resume-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            c.post(
                _path(tid, f"/{cred_id}/suspend") + _qs(tid), headers=_admin_hdrs(tid)
            )
            r = c.post(
                _path(tid, f"/{cred_id}/resume") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active"


# ---------------------------------------------------------------------------
# C1-08 — revoke active credential (idempotent)
# ---------------------------------------------------------------------------


def test_c1_08_revoke_idempotent(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "revoke-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r1 = c.delete(
                _path(tid, f"/{cred_id}") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
            r2 = c.delete(
                _path(tid, f"/{cred_id}") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r1.status_code == 200, r1.text
    assert r1.json()["revoked"] is True
    assert r2.status_code == 200, r2.text


# ---------------------------------------------------------------------------
# C1-09 — revoke a rotated credential → 409
# ---------------------------------------------------------------------------


def test_c1_09_revoke_rotated_conflicts(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    old_id = _direct_issue(engine, tid, "rotated-revoke-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            c.post(_path(tid, f"/{old_id}/rotate") + _qs(tid), headers=_admin_hdrs(tid))
            r = c.delete(
                _path(tid, f"/{old_id}") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "CREDENTIAL_STATE_CONFLICT"


# ---------------------------------------------------------------------------
# C1-10 — assign self-service role → 200
# ---------------------------------------------------------------------------


def test_c1_10_assign_self_service_role(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "role-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.put(
                _path(tid, f"/{cred_id}/role") + _qs(tid),
                json={"role": "analyst"},
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "analyst"


# ---------------------------------------------------------------------------
# C1-11 — assign tenant_admin role → 403 ROLE_NOT_DELEGATABLE
# ---------------------------------------------------------------------------


def test_c1_11_tenant_admin_role_denied(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "role-deny-1")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.put(
                _path(tid, f"/{cred_id}/role") + _qs(tid),
                json={"role": "tenant_admin"},
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "ROLE_NOT_DELEGATABLE"


# ---------------------------------------------------------------------------
# C1-12 — assign platform_admin role → 403 ROLE_NOT_DELEGATABLE
# ---------------------------------------------------------------------------


def test_c1_12_platform_admin_role_denied(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "role-deny-2")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.put(
                _path(tid, f"/{cred_id}/role") + _qs(tid),
                json={"role": "platform_admin"},
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "ROLE_NOT_DELEGATABLE"


# ---------------------------------------------------------------------------
# C1-13 — assign unknown role → 422 INVALID_ROLE
# ---------------------------------------------------------------------------


def test_c1_13_unknown_role_rejected(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "role-unknown")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.put(
                _path(tid, f"/{cred_id}/role") + _qs(tid),
                json={"role": "superadmin"},
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["code"] == "INVALID_ROLE"


# ---------------------------------------------------------------------------
# C1-14 — list /rbac shows assignment after assign
# ---------------------------------------------------------------------------


def test_c1_14_rbac_list(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "rbac-test")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            c.put(
                _path(tid, f"/{cred_id}/role") + _qs(tid),
                json={"role": "auditor"},
                headers=_admin_hdrs(tid),
            )
            r = c.get(
                _path(tid, "/rbac") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["tenant_id"] == tid
    assigned_ids = [a["credential_id"] for a in data["assignments"]]
    assert cred_id in assigned_ids


# ---------------------------------------------------------------------------
# C1-15 — cross-tenant isolation
# ---------------------------------------------------------------------------


def test_c1_15_cross_tenant_isolation(app, engine):
    tid_a = _tid()
    tid_b = _tid()
    uid_a, _, subject_a = _seat_admin(engine, tid_a)
    _seat_admin(engine, tid_b)
    cred_id_b = _direct_issue(engine, tid_b, "tenant-b-key")

    _install_actor_override(
        app, subject=subject_a, tenant_id=tid_a, membership_id=uid_a
    )
    try:
        with TestClient(app) as c:
            r = c.get(
                _path(tid_a, f"/{cred_id_b}") + _qs(tid_a),
                headers=_admin_hdrs(tid_a),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 404, r.text


# ---------------------------------------------------------------------------
# C1-16 — no plaintext_secret in list response
# ---------------------------------------------------------------------------


def test_c1_16_no_plaintext_in_list(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    _direct_issue(engine, tid, "no-plaintext-list")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.get(_path(tid) + _qs(tid), headers=_admin_hdrs(tid))
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    for item in r.json()["items"]:
        assert "plaintext_secret" not in item
        assert "secret" not in item


# ---------------------------------------------------------------------------
# C1-17 — no plaintext_secret in get response
# ---------------------------------------------------------------------------


def test_c1_17_no_plaintext_in_get(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)
    cred_id = _direct_issue(engine, tid, "no-plaintext-get")
    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.get(
                _path(tid, f"/{cred_id}") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "plaintext_secret" not in data
    assert "secret" not in data


# ---------------------------------------------------------------------------
# C1-18 — portal_access credential → 404 (type guard)
# ---------------------------------------------------------------------------


def test_c1_18_wrong_credential_type(app, engine):
    tid = _tid()
    uid, _, subject = _seat_admin(engine, tid)

    from api.credential_authority import issue_credential

    portal_result = issue_credential(
        engine,
        tenant_id=tid,
        credential_type="portal_access",
        credential_slot=str(uuid.uuid4()),
        actor_id="test-setup",
    )
    portal_cred_id = portal_result.record.credential_id

    _install_actor_override(app, subject=subject, tenant_id=tid, membership_id=uid)
    try:
        with TestClient(app) as c:
            r = c.get(
                _path(tid, f"/{portal_cred_id}") + _qs(tid),
                headers=_admin_hdrs(tid),
            )
    finally:
        _clear_actor_override(app)
    assert r.status_code == 404, r.text


# ---------------------------------------------------------------------------
# C1-19 / C1-20 — constants contract
# ---------------------------------------------------------------------------


def test_c1_19_self_service_roles_valid():
    from api.tenant_rbac import VALID_ROLE_NAMES

    assert SELF_SERVICE_CREDENTIAL_ROLES.issubset(VALID_ROLE_NAMES)


def test_c1_20_platform_only_disjoint_from_self_service():
    assert SELF_SERVICE_CREDENTIAL_ROLES.isdisjoint(PLATFORM_ONLY_CREDENTIAL_ROLES)
