"""
tests/test_tenant_rbac.py — Functional tests for intra-tenant RBAC (PR 57).

Coverage:
- Role hierarchy: role_satisfies / role_satisfies_any
- Scope expansion: get_role_scopes
- DB operations: assign_role, revoke_role, get_key_role, list_role_assignments
- Audit trail: every assignment and revocation appends a record
- Deny-by-default: require_role raises 403 when key has no role or insufficient role
- require_role: 401 when unauthenticated, 403 for wrong role, pass for correct role
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from sqlalchemy import text

from api.tenant_rbac import (
    BUILTIN_ROLES,
    VALID_ROLE_NAMES,
    assign_role,
    get_key_role,
    get_role_audit_log,
    get_role_scopes,
    list_role_assignments,
    require_role,
    revoke_role,
    role_satisfies,
    role_satisfies_any,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "rbac-test.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")

    from api.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    SessionLocal = get_sessionmaker(sqlite_path=db_path)
    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()
        reset_engine_cache()


def _insert_key(
    conn, *, prefix: str, tenant_id: str, scopes_csv: str = "keys:read"
) -> None:
    """Insert a minimal api_keys row for testing."""
    conn.execute(
        text(
            "INSERT INTO api_keys (name, prefix, key_hash, scopes_csv, tenant_id, enabled) "
            "VALUES (:name, :prefix, :key_hash, :scopes_csv, :tenant_id, 1)"
        ),
        {
            "name": f"test:{prefix}",
            "prefix": prefix,
            "key_hash": f"hash_{prefix}",
            "scopes_csv": scopes_csv,
            "tenant_id": tenant_id,
        },
    )
    conn.commit()


def _make_request(key_prefix: str, tenant_id: str) -> Request:
    """Create a minimal mock Request with auth state."""
    scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
    req = Request(scope)
    req.state.auth = SimpleNamespace(key_prefix=key_prefix, tenant_id=tenant_id)
    req.state.tenant_id = tenant_id
    req.state.tenant_is_key_bound = True
    return req


def _make_unauth_request() -> Request:
    """Create a Request with no auth state."""
    scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
    return Request(scope)


# ---------------------------------------------------------------------------
# TestRoleHierarchy
# ---------------------------------------------------------------------------


class TestRoleHierarchy:
    def test_tenant_admin_satisfies_all_roles(self):
        for role in BUILTIN_ROLES:
            assert role_satisfies("tenant_admin", role)

    def test_governance_admin_satisfies_subordinate_roles(self):
        assert role_satisfies("governance_admin", "governance_admin")
        assert role_satisfies("governance_admin", "analyst")
        assert role_satisfies("governance_admin", "auditor")
        assert role_satisfies("governance_admin", "read_only")

    def test_governance_admin_does_not_satisfy_tenant_admin(self):
        assert not role_satisfies("governance_admin", "tenant_admin")

    def test_analyst_satisfies_only_analyst_and_read_only(self):
        assert role_satisfies("analyst", "analyst")
        assert role_satisfies("analyst", "read_only")
        assert not role_satisfies("analyst", "auditor")
        assert not role_satisfies("analyst", "governance_admin")
        assert not role_satisfies("analyst", "tenant_admin")

    def test_auditor_satisfies_only_auditor_and_read_only(self):
        assert role_satisfies("auditor", "auditor")
        assert role_satisfies("auditor", "read_only")
        assert not role_satisfies("auditor", "analyst")
        assert not role_satisfies("auditor", "governance_admin")
        assert not role_satisfies("auditor", "tenant_admin")

    def test_read_only_satisfies_only_itself(self):
        assert role_satisfies("read_only", "read_only")
        for role in ("analyst", "auditor", "governance_admin", "tenant_admin"):
            assert not role_satisfies("read_only", role)

    def test_none_satisfies_nothing(self):
        for role in BUILTIN_ROLES:
            assert not role_satisfies(None, role)

    def test_unknown_role_satisfies_nothing(self):
        for role in BUILTIN_ROLES:
            assert not role_satisfies("super_hacker", role)

    def test_role_satisfies_any_short_circuits(self):
        assert role_satisfies_any("analyst", {"analyst", "auditor"})
        assert role_satisfies_any("tenant_admin", {"read_only"})
        assert not role_satisfies_any("read_only", {"analyst", "auditor"})
        assert not role_satisfies_any(None, {"read_only"})


# ---------------------------------------------------------------------------
# TestRoleScopes
# ---------------------------------------------------------------------------


class TestRoleScopes:
    def test_tenant_admin_has_all_major_scopes(self):
        scopes = get_role_scopes("tenant_admin")
        for expected in ("governance:write", "audit:read", "keys:write", "admin:read"):
            assert expected in scopes

    def test_read_only_has_minimal_scopes(self):
        scopes = get_role_scopes("read_only")
        assert "rag:read" in scopes
        assert "governance:write" not in scopes
        assert "keys:write" not in scopes

    def test_unknown_role_returns_empty(self):
        assert get_role_scopes("nonexistent") == frozenset()

    def test_none_returns_empty(self):
        assert get_role_scopes(None) == frozenset()

    def test_all_roles_have_nonempty_scopes(self):
        for role in BUILTIN_ROLES:
            assert get_role_scopes(role), f"{role} has empty scopes"


# ---------------------------------------------------------------------------
# TestAssignRoleDB
# ---------------------------------------------------------------------------


class TestAssignRoleDB:
    def test_assign_role_persists(self, db):
        _insert_key(db, prefix="kA", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor-key",
            target_key_prefix="kA",
            role_name="analyst",
        )
        assert get_key_role(db, tenant_id="tenant-a", key_prefix="kA") == "analyst"

    def test_assign_updates_existing_role(self, db):
        _insert_key(db, prefix="kB", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kB",
            role_name="read_only",
        )
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kB",
            role_name="governance_admin",
        )
        assert (
            get_key_role(db, tenant_id="tenant-a", key_prefix="kB")
            == "governance_admin"
        )

    def test_assign_unknown_role_raises(self, db):
        _insert_key(db, prefix="kC", tenant_id="tenant-a")
        with pytest.raises(ValueError, match="Unknown role"):
            assign_role(
                db,
                tenant_id="tenant-a",
                actor_key_prefix="actor",
                target_key_prefix="kC",
                role_name="superuser",
            )

    def test_assign_to_wrong_tenant_raises(self, db):
        _insert_key(db, prefix="kD", tenant_id="tenant-a")
        with pytest.raises(ValueError, match="not found"):
            assign_role(
                db,
                tenant_id="tenant-b",
                actor_key_prefix="actor",
                target_key_prefix="kD",
                role_name="analyst",
            )

    def test_revoke_clears_role(self, db):
        _insert_key(db, prefix="kE", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kE",
            role_name="auditor",
        )
        revoke_role(
            db, tenant_id="tenant-a", actor_key_prefix="actor", target_key_prefix="kE"
        )
        assert get_key_role(db, tenant_id="tenant-a", key_prefix="kE") is None

    def test_get_key_role_returns_none_when_no_role(self, db):
        _insert_key(db, prefix="kF", tenant_id="tenant-a")
        assert get_key_role(db, tenant_id="tenant-a", key_prefix="kF") is None

    def test_list_assignments_only_returns_keys_with_roles(self, db):
        _insert_key(db, prefix="kG", tenant_id="tenant-b")
        _insert_key(db, prefix="kH", tenant_id="tenant-b")
        assign_role(
            db,
            tenant_id="tenant-b",
            actor_key_prefix="actor",
            target_key_prefix="kG",
            role_name="analyst",
        )
        assignments = list_role_assignments(db, tenant_id="tenant-b")
        prefixes = [a["key_prefix"] for a in assignments]
        assert "kG" in prefixes
        assert "kH" not in prefixes

    def test_all_builtin_roles_accepted(self, db):
        for i, role in enumerate(BUILTIN_ROLES):
            prefix = f"k-builtin-{i}"
            _insert_key(db, prefix=prefix, tenant_id="tenant-c")
            result = assign_role(
                db,
                tenant_id="tenant-c",
                actor_key_prefix="actor",
                target_key_prefix=prefix,
                role_name=role,
            )
            assert result["role"] == role


# ---------------------------------------------------------------------------
# TestRoleAuditTrail
# ---------------------------------------------------------------------------


class TestRoleAuditTrail:
    def test_assign_creates_audit_record(self, db):
        _insert_key(db, prefix="kAudit1", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor-k",
            target_key_prefix="kAudit1",
            role_name="analyst",
        )
        log = get_role_audit_log(db, tenant_id="tenant-a")
        assert any(
            e["action"] == "assign_role" and e["target_key_prefix"] == "kAudit1"
            for e in log
        )

    def test_revoke_creates_audit_record(self, db):
        _insert_key(db, prefix="kAudit2", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor-k",
            target_key_prefix="kAudit2",
            role_name="auditor",
        )
        revoke_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor-k",
            target_key_prefix="kAudit2",
        )
        log = get_role_audit_log(db, tenant_id="tenant-a")
        assert any(
            e["action"] == "revoke_role" and e["target_key_prefix"] == "kAudit2"
            for e in log
        )

    def test_audit_records_have_unique_event_ids(self, db):
        _insert_key(db, prefix="kAudit3", tenant_id="tenant-a")
        for role in ("analyst", "auditor", "read_only"):
            assign_role(
                db,
                tenant_id="tenant-a",
                actor_key_prefix="actor",
                target_key_prefix="kAudit3",
                role_name=role,
            )
        log = get_role_audit_log(db, tenant_id="tenant-a")
        event_ids = [e["event_id"] for e in log]
        assert len(event_ids) == len(set(event_ids))

    def test_audit_scoped_to_tenant(self, db):
        _insert_key(db, prefix="kAuditX", tenant_id="tenant-x")
        _insert_key(db, prefix="kAuditY", tenant_id="tenant-y")
        assign_role(
            db,
            tenant_id="tenant-x",
            actor_key_prefix="actor",
            target_key_prefix="kAuditX",
            role_name="analyst",
        )
        assign_role(
            db,
            tenant_id="tenant-y",
            actor_key_prefix="actor",
            target_key_prefix="kAuditY",
            role_name="auditor",
        )

        log_x = get_role_audit_log(db, tenant_id="tenant-x")
        log_y = get_role_audit_log(db, tenant_id="tenant-y")

        assert all(e["target_key_prefix"] == "kAuditX" for e in log_x)
        assert all(e["target_key_prefix"] == "kAuditY" for e in log_y)


# ---------------------------------------------------------------------------
# TestDenyByDefault (require_role FastAPI dependency)
# ---------------------------------------------------------------------------


class TestDenyByDefault:
    def test_unauthenticated_request_raises_401(self, db):
        dep = require_role("read_only")
        req = _make_unauth_request()
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 401

    def test_key_with_no_role_raises_403(self, db):
        _insert_key(db, prefix="kNoRole", tenant_id="tenant-a")
        dep = require_role("read_only")
        req = _make_request(key_prefix="kNoRole", tenant_id="tenant-a")
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_insufficient_role_raises_403(self, db):
        _insert_key(db, prefix="kLow", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kLow",
            role_name="read_only",
        )
        dep = require_role("governance_admin")
        req = _make_request(key_prefix="kLow", tenant_id="tenant-a")
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_exact_role_passes(self, db):
        _insert_key(db, prefix="kExact", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kExact",
            role_name="auditor",
        )
        dep = require_role("auditor")
        req = _make_request(key_prefix="kExact", tenant_id="tenant-a")
        dep(request=req, conn=db)  # should not raise

    def test_superior_role_satisfies_require_role(self, db):
        _insert_key(db, prefix="kSuper", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kSuper",
            role_name="tenant_admin",
        )
        for required_role in BUILTIN_ROLES:
            dep = require_role(required_role)
            req = _make_request(key_prefix="kSuper", tenant_id="tenant-a")
            dep(request=req, conn=db)  # must not raise for any role

    def test_revoked_role_raises_403(self, db):
        _insert_key(db, prefix="kRevoked", tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kRevoked",
            role_name="analyst",
        )
        revoke_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            target_key_prefix="kRevoked",
        )
        dep = require_role("analyst")
        req = _make_request(key_prefix="kRevoked", tenant_id="tenant-a")
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_403_response_includes_required_roles(self, db):
        _insert_key(db, prefix="kErr", tenant_id="tenant-a")
        dep = require_role("governance_admin", "tenant_admin")
        req = _make_request(key_prefix="kErr", tenant_id="tenant-a")
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        detail = exc_info.value.detail
        assert detail["code"] == "RBAC_INSUFFICIENT_ROLE"
        assert "governance_admin" in detail["required_roles"]
        assert "tenant_admin" in detail["required_roles"]


# ---------------------------------------------------------------------------
# TestValidRoleNames
# ---------------------------------------------------------------------------


class TestValidRoleNames:
    def test_all_builtin_roles_are_valid(self):
        for role in BUILTIN_ROLES:
            assert role in VALID_ROLE_NAMES

    def test_valid_role_names_covers_all_builtins(self):
        assert VALID_ROLE_NAMES == frozenset(BUILTIN_ROLES)

    def test_invalid_role_raises_value_error(self, db):
        _insert_key(db, prefix="kVal", tenant_id="tenant-a")
        with pytest.raises(ValueError):
            assign_role(
                db,
                tenant_id="tenant-a",
                actor_key_prefix="a",
                target_key_prefix="kVal",
                role_name="invalid_role",
            )
