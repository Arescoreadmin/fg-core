"""
tests/test_tenant_rbac.py — Functional tests for intra-tenant RBAC (R4.10).

Coverage:
- Role hierarchy: role_satisfies / role_satisfies_any (pure logic, unchanged)
- Scope expansion: get_role_scopes (pure logic, unchanged)
- Canonical DB operations: assign_role, revoke_role, get_credential_role, list_role_assignments
- Audit trail: every assignment and revocation appends a record with target_credential_id
- Deny-by-default: require_role raises 403 when credential has no role or insufficient role
- require_role: 401 when unauthenticated, 403 for wrong role, pass for correct role
- Canonical identity: credential_id-based lookup is unambiguous for any UUID pair
- Scope-less authorization: require_role passes based on role alone, not scopes_csv
- Legacy isolation: api_keys.role cannot influence canonical credential role (RBAC-7)
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from sqlalchemy import text

from api.tenant_rbac import (
    BUILTIN_ROLES,
    VALID_ROLE_NAMES,
    assign_role,
    get_credential_role,
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


def _insert_credential(conn, *, tenant_id: str) -> str:
    """Insert a minimal tenant_credentials row and return its credential_id (UUID string)."""
    credential_id = str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO tenant_credentials "
            "(credential_id, tenant_id, credential_type, credential_slot, generation, "
            "lookup_fingerprint, lookup_key_version, secret_prefix, secret_hash, "
            "hash_algorithm, hash_params, status, issued_at, approximate_use_count, schema_version) "
            "VALUES "
            "(:cid, :tid, 'test_credential', :slot, 1, "
            ":cid, 1, 'tst_', 'test_hash', 'sha256', '{}', 'active', CURRENT_TIMESTAMP, 0, 1)"
        ),
        {"cid": credential_id, "tid": tenant_id, "slot": f"test:{credential_id[:8]}"},
    )
    conn.commit()
    return credential_id


def _make_request(
    key_prefix: str, tenant_id: str, credential_id: str | None = None
) -> Request:
    """Create a minimal mock Request with canonical credential_id auth state."""
    scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
    req: Request = Request(scope)
    req.state.auth = SimpleNamespace(
        key_prefix=key_prefix, tenant_id=tenant_id, credential_id=credential_id
    )
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
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor-key",
            credential_id=cid,
            role_name="analyst",
        )
        assert (
            get_credential_role(db, tenant_id="tenant-a", credential_id=cid)
            == "analyst"
        )

    def test_assign_updates_existing_role(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="read_only",
        )
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="governance_admin",
        )
        assert (
            get_credential_role(db, tenant_id="tenant-a", credential_id=cid)
            == "governance_admin"
        )

    def test_assign_unknown_role_raises(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        with pytest.raises(ValueError, match="Unknown role"):
            assign_role(
                db,
                tenant_id="tenant-a",
                actor_key_prefix="actor",
                credential_id=cid,
                role_name="superuser",
            )

    def test_assign_to_wrong_tenant_raises(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        with pytest.raises(ValueError, match="not found"):
            assign_role(
                db,
                tenant_id="tenant-b",
                actor_key_prefix="actor",
                credential_id=cid,
                role_name="analyst",
            )

    def test_revoke_clears_role(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="auditor",
        )
        revoke_role(
            db, tenant_id="tenant-a", actor_key_prefix="actor", credential_id=cid
        )
        assert get_credential_role(db, tenant_id="tenant-a", credential_id=cid) is None

    def test_get_credential_role_returns_none_when_no_role(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assert get_credential_role(db, tenant_id="tenant-a", credential_id=cid) is None

    def test_list_assignments_only_returns_credentials_with_roles(self, db):
        cid_g = _insert_credential(db, tenant_id="tenant-b")
        cid_h = _insert_credential(db, tenant_id="tenant-b")
        assign_role(
            db,
            tenant_id="tenant-b",
            actor_key_prefix="actor",
            credential_id=cid_g,
            role_name="analyst",
        )
        assignments = list_role_assignments(db, tenant_id="tenant-b")
        cids = [a["credential_id"] for a in assignments]
        assert cid_g in cids
        assert cid_h not in cids

    def test_all_builtin_roles_accepted(self, db):
        for role in BUILTIN_ROLES:
            cid = _insert_credential(db, tenant_id="tenant-c")
            result = assign_role(
                db,
                tenant_id="tenant-c",
                actor_key_prefix="actor",
                credential_id=cid,
                role_name=role,
            )
            assert result["role"] == role


# ---------------------------------------------------------------------------
# TestRoleAuditTrail
# ---------------------------------------------------------------------------


class TestRoleAuditTrail:
    def test_assign_creates_audit_record(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor-k",
            credential_id=cid,
            role_name="analyst",
        )
        log = get_role_audit_log(db, tenant_id="tenant-a")
        assert any(
            e["action"] == "assign_role" and e["target_credential_id"] == cid
            for e in log
        )

    def test_revoke_creates_audit_record(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor-k",
            credential_id=cid,
            role_name="auditor",
        )
        revoke_role(
            db, tenant_id="tenant-a", actor_key_prefix="actor-k", credential_id=cid
        )
        log = get_role_audit_log(db, tenant_id="tenant-a")
        assert any(
            e["action"] == "revoke_role" and e["target_credential_id"] == cid
            for e in log
        )

    def test_audit_records_have_unique_event_ids(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        for role in ("analyst", "auditor", "read_only"):
            assign_role(
                db,
                tenant_id="tenant-a",
                actor_key_prefix="actor",
                credential_id=cid,
                role_name=role,
            )
        log = get_role_audit_log(db, tenant_id="tenant-a")
        event_ids = [e["event_id"] for e in log]
        assert len(event_ids) == len(set(event_ids))

    def test_audit_scoped_to_tenant(self, db):
        cid_x = _insert_credential(db, tenant_id="tenant-x")
        cid_y = _insert_credential(db, tenant_id="tenant-y")
        assign_role(
            db,
            tenant_id="tenant-x",
            actor_key_prefix="actor",
            credential_id=cid_x,
            role_name="analyst",
        )
        assign_role(
            db,
            tenant_id="tenant-y",
            actor_key_prefix="actor",
            credential_id=cid_y,
            role_name="auditor",
        )

        log_x = get_role_audit_log(db, tenant_id="tenant-x")
        log_y = get_role_audit_log(db, tenant_id="tenant-y")

        assert all(e["target_credential_id"] == cid_x for e in log_x)
        assert all(e["target_credential_id"] == cid_y for e in log_y)


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

    def test_credential_with_no_role_raises_403(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        dep = require_role("read_only")
        req = _make_request(
            key_prefix="kNoRole", tenant_id="tenant-a", credential_id=cid
        )
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_insufficient_role_raises_403(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="read_only",
        )
        dep = require_role("governance_admin")
        req = _make_request(key_prefix="kLow", tenant_id="tenant-a", credential_id=cid)
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_exact_role_passes(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="auditor",
        )
        dep = require_role("auditor")
        req = _make_request(
            key_prefix="kExact", tenant_id="tenant-a", credential_id=cid
        )
        dep(request=req, conn=db)  # must not raise

    def test_superior_role_satisfies_require_role(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="tenant_admin",
        )
        for required_role in BUILTIN_ROLES:
            dep = require_role(required_role)
            req = _make_request(
                key_prefix="kSuper", tenant_id="tenant-a", credential_id=cid
            )
            dep(request=req, conn=db)  # must not raise for any role

    def test_revoked_role_raises_403(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        revoke_role(
            db, tenant_id="tenant-a", actor_key_prefix="actor", credential_id=cid
        )
        dep = require_role("analyst")
        req = _make_request(
            key_prefix="kRevoked", tenant_id="tenant-a", credential_id=cid
        )
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_403_response_includes_required_roles(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        dep = require_role("governance_admin", "tenant_admin")
        req = _make_request(key_prefix="kErr", tenant_id="tenant-a", credential_id=cid)
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
        # P-113.6: VALID_ROLE_NAMES was expanded to include platform_admin
        # (TENANT_ASSIGNABLE_ROLES | PLATFORM_CREDENTIAL_ROLES).  BUILTIN_ROLES
        # remains the tenant-facing set; VALID_ROLE_NAMES is now a superset.
        assert frozenset(BUILTIN_ROLES).issubset(VALID_ROLE_NAMES)
        # platform_admin must be present (Defect 1 fix)
        assert "platform_admin" in VALID_ROLE_NAMES

    def test_invalid_role_raises_value_error(self, db):
        cid = _insert_credential(db, tenant_id="tenant-a")
        with pytest.raises(ValueError):
            assign_role(
                db,
                tenant_id="tenant-a",
                actor_key_prefix="a",
                credential_id=cid,
                role_name="invalid_role",
            )


# ---------------------------------------------------------------------------
# TestCanonicalCredentialDisambiguation
# ---------------------------------------------------------------------------


class TestCanonicalCredentialDisambiguation:
    """Prove that canonical UUID-based role assignment is unambiguous."""

    def test_role_assigned_to_correct_credential(self, db):
        cid1 = _insert_credential(db, tenant_id="tenant-multi")
        cid2 = _insert_credential(db, tenant_id="tenant-multi")
        assign_role(
            db,
            tenant_id="tenant-multi",
            actor_key_prefix="actor",
            credential_id=cid1,
            role_name="analyst",
        )
        assert (
            get_credential_role(db, tenant_id="tenant-multi", credential_id=cid1)
            == "analyst"
        )
        assert (
            get_credential_role(db, tenant_id="tenant-multi", credential_id=cid2)
            is None
        )

    def test_revoke_only_affects_target_credential(self, db):
        cid1 = _insert_credential(db, tenant_id="tenant-multi2")
        cid2 = _insert_credential(db, tenant_id="tenant-multi2")
        assign_role(
            db,
            tenant_id="tenant-multi2",
            actor_key_prefix="actor",
            credential_id=cid1,
            role_name="analyst",
        )
        assign_role(
            db,
            tenant_id="tenant-multi2",
            actor_key_prefix="actor",
            credential_id=cid2,
            role_name="auditor",
        )
        revoke_role(
            db, tenant_id="tenant-multi2", actor_key_prefix="actor", credential_id=cid1
        )
        assert (
            get_credential_role(db, tenant_id="tenant-multi2", credential_id=cid1)
            is None
        )
        assert (
            get_credential_role(db, tenant_id="tenant-multi2", credential_id=cid2)
            == "auditor"
        )

    def test_require_role_resolves_correct_credential_via_uuid(self, db):
        cid1 = _insert_credential(db, tenant_id="tenant-res")
        cid2 = _insert_credential(db, tenant_id="tenant-res")
        assign_role(
            db,
            tenant_id="tenant-res",
            actor_key_prefix="actor",
            credential_id=cid2,
            role_name="auditor",
        )
        dep = require_role("auditor")
        # cid1 has no role → 403
        req1 = _make_request(
            key_prefix="fgk", tenant_id="tenant-res", credential_id=cid1
        )
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req1, conn=db)
        assert exc_info.value.status_code == 403
        # cid2 has auditor → passes
        req2 = _make_request(
            key_prefix="fgk", tenant_id="tenant-res", credential_id=cid2
        )
        dep(request=req2, conn=db)


# ---------------------------------------------------------------------------
# TestScopelessRoleAuthorization
# ---------------------------------------------------------------------------


class TestScopelessRoleAuthorization:
    """Prove require_role passes based on role alone; scopes are not checked."""

    def test_tenant_admin_role_passes_without_explicit_keys_write(self, db):
        cid = _insert_credential(db, tenant_id="tenant-scope")
        assign_role(
            db,
            tenant_id="tenant-scope",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="tenant_admin",
        )
        dep = require_role("tenant_admin")
        req = _make_request(
            key_prefix="kScopeless", tenant_id="tenant-scope", credential_id=cid
        )
        dep(request=req, conn=db)  # must not raise

    def test_auditor_role_passes_without_explicit_audit_read(self, db):
        cid = _insert_credential(db, tenant_id="tenant-scope")
        assign_role(
            db,
            tenant_id="tenant-scope",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="auditor",
        )
        dep = require_role("auditor")
        req = _make_request(
            key_prefix="kAuditRole", tenant_id="tenant-scope", credential_id=cid
        )
        dep(request=req, conn=db)  # must not raise

    def test_governance_admin_role_passes_without_governance_write_scope(self, db):
        cid = _insert_credential(db, tenant_id="tenant-scope")
        assign_role(
            db,
            tenant_id="tenant-scope",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="governance_admin",
        )
        dep = require_role("governance_admin")
        req = _make_request(
            key_prefix="kGovRole", tenant_id="tenant-scope", credential_id=cid
        )
        dep(request=req, conn=db)  # must not raise


# ---------------------------------------------------------------------------
# TestCanonicalRBACGuarantees (RBAC-1 through RBAC-8)
# ---------------------------------------------------------------------------


class TestCanonicalRBACGuarantees:
    """R4.10 canonical authority guarantees."""

    def test_rbac1_credential_with_role_passes_require_role(self, db):
        """RBAC-1: canonical credential with assigned role passes require_role."""
        cid = _insert_credential(db, tenant_id="tenant-g1")
        assign_role(
            db,
            tenant_id="tenant-g1",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        dep = require_role("analyst")
        req = _make_request(key_prefix="k", tenant_id="tenant-g1", credential_id=cid)
        dep(request=req, conn=db)  # must not raise

    def test_rbac2_credential_without_role_gets_403(self, db):
        """RBAC-2: canonical credential without role gets 403."""
        cid = _insert_credential(db, tenant_id="tenant-g2")
        dep = require_role("read_only")
        req = _make_request(key_prefix="k", tenant_id="tenant-g2", credential_id=cid)
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_rbac3_cross_tenant_credential_cannot_read_other_tenant_role(self, db):
        """RBAC-3: cross-tenant credential cannot read another tenant's role."""
        cid = _insert_credential(db, tenant_id="tenant-g3a")
        assign_role(
            db,
            tenant_id="tenant-g3a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        assert (
            get_credential_role(db, tenant_id="tenant-g3b", credential_id=cid) is None
        )

    def test_rbac4_cross_tenant_role_assignment_fails(self, db):
        """RBAC-4: cross-tenant role assignment raises ValueError."""
        cid = _insert_credential(db, tenant_id="tenant-g4-real")
        with pytest.raises(ValueError, match="not found"):
            assign_role(
                db,
                tenant_id="tenant-g4-evil",
                actor_key_prefix="attacker",
                credential_id=cid,
                role_name="tenant_admin",
            )

    def test_rbac5_cross_tenant_role_revoke_fails(self, db):
        """RBAC-5: cross-tenant role revoke raises ValueError."""
        cid = _insert_credential(db, tenant_id="tenant-g5-real")
        assign_role(
            db,
            tenant_id="tenant-g5-real",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        with pytest.raises(ValueError, match="not found"):
            revoke_role(
                db,
                tenant_id="tenant-g5-evil",
                actor_key_prefix="attacker",
                credential_id=cid,
            )

    def test_rbac6_list_role_assignments_is_tenant_isolated(self, db):
        """RBAC-6: list_role_assignments is scoped to the requesting tenant."""
        cid_a = _insert_credential(db, tenant_id="tenant-g6a")
        cid_b = _insert_credential(db, tenant_id="tenant-g6b")
        assign_role(
            db,
            tenant_id="tenant-g6a",
            actor_key_prefix="actor",
            credential_id=cid_a,
            role_name="analyst",
        )
        assign_role(
            db,
            tenant_id="tenant-g6b",
            actor_key_prefix="actor",
            credential_id=cid_b,
            role_name="auditor",
        )
        for_a = list_role_assignments(db, tenant_id="tenant-g6a")
        for_b = list_role_assignments(db, tenant_id="tenant-g6b")
        assert all(r["credential_id"] == cid_a for r in for_a)
        assert all(r["credential_id"] == cid_b for r in for_b)

    def test_rbac7_credential_without_role_is_denied(self, db):
        """RBAC-7: a credential with no role in tenant_credential_roles is denied.

        R4.11: api_keys table is retired. The invariant is now enforced structurally —
        the legacy table no longer exists. This test verifies the positive side:
        canonical RBAC requires an explicit tenant_credential_roles entry.
        """
        cid = _insert_credential(db, tenant_id="tenant-g7")
        # No role assigned in tenant_credential_roles.
        assert get_credential_role(db, tenant_id="tenant-g7", credential_id=cid) is None
        # require_role must deny a credential with no assigned role.
        dep = require_role("read_only")
        req = _make_request(key_prefix="k", tenant_id="tenant-g7", credential_id=cid)
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_rbac8_audit_event_records_target_credential_id(self, db):
        """RBAC-8: audit event records canonical credential identity."""
        cid = _insert_credential(db, tenant_id="tenant-g8")
        assign_role(
            db,
            tenant_id="tenant-g8",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        log = get_role_audit_log(db, tenant_id="tenant-g8")
        assert any(e["target_credential_id"] == cid for e in log)
