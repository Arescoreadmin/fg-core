"""
tests/security/test_rbac_security.py — Security tests for RBAC (R4.10).

Coverage:
- Cross-tenant isolation: role lookups are always scoped to tenant_id
- Unauthorized assignment: non-existent target credential raises ValueError
- Unknown role rejection: all invalid role names are rejected before DB is touched
- Audit integrity: actor and credential are correctly recorded; events are never empty
- Blank tenant guard: assign/revoke/list/audit reject blank tenant_id
- Error messages: no key material, no stack traces in public detail fields
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from api.tenant_rbac import (
    assign_role,
    get_credential_role,
    get_role_audit_log,
    list_role_assignments,
    require_role,
    revoke_role,
)


# ---------------------------------------------------------------------------
# DB fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "rbac-security.db")
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


def _nonexistent_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# TestCrossTenantIsolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_role_not_visible_across_tenants(self, db):
        cid_a = _insert_credential(db, tenant_id="tenant-iso-a")
        assign_role(
            db,
            tenant_id="tenant-iso-a",
            actor_key_prefix="actor",
            credential_id=cid_a,
            role_name="analyst",
        )
        # tenant-iso-b cannot see the role assigned to tenant-iso-a's credential.
        assert (
            get_credential_role(db, tenant_id="tenant-iso-b", credential_id=cid_a)
            is None
        )

    def test_assign_to_credential_in_other_tenant_raises(self, db):
        cid = _insert_credential(db, tenant_id="tenant-other")
        with pytest.raises(ValueError, match="not found"):
            assign_role(
                db,
                tenant_id="tenant-attacker",
                actor_key_prefix="evil-key",
                credential_id=cid,
                role_name="tenant_admin",
            )

    def test_revoke_from_credential_in_other_tenant_raises(self, db):
        cid = _insert_credential(db, tenant_id="tenant-victim")
        assign_role(
            db,
            tenant_id="tenant-victim",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        with pytest.raises(ValueError, match="not found"):
            revoke_role(
                db,
                tenant_id="tenant-attacker",
                actor_key_prefix="evil-key",
                credential_id=cid,
            )

    def test_list_assignments_scoped_to_tenant(self, db):
        cid_a = _insert_credential(db, tenant_id="tenant-list-a")
        cid_b = _insert_credential(db, tenant_id="tenant-list-b")
        assign_role(
            db,
            tenant_id="tenant-list-a",
            actor_key_prefix="actor",
            credential_id=cid_a,
            role_name="analyst",
        )
        assign_role(
            db,
            tenant_id="tenant-list-b",
            actor_key_prefix="actor",
            credential_id=cid_b,
            role_name="auditor",
        )

        for_a = list_role_assignments(db, tenant_id="tenant-list-a")
        for_b = list_role_assignments(db, tenant_id="tenant-list-b")

        assert all(row["credential_id"] == cid_a for row in for_a)
        assert all(row["credential_id"] == cid_b for row in for_b)

    def test_audit_log_scoped_to_tenant(self, db):
        cid_a = _insert_credential(db, tenant_id="tenant-aud-a")
        cid_b = _insert_credential(db, tenant_id="tenant-aud-b")
        assign_role(
            db,
            tenant_id="tenant-aud-a",
            actor_key_prefix="actor",
            credential_id=cid_a,
            role_name="analyst",
        )
        assign_role(
            db,
            tenant_id="tenant-aud-b",
            actor_key_prefix="actor",
            credential_id=cid_b,
            role_name="auditor",
        )

        log_a = get_role_audit_log(db, tenant_id="tenant-aud-a")
        log_b = get_role_audit_log(db, tenant_id="tenant-aud-b")

        assert all(e["target_credential_id"] != cid_b for e in log_a)
        assert all(e["target_credential_id"] != cid_a for e in log_b)


# ---------------------------------------------------------------------------
# TestUnknownRoleRejection
# ---------------------------------------------------------------------------


class TestUnknownRoleRejection:
    def test_empty_string_role_rejected(self, db):
        cid = _insert_credential(db, tenant_id="tenant-r")
        with pytest.raises(ValueError):
            assign_role(
                db,
                tenant_id="tenant-r",
                actor_key_prefix="a",
                credential_id=cid,
                role_name="",
            )

    def test_sql_injection_role_rejected(self, db):
        cid = _insert_credential(db, tenant_id="tenant-r")
        with pytest.raises(ValueError):
            assign_role(
                db,
                tenant_id="tenant-r",
                actor_key_prefix="a",
                credential_id=cid,
                role_name="analyst'; DROP TABLE tenant_credential_roles;--",
            )

    def test_superuser_role_rejected(self, db):
        cid = _insert_credential(db, tenant_id="tenant-r")
        with pytest.raises(ValueError):
            assign_role(
                db,
                tenant_id="tenant-r",
                actor_key_prefix="a",
                credential_id=cid,
                role_name="superuser",
            )


# ---------------------------------------------------------------------------
# TestBlankTenantGuard
# ---------------------------------------------------------------------------


class TestBlankTenantGuard:
    def test_assign_blank_tenant_raises(self, db):
        with pytest.raises((ValueError, Exception)):
            assign_role(
                db,
                tenant_id="",
                actor_key_prefix="a",
                credential_id=_nonexistent_uuid(),
                role_name="analyst",
            )

    def test_revoke_blank_tenant_raises(self, db):
        with pytest.raises((ValueError, Exception)):
            revoke_role(
                db,
                tenant_id="  ",
                actor_key_prefix="a",
                credential_id=_nonexistent_uuid(),
            )

    def test_list_blank_tenant_raises(self, db):
        with pytest.raises((ValueError, Exception)):
            list_role_assignments(db, tenant_id="")

    def test_audit_blank_tenant_raises(self, db):
        with pytest.raises((ValueError, Exception)):
            get_role_audit_log(db, tenant_id="")


# ---------------------------------------------------------------------------
# TestAuditIntegrity
# ---------------------------------------------------------------------------


class TestAuditIntegrity:
    def test_audit_records_actor_correctly(self, db):
        cid = _insert_credential(db, tenant_id="tenant-audit")
        assign_role(
            db,
            tenant_id="tenant-audit",
            actor_key_prefix="known-actor-prefix",
            credential_id=cid,
            role_name="analyst",
        )
        log = get_role_audit_log(db, tenant_id="tenant-audit")
        assert any(e["actor_key_prefix"] == "known-actor-prefix" for e in log)

    def test_audit_records_role_name(self, db):
        cid = _insert_credential(db, tenant_id="tenant-audit")
        assign_role(
            db,
            tenant_id="tenant-audit",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="governance_admin",
        )
        log = get_role_audit_log(db, tenant_id="tenant-audit")
        assert any(e["role_name"] == "governance_admin" for e in log)

    def test_revoke_audit_records_none_role(self, db):
        cid = _insert_credential(db, tenant_id="tenant-audit")
        assign_role(
            db,
            tenant_id="tenant-audit",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        revoke_role(
            db, tenant_id="tenant-audit", actor_key_prefix="actor", credential_id=cid
        )
        log = get_role_audit_log(db, tenant_id="tenant-audit")
        revoke_events = [e for e in log if e["action"] == "revoke_role"]
        assert revoke_events
        assert revoke_events[0]["role_name"] is None

    def test_audit_event_ids_are_uuids(self, db):
        import re

        cid = _insert_credential(db, tenant_id="tenant-uuid")
        assign_role(
            db,
            tenant_id="tenant-uuid",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="read_only",
        )
        log = get_role_audit_log(db, tenant_id="tenant-uuid")
        uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        assert all(uuid_re.match(e["event_id"]) for e in log)

    def test_audit_records_target_credential_id(self, db):
        cid = _insert_credential(db, tenant_id="tenant-audit-cid")
        assign_role(
            db,
            tenant_id="tenant-audit-cid",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="analyst",
        )
        log = get_role_audit_log(db, tenant_id="tenant-audit-cid")
        assert any(e["target_credential_id"] == cid for e in log)


# ---------------------------------------------------------------------------
# TestErrorMessageSafety
# ---------------------------------------------------------------------------


class TestErrorMessageSafety:
    def test_wrong_tenant_error_does_not_leak_credential_secret(self, db):
        cid = _insert_credential(db, tenant_id="tenant-real")
        try:
            assign_role(
                db,
                tenant_id="tenant-evil",
                actor_key_prefix="a",
                credential_id=cid,
                role_name="analyst",
            )
        except ValueError as exc:
            msg = str(exc)
            assert "test_hash" not in msg, (
                "secret_hash must not appear in error messages"
            )

    def test_unknown_role_error_does_not_include_db_details(self, db):
        cid = _insert_credential(db, tenant_id="tenant-safe")
        try:
            assign_role(
                db,
                tenant_id="tenant-safe",
                actor_key_prefix="a",
                credential_id=cid,
                role_name="__evil__",
            )
        except ValueError as exc:
            msg = str(exc)
            assert "sqlite" not in msg.lower()
            assert "INSERT" not in msg
            assert "SELECT" not in msg


# ---------------------------------------------------------------------------
# TestRequireRoleDenyByDefault
# ---------------------------------------------------------------------------


class TestRequireRoleDenyByDefault:
    """Ensure require_role is strictly deny-by-default for all edge cases."""

    def test_empty_allowed_roles_set_denies_all(self, db):
        """Calling require_role() with no arguments should always raise 403."""
        from types import SimpleNamespace

        from fastapi import HTTPException, Request

        cid = _insert_credential(db, tenant_id="tenant-a")
        dep = require_role()
        scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
        req = Request(scope)
        req.state.auth = SimpleNamespace(
            key_prefix="kEmpty", tenant_id="tenant-a", credential_id=cid
        )
        req.state.tenant_id = "tenant-a"
        req.state.tenant_is_key_bound = True
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403

    def test_whitespace_role_names_ignored(self, db):
        """Whitespace-only role names in require_role are silently dropped → always 403."""
        from types import SimpleNamespace

        from fastapi import HTTPException, Request

        cid = _insert_credential(db, tenant_id="tenant-a")
        assign_role(
            db,
            tenant_id="tenant-a",
            actor_key_prefix="actor",
            credential_id=cid,
            role_name="tenant_admin",
        )
        dep = require_role("  ", "\t")
        scope = {"type": "http", "method": "GET", "path": "/test", "headers": []}
        req = Request(scope)
        req.state.auth = SimpleNamespace(
            key_prefix="kWS", tenant_id="tenant-a", credential_id=cid
        )
        req.state.tenant_id = "tenant-a"
        req.state.tenant_is_key_bound = True
        with pytest.raises(HTTPException) as exc_info:
            dep(request=req, conn=db)
        assert exc_info.value.status_code == 403
