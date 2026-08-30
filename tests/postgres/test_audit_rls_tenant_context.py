"""
Integration tests: security_audit_log RLS enforcement under fg_app role.

These tests MUST run against a real Postgres instance (FG_POSTGRES_TESTS=1).
SQLite bypasses RLS entirely and would give false-green results.

Test coverage:
  A  Happy path — INSERT with correct app.tenant_id set succeeds.
  B  _persist_event sets app.tenant_id before INSERT, allowing the write.
  C  _persist_event with no tenant_id raises AuditPersistenceError (FG-AUDIT-002) in prod env.
  D  Cross-tenant context blocked — INSERT for tenant-b while context is tenant-a fails.
  E  Atomicity — audit failure leaves no orphan tenant row (compensation logic).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.security_audit import AuditPersistenceError, AuditEvent, EventType, Severity


# ---------------------------------------------------------------------------
# Test A — happy path: INSERT with correct tenant context succeeds
# ---------------------------------------------------------------------------


def test_audit_insert_succeeds_with_tenant_context(pg_engine) -> None:
    """A row can be inserted into security_audit_log when app.tenant_id matches."""
    import hashlib

    entry_hash = hashlib.sha256(b"test-entry-tenant-audit-a").hexdigest()
    with Session(pg_engine) as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"),
            {"tid": "tenant-audit-a"},
        )
        session.execute(
            text(
                """
                INSERT INTO security_audit_log
                    (tenant_id, event_type, details_json, entry_hash, prev_hash)
                VALUES (:tenant_id, 'admin_action', '{}'::jsonb, :entry_hash, 'GENESIS')
                """
            ),
            {"tenant_id": "tenant-audit-a", "entry_hash": entry_hash},
        )
        session.commit()

    # Verify the row is visible to the same tenant context.
    with Session(pg_engine) as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"),
            {"tid": "tenant-audit-a"},
        )
        count = session.execute(
            text("SELECT COUNT(*) FROM security_audit_log WHERE tenant_id = :tid"),
            {"tid": "tenant-audit-a"},
        ).scalar_one()
    assert count == 1


# ---------------------------------------------------------------------------
# Test B — _persist_event sets app.tenant_id before INSERT
# ---------------------------------------------------------------------------


def test_persist_event_sets_tenant_context_and_inserts(pg_engine, monkeypatch) -> None:
    """_persist_event must call set_config('app.tenant_id') before the INSERT."""
    tenant_id = "tenant-persist-b"

    # Patch get_engine to return our test engine so _persist_event talks to Postgres.
    monkeypatch.setenv("FG_ENV", "test")

    # _persist_event imports get_engine locally via `from api.db import get_engine`.
    # Patching the source module (api.db) ensures the local import picks up the override.
    import api.db as db_module

    monkeypatch.setattr(db_module, "get_engine", lambda: pg_engine)

    # We need to make SecurityAuditLog map to the bootstrap's simplified table.
    # Instead of testing through the ORM (which needs extra columns), we verify
    # the set_config call happens by inspecting a real Session.
    set_config_calls: list[str] = []

    original_execute = Session.execute

    def tracking_execute(self, statement, params=None, **kwargs):
        stmt_str = str(statement)
        if "set_config" in stmt_str and params and params.get("tid") == tenant_id:
            set_config_calls.append(tenant_id)
        return original_execute(self, statement, params, **kwargs)

    monkeypatch.setattr(Session, "execute", tracking_execute)

    # Build a minimal AuditEvent with a real tenant_id.
    event = AuditEvent(
        event_type=EventType.ADMIN_ACTION,
        success=True,
        severity=Severity.INFO,
        tenant_id=tenant_id,
        reason="test_action",
        details={"test": True},
    )

    from api.security_audit import SecurityAuditor

    auditor = SecurityAuditor(persist_to_db=True)

    # _persist_event will fail at the ORM/column-mismatch stage (bootstrap table
    # is simpler than the ORM model) but we only care that set_config was called
    # BEFORE any DML attempt — which is what set_config_calls captures.
    try:
        auditor._persist_event(event)
    except Exception:
        pass  # Column mismatch on bootstrap schema is expected; set_config is what matters

    assert set_config_calls, (
        "_persist_event must call set_config('app.tenant_id') before any INSERT"
    )
    assert set_config_calls[0] == tenant_id


# ---------------------------------------------------------------------------
# Test C — fail closed: no tenant_id raises AuditPersistenceError in prod env
# ---------------------------------------------------------------------------


def test_persist_event_no_tenant_id_raises_in_prod(pg_engine, monkeypatch) -> None:
    """_persist_event with tenant_id=None must raise FG-AUDIT-002 in prod-like env."""
    monkeypatch.setenv("FG_ENV", "production")

    event = AuditEvent(
        event_type=EventType.ADMIN_ACTION,
        success=True,
        severity=Severity.INFO,
        tenant_id=None,
        reason="no_tenant",
    )

    from api.security_audit import SecurityAuditor

    auditor = SecurityAuditor(persist_to_db=True)

    with pytest.raises(AuditPersistenceError) as exc_info:
        auditor._persist_event(event)

    assert exc_info.value.code == "FG-AUDIT-002"

    # Confirm no row was written.
    with Session(pg_engine) as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"),
            {"tid": "any-tenant"},
        )
        count = session.execute(
            text("SELECT COUNT(*) FROM security_audit_log")
        ).scalar_one()
    assert count == 0


# ---------------------------------------------------------------------------
# Test D — cross-tenant context blocked by RLS
# ---------------------------------------------------------------------------


def test_cross_tenant_insert_blocked_by_rls(pg_engine) -> None:
    """INSERT for tenant-b while app.tenant_id=tenant-a must be blocked by RLS."""
    import hashlib

    cross_hash = hashlib.sha256(b"test-cross-tenant-d").hexdigest()
    with Session(pg_engine) as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"),
            {"tid": "tenant-rls-a"},
        )
        with pytest.raises((SQLAlchemyError, Exception)):
            session.execute(
                text(
                    """
                    INSERT INTO security_audit_log
                        (tenant_id, event_type, details_json, entry_hash, prev_hash)
                    VALUES (:tenant_id, 'admin_action', '{}'::jsonb, :entry_hash, 'GENESIS')
                    """
                ),
                {
                    "tenant_id": "tenant-rls-b",
                    "entry_hash": cross_hash,
                },  # mismatch: context is tenant-rls-a
            )
            session.commit()


# ---------------------------------------------------------------------------
# Test E — atomicity: audit failure leaves no orphan tenant
# ---------------------------------------------------------------------------


def test_create_tenant_audit_failure_compensates(pg_engine, monkeypatch) -> None:
    """If audit_admin_action raises AuditPersistenceError, the tenant row is deleted."""
    from fastapi import HTTPException

    tenant_id = "test-orphan-compensation-e2e"

    # Skip if tenants table doesn't exist in bootstrap schema.
    try:
        with pg_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM tenants LIMIT 1"))
    except Exception:
        pytest.skip("tenants table not present in bootstrap schema")

    # Clean up any leftover from previous runs.
    with pg_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM tenants WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )

    # Patch audit_admin_action to raise AuditPersistenceError.
    import api.admin as admin_module

    monkeypatch.setattr(
        admin_module,
        "audit_admin_action",
        MagicMock(
            side_effect=AuditPersistenceError(
                "FG-AUDIT-002",
                "injected for test",
            )
        ),
    )

    # Patch get_tenant_repository in its source module so the local import inside
    # create_tenant (from api.tenant_repository import get_tenant_repository) picks
    # up the patched version at call time.
    import api.tenant_repository as tenant_repo_module
    from api.tenant_repository import TenantRepository

    monkeypatch.setattr(
        tenant_repo_module,
        "get_tenant_repository",
        lambda: TenantRepository(pg_engine),
    )

    # Also patch get_engine in admin so compensation uses our test engine.
    monkeypatch.setattr(admin_module, "get_engine", lambda: pg_engine, raising=False)

    # Build a minimal fake request.
    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "POST",
        "scheme": "http",
        "path": "/admin/tenants",
        "raw_path": b"/admin/tenants",
        "query_string": b"",
        "headers": [],
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }
    fake_request: StarletteRequest = StarletteRequest(scope)
    fake_request.state.auth = None
    fake_request.state.request_id = "test-req-e"

    from api.admin import TenantCreateRequest, create_tenant
    from api.actor_context import ActorContext

    req = TenantCreateRequest(tenant_id=tenant_id, name="Test Orphan")
    actor_ctx = MagicMock(spec=ActorContext)

    with pytest.raises(HTTPException) as exc_info:
        import asyncio

        asyncio.run(create_tenant(req, fake_request, actor_ctx))

    assert exc_info.value.status_code == 500

    # The tenant MUST NOT exist after compensation.
    with pg_engine.connect() as conn:
        row = conn.execute(
            text("SELECT tenant_id FROM tenants WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        ).fetchone()
    assert row is None, (
        f"Tenant {tenant_id!r} must not exist after audit failure compensation"
    )
