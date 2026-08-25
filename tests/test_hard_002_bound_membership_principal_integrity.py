"""HARD-002 — BOUND membership principal integrity.

Migration 0183 enforces:

    identity_binding_status <> 'bound'
    OR principal_id IS NOT NULL

The database is authoritative. SQLite coverage proves the portable CHECK
semantics for direct SQL and transitions; the FG_DB_URL-gated test exercises
the same invariant against a real migrated Postgres database when that lane is
enabled.
"""

from __future__ import annotations

import os
import pathlib
import uuid
from typing import Any

import pytest
import sqlalchemy
from sqlalchemy import CheckConstraint, create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from api.db_models import TenantUser

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MIGRATION_0183 = (
    _REPO_ROOT
    / "migrations"
    / "postgres"
    / "0183_bound_membership_principal_integrity.sql"
)
_MIGRATION_0182 = (
    _REPO_ROOT / "migrations" / "postgres" / "0182_identity_authority_hardening.sql"
)
_MODELS = _REPO_ROOT / "api" / "db_models.py"
_INVITATION_FLOW = _REPO_ROOT / "admin_gateway" / "identity" / "invitation_flow.py"
_PRINCIPAL_AUTHORITY = _REPO_ROOT / "api" / "principal_authority.py"
_PR_AUTH_004_TEST = (
    _REPO_ROOT / "tests" / "test_pr_auth_004_runtime_principal_authority_cutover.py"
)
_HARD_002_DOC = (
    _REPO_ROOT / "docs" / "architecture" / "HARD_002_BOUND_PRINCIPAL_INTEGRITY.md"
)

_NOW = "2026-08-24T00:00:00+00:00"
_PREDICATE = "identity_binding_status <> 'bound' OR principal_id IS NOT NULL"
_CONSTRAINT = "chk_bound_requires_principal_id"
_RAW_SUBJECT = "auth0|RAW-SUBJECT-MUST-NOT-LEAK"

_SQLITE_SCHEMA = """
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
    id                      TEXT    PRIMARY KEY,
    tenant_id               TEXT    NOT NULL,
    email                   TEXT    NOT NULL DEFAULT 'member@example.com',
    display_name            TEXT    NOT NULL DEFAULT 'Test Member',
    role                    TEXT    NOT NULL DEFAULT 'user',
    active                  INTEGER NOT NULL DEFAULT 1,
    identity_binding_status TEXT    NOT NULL DEFAULT 'unbound',
    identity_type           TEXT    NOT NULL DEFAULT 'human',
    identity_provider       TEXT,
    identity_issuer         TEXT,
    identity_subject        TEXT,
    identity_email          TEXT,
    principal_id            TEXT    REFERENCES fg_principals(id),
    created_at              TEXT    NOT NULL DEFAULT '2026-08-24T00:00:00+00:00',
    updated_at              TEXT    NOT NULL DEFAULT '2026-08-24T00:00:00+00:00',
    CONSTRAINT chk_bound_requires_principal_id
        CHECK (identity_binding_status <> 'bound' OR principal_id IS NOT NULL)
);
"""


def _executable_sql(src: str) -> str:
    return "\n".join(
        line for line in src.splitlines() if not line.strip().startswith("--")
    )


def _setup_sqlite(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        for raw in _SQLITE_SCHEMA.split(";"):
            stmt = raw.strip()
            if stmt:
                conn.execute(text(stmt))


@pytest.fixture()
def engine() -> Engine:
    eng = create_engine("sqlite:///:memory:", future=True)
    _setup_sqlite(eng)

    @sqlalchemy.event.listens_for(eng, "connect")
    def _fk_on(dbapi_con: Any, _rec: Any) -> None:
        dbapi_con.execute("PRAGMA foreign_keys = ON")

    return eng


def _principal(conn: Connection, pid: str | None = None) -> str:
    principal_id = pid or str(uuid.uuid4())
    conn.execute(
        text(
            """
            INSERT INTO fg_principals
                (id, display_name, primary_email, principal_type,
                 lifecycle_state, mfa_verified, authority_version,
                 created_at, updated_at)
            VALUES
                (:id, 'Test Principal', :email, 'human',
                 'active', 0, 1, :now, :now)
            """
        ),
        {"id": principal_id, "email": f"{principal_id}@example.com", "now": _NOW},
    )
    return principal_id


def _membership(
    conn: Connection,
    *,
    status: str = "unbound",
    principal_id: str | None = None,
    uid: str | None = None,
) -> str:
    membership_id = uid or str(uuid.uuid4())
    conn.execute(
        text(
            """
            INSERT INTO tenant_users
                (id, tenant_id, email, display_name, role, active,
                 identity_binding_status, identity_type, identity_provider,
                 identity_issuer, identity_subject, identity_email, principal_id)
            VALUES
                (:id, :tenant_id, :email, 'Test Member', 'user', 1,
                 :status, 'human', :provider, :issuer, :subject, :email, :pid)
            """
        ),
        {
            "id": membership_id,
            "tenant_id": f"tenant-{uuid.uuid4().hex[:12]}",
            "email": f"{membership_id}@example.com",
            "status": status,
            "provider": "auth0" if status == "bound" else None,
            "issuer": "https://example.auth0.com/" if status == "bound" else None,
            "subject": _RAW_SUBJECT if status == "bound" else None,
            "pid": principal_id,
        },
    )
    return membership_id


# A — migration structure


def test_A1_migration_0183_exists() -> None:
    assert _MIGRATION_0183.exists()
    assert _MIGRATION_0183.name == "0183_bound_membership_principal_integrity.sql"


def test_A2_migration_has_exact_constraint_and_predicate() -> None:
    src = _MIGRATION_0183.read_text(encoding="utf-8")
    normalized = " ".join(src.split())
    assert _CONSTRAINT in src
    assert _PREDICATE in normalized
    assert (
        "CHECK ( identity_binding_status <> 'bound' OR principal_id IS NOT NULL )"
        in normalized
    )


def test_A3_migration_uses_not_valid_then_validate() -> None:
    src = _MIGRATION_0183.read_text(encoding="utf-8")
    assert "NOT VALID" in src
    assert f"VALIDATE CONSTRAINT {_CONSTRAINT}" in src
    assert src.index("NOT VALID") < src.index(f"VALIDATE CONSTRAINT {_CONSTRAINT}")


def test_A4_migration_is_idempotent_and_replay_safe() -> None:
    src = _MIGRATION_0183.read_text(encoding="utf-8")
    assert "IF NOT EXISTS" in src
    assert "FROM pg_constraint" in src
    assert f"conname = '{_CONSTRAINT}'" in src
    assert "conrelid = 'tenant_users'::regclass" in src
    assert src.count(_CONSTRAINT) >= 4


def test_A5_migration_has_no_data_repair_or_destructive_schema() -> None:
    src = _executable_sql(_MIGRATION_0183.read_text(encoding="utf-8")).upper()
    forbidden = (
        "INSERT INTO",
        "UPDATE TENANT_USERS",
        "DELETE FROM",
        "TRUNCATE",
        "DROP COLUMN",
        "DROP INDEX",
        "ALTER COLUMN PRINCIPAL_ID SET NOT NULL",
        "PRINCIPAL_ID UUID NOT NULL",
    )
    for token in forbidden:
        assert token not in src


def test_A6_migration_preserves_legacy_columns_and_hard_001_trigger() -> None:
    src = _MIGRATION_0183.read_text(encoding="utf-8").upper()
    for legacy_col in (
        "IDENTITY_PROVIDER",
        "IDENTITY_ISSUER",
        "IDENTITY_SUBJECT",
        "IDENTITY_BINDING_STATUS",
        "IDENTITY_EMAIL",
    ):
        assert f"DROP COLUMN {legacy_col}" not in src
    hard_001 = _MIGRATION_0182.read_text(encoding="utf-8")
    assert "fg_principal_authority_version_enforce" in hard_001
    assert "fg_principals_authority_version_bump" in hard_001


def test_A7_migration_documents_locking_deployment_and_rollback() -> None:
    src = _MIGRATION_0183.read_text(encoding="utf-8")
    assert "ACCESS EXCLUSIVE" in src
    assert "SHARE UPDATE EXCLUSIVE" in src
    assert "No table rewrite" in src
    assert "DROP CONSTRAINT IF EXISTS chk_bound_requires_principal_id" in src
    assert "No data repair" in src


# B — ORM mirror


def test_B1_tenant_user_orm_mirrors_constraint() -> None:
    tenant_user_table: Any = TenantUser.__table__
    constraints = {
        c.name: c
        for c in tenant_user_table.constraints
        if isinstance(c, CheckConstraint)
    }
    assert _CONSTRAINT in constraints
    assert str(constraints[_CONSTRAINT].sqltext) == _PREDICATE


def test_B2_orm_principal_id_remains_nullable() -> None:
    assert TenantUser.__table__.c.principal_id.nullable is True


# C/D/F/G — valid states, invalid states, transitions, FK


def test_C1_unbound_with_null_principal_is_valid(engine: Engine) -> None:
    with engine.begin() as conn:
        uid = _membership(conn, status="unbound", principal_id=None)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": uid}
        ).fetchone()
    assert row is not None
    assert row.principal_id is None


def test_C2_unbound_with_principal_is_valid(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        uid = _membership(conn, status="unbound", principal_id=pid)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": uid}
        ).fetchone()
    assert row is not None
    assert row.principal_id == pid


def test_C3_bound_with_principal_is_valid(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        uid = _membership(conn, status="bound", principal_id=pid)
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT identity_binding_status, principal_id FROM tenant_users WHERE id = :id"
            ),
            {"id": uid},
        ).fetchone()
    assert row is not None
    assert row.identity_binding_status == "bound"
    assert row.principal_id == pid


def test_D1_bound_with_null_principal_is_rejected(engine: Engine) -> None:
    with engine.begin() as conn:
        with pytest.raises(IntegrityError):
            _membership(conn, status="bound", principal_id=None)


def test_D2_bound_principal_cannot_be_cleared(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        uid = _membership(conn, status="bound", principal_id=pid)
        with pytest.raises(IntegrityError):
            conn.execute(
                text("UPDATE tenant_users SET principal_id = NULL WHERE id = :id"),
                {"id": uid},
            )


def test_D3_unbound_to_bound_without_principal_fails(engine: Engine) -> None:
    with engine.begin() as conn:
        uid = _membership(conn, status="unbound", principal_id=None)
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    """
                    UPDATE tenant_users
                       SET identity_binding_status = 'bound',
                           principal_id = NULL
                     WHERE id = :id
                    """
                ),
                {"id": uid},
            )


def test_E1_assign_principal_before_bound_succeeds(engine: Engine) -> None:
    with engine.begin() as conn:
        uid = _membership(conn, status="unbound", principal_id=None)
        pid = _principal(conn)
        conn.execute(
            text(
                """
                UPDATE tenant_users
                   SET principal_id = :pid,
                       identity_binding_status = 'bound'
                 WHERE id = :id
                """
            ),
            {"id": uid, "pid": pid},
        )
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT identity_binding_status, principal_id FROM tenant_users WHERE id = :id"
            ),
            {"id": uid},
        ).fetchone()
    assert row is not None
    assert row.identity_binding_status == "bound"
    assert row.principal_id == pid


def test_E2_bound_first_then_principal_fails(engine: Engine) -> None:
    with engine.begin() as conn:
        uid = _membership(conn, status="unbound", principal_id=None)
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    "UPDATE tenant_users SET identity_binding_status = 'bound' WHERE id = :id"
                ),
                {"id": uid},
            )


def test_F1_direct_sql_insert_bound_null_fails(engine: Engine) -> None:
    with engine.begin() as conn:
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    """
                    INSERT INTO tenant_users
                        (id, tenant_id, email, display_name,
                         identity_binding_status, identity_type)
                    VALUES
                        (:id, :tenant_id, :email, 'Bad Member', 'bound', 'human')
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": f"tenant-{uuid.uuid4().hex[:12]}",
                    "email": f"{uuid.uuid4()}@example.com",
                },
            )


def test_F2_direct_sql_update_to_bound_null_fails(engine: Engine) -> None:
    with engine.begin() as conn:
        uid = _membership(conn, status="unbound", principal_id=None)
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    """
                    UPDATE tenant_users
                       SET identity_binding_status = 'bound',
                           principal_id = NULL
                     WHERE id = :id
                    """
                ),
                {"id": uid},
            )


def test_G1_bound_nonexistent_principal_fails_fk(engine: Engine) -> None:
    with engine.begin() as conn:
        with pytest.raises(IntegrityError):
            _membership(conn, status="bound", principal_id=str(uuid.uuid4()))


def test_G2_valid_principal_satisfies_check_and_fk(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        uid = _membership(conn, status="bound", principal_id=pid)
    assert uid


# H/I/J/K/N — regressions and scope guards


def test_H1_invitation_flow_still_assigns_principal_before_bound() -> None:
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    principal_idx = src.index("membership.principal_id = resolution.principal_id")
    bound_idx = src.index('membership.identity_binding_status = "bound"')
    flush_idx = src.index("db.flush()", bound_idx)
    assert principal_idx < bound_idx < flush_idx
    assert "resolve_or_create_principal_for_external_identity" in src


def test_H2_pr_auth_004_error_semantics_not_broadly_remapped() -> None:
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    handler_start = src.index("except IntegrityError as exc")
    handler_end = src.index('auth_state.status = "bound"', handler_start)
    handler = src[handler_start:handler_end]
    assert "IDENTITY_ALREADY_BOUND" in handler
    assert "PRINCIPAL_LINKAGE_INVALID" in handler
    assert "IDENTITY_BINDING_FAILED" in handler


def test_I1_auth_modules_import_without_schema_side_effects() -> None:
    from api import identity_backfill_reconciliation, principal_authority

    assert hasattr(identity_backfill_reconciliation, "run_reconciliation")
    assert hasattr(
        principal_authority, "resolve_or_create_principal_for_external_identity"
    )


def test_J1_hard_001_trigger_source_unchanged() -> None:
    src = _MIGRATION_0182.read_text(encoding="utf-8")
    assert "CREATE OR REPLACE FUNCTION fg_principal_authority_version_enforce" in src
    assert "CREATE TRIGGER fg_principals_authority_version_bump" in src
    assert "BEFORE UPDATE ON fg_principals" in src


def test_K1_hard_002_doc_records_production_precondition_and_rollback() -> None:
    src = _HARD_002_DOC.read_text(encoding="utf-8")
    assert "identity_binding_status = 'bound'" in src
    assert "principal_id IS NULL" in src
    assert "Expected result" in src
    assert "DROP CONSTRAINT IF EXISTS chk_bound_requires_principal_id" in src


def test_L1_replay_static_single_constraint_no_trigger_duplication() -> None:
    src = _MIGRATION_0183.read_text(encoding="utf-8")
    executable = _executable_sql(src).upper()
    assert executable.count("ADD CONSTRAINT CHK_BOUND_REQUIRES_PRINCIPAL_ID") == 1
    assert executable.count("VALIDATE CONSTRAINT CHK_BOUND_REQUIRES_PRINCIPAL_ID") == 1
    assert "CREATE TRIGGER" not in executable
    assert "CREATE OR REPLACE FUNCTION" not in executable


def test_M1_constraint_sources_do_not_expose_raw_identity_subject() -> None:
    for path in (_MIGRATION_0183, _MODELS, _HARD_002_DOC):
        src = path.read_text(encoding="utf-8")
        assert _RAW_SUBJECT not in src
    assert "RAISE EXCEPTION" not in _MIGRATION_0183.read_text(encoding="utf-8").upper()


def test_N1_scope_guard_no_runtime_auth_or_authority_changes() -> None:
    changed_allowed = {
        "migrations/postgres/0183_bound_membership_principal_integrity.sql",
        "api/db_models.py",
        "tests/test_hard_002_bound_membership_principal_integrity.py",
        "tests/test_hard_001_identity_authority_hardening.py",
        "tests/test_pr_auth_004_runtime_principal_authority_cutover.py",
        "docs/architecture/HARD_001_IDENTITY_AUTHORITY_HARDENING.md",
        "docs/architecture/HARD_002_BOUND_PRINCIPAL_INTEGRITY.md",
        "docs/architecture/PR_AUTH_003_RECONCILIATION.md",
        "docs/architecture/PR_AUTH_004_RUNTIME_PRINCIPAL_CUTOVER.md",
        "docs/ai/PR_FIX_LOG.md",
    }
    assert _INVITATION_FLOW.exists()
    assert _PRINCIPAL_AUTHORITY.exists()
    assert _PR_AUTH_004_TEST.exists()
    # Static contract for the intended diff footprint; the pre-commit audit
    # separately compares this against git diff --name-only.
    assert "api/principal_authority.py" not in changed_allowed
    assert "admin_gateway/identity/invitation_flow.py" not in changed_allowed


def test_N2_migration_contains_no_legacy_cleanup_or_authority_writes() -> None:
    src = _executable_sql(_MIGRATION_0183.read_text(encoding="utf-8")).upper()
    forbidden = (
        "DROP COLUMN",
        "DELETE FROM",
        "UPDATE TENANT_USERS",
        "INSERT INTO FG_PRINCIPALS",
        "INSERT INTO FG_EXTERNAL_IDENTITIES",
        "PRINCIPAL_ID NOT NULL",
    )
    for token in forbidden:
        assert token not in src


def test_PG1_real_postgres_rejects_bound_null_when_configured() -> None:
    db_url = os.getenv("FG_DB_URL")
    if not db_url:
        pytest.skip("FG_DB_URL not configured")

    from api.db_migrations import apply_migrations

    pg_engine = create_engine(db_url, future=True)
    if pg_engine.dialect.name != "postgresql":
        pytest.skip("FG_DB_URL is not a Postgres DSN")

    apply_migrations(pg_engine)

    membership_id = f"hard002-{uuid.uuid4().hex}"
    tenant_id = f"hard002-tenant-{uuid.uuid4().hex[:12]}"
    principal_id = str(uuid.uuid4())

    with pg_engine.connect() as conn:
        trans = conn.begin()
        try:
            conn.execute(
                text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                {"tenant_id": tenant_id},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO fg_principals
                        (id, display_name, primary_email, principal_type,
                         lifecycle_state, mfa_verified, authority_version,
                         created_at, updated_at)
                    VALUES
                        (:id, 'Hard 002 Principal', :email, 'human',
                         'active', false, 1, now(), now())
                    """
                ),
                {"id": principal_id, "email": f"{principal_id}@example.com"},
            )
            with pytest.raises(IntegrityError):
                with conn.begin_nested():
                    conn.execute(
                        text(
                            """
                            INSERT INTO tenant_users
                                (id, tenant_id, email, display_name, role, active,
                                 identity_binding_status, identity_type, principal_id)
                            VALUES
                                (:id, :tenant_id, :email, 'Hard 002 Bad Member',
                                 'user', true, 'bound', 'human', NULL)
                            """
                        ),
                        {
                            "id": f"hard002-bad-{uuid.uuid4().hex}",
                            "tenant_id": tenant_id,
                            "email": f"bad-{uuid.uuid4().hex}@example.com",
                        },
                    )
            conn.execute(
                text(
                    """
                    INSERT INTO tenant_users
                        (id, tenant_id, email, display_name, role, active,
                         identity_binding_status, identity_type, principal_id)
                    VALUES
                        (:id, :tenant_id, :email, 'Hard 002 Member', 'user',
                         true, 'unbound', 'human', NULL)
                    """
                ),
                {
                    "id": membership_id,
                    "tenant_id": tenant_id,
                    "email": f"{membership_id}@example.com",
                },
            )
            with pytest.raises(IntegrityError):
                with conn.begin_nested():
                    conn.execute(
                        text(
                            """
                            UPDATE tenant_users
                               SET identity_binding_status = 'bound',
                                   principal_id = NULL
                             WHERE id = :id
                            """
                        ),
                        {"id": membership_id},
                    )
            trans.rollback()
        finally:
            if trans.is_active:
                trans.rollback()
    pg_engine.dispose()
