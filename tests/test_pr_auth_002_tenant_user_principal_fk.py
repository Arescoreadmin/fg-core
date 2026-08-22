"""PR-AUTH-002 — tenant_users.principal_id FK column tests.

All tests run against SQLite in-memory using the canonical schema for
fg_principals, fg_external_identities (migrations 0179 + 0180), and the
new principal_id column on tenant_users (migration 0181).

Coverage groups:
  A — Schema invariants (source-level)
  B — Column presence and nullability
  C — FK integrity: principal_id must reference fg_principals.id
  D — Legacy identity columns unaffected
  E — Index/constraint: principal_id IS NOT NULL partial index implied
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

# ---------------------------------------------------------------------------
# SQLite schema (mirrors 0179 + 0180 + 0181)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fg_principals (
    id                TEXT        PRIMARY KEY,
    display_name      TEXT,
    primary_email     TEXT,
    principal_type    TEXT        NOT NULL DEFAULT 'human',
    lifecycle_state   TEXT        NOT NULL DEFAULT 'active',
    mfa_verified      INTEGER     NOT NULL DEFAULT 0,
    authority_version INTEGER     NOT NULL DEFAULT 1,
    created_at        TEXT        NOT NULL,
    updated_at        TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS fg_external_identities (
    id               TEXT        PRIMARY KEY,
    principal_id     TEXT        NOT NULL REFERENCES fg_principals(id),
    provider         TEXT        NOT NULL,
    provider_issuer  TEXT        NOT NULL,
    provider_subject TEXT        NOT NULL,
    provider_email   TEXT,
    created_at       TEXT        NOT NULL,
    last_seen_at     TEXT,
    UNIQUE (provider, provider_issuer, provider_subject)
);

CREATE TABLE IF NOT EXISTS tenants (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_users (
    id                       TEXT    PRIMARY KEY,
    tenant_id                TEXT    NOT NULL,
    email                    TEXT    NOT NULL,
    display_name             TEXT    NOT NULL,
    role                     TEXT    NOT NULL DEFAULT 'user',
    active                   INTEGER NOT NULL DEFAULT 1,
    identity_binding_status  TEXT    NOT NULL DEFAULT 'unbound',
    identity_type            TEXT    NOT NULL DEFAULT 'human',
    identity_provider        TEXT,
    identity_subject         TEXT,
    identity_issuer          TEXT,
    membership_version       INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT    NOT NULL,
    updated_at               TEXT    NOT NULL,
    principal_id             TEXT    REFERENCES fg_principals(id)
);
"""

_NOW = "2026-08-22T00:00:00+00:00"


def _setup_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))


@pytest.fixture()
def engine() -> Engine:
    import sqlalchemy

    eng = create_engine("sqlite:///:memory:", echo=False)
    _setup_schema(eng)

    @sqlalchemy.event.listens_for(eng, "connect")
    def _fk_on(dbapi_con, _rec):
        dbapi_con.execute("PRAGMA foreign_keys = ON")

    return eng


def _insert_principal(conn, pid: str) -> None:
    conn.execute(
        text(
            "INSERT INTO fg_principals (id, principal_type, lifecycle_state,"
            " mfa_verified, authority_version, created_at, updated_at)"
            " VALUES (:id, 'human', 'active', 0, 1, :now, :now)"
        ),
        {"id": pid, "now": _NOW},
    )


def _insert_tenant_user(conn, *, uid: str, tenant_id: str, principal_id=None) -> None:
    conn.execute(
        text(
            "INSERT INTO tenant_users"
            " (id, tenant_id, email, display_name, created_at, updated_at, principal_id)"
            " VALUES (:id, :tid, :email, :dn, :now, :now, :pid)"
        ),
        {
            "id": uid,
            "tid": tenant_id,
            "email": f"{uid}@example.com",
            "dn": uid,
            "now": _NOW,
            "pid": principal_id,
        },
    )


# ---------------------------------------------------------------------------
# A — Schema invariants (source-level)
# ---------------------------------------------------------------------------

_MODELS_SRC = __import__("pathlib").Path("api/db_models.py").read_text(encoding="utf-8")
_M181_SRC = (
    __import__("pathlib")
    .Path("migrations/postgres/0181_tenant_users_principal_id.sql")
    .read_text(encoding="utf-8")
)


def test_A1_migration_0181_exists() -> None:
    assert "ALTER TABLE tenant_users" in _M181_SRC
    assert "principal_id" in _M181_SRC
    assert "fg_principals" in _M181_SRC


def test_A2_migration_0181_is_nullable() -> None:
    assert "NOT NULL" not in _M181_SRC.split("ADD COLUMN")[1].split(";")[0]


def test_A3_migration_0181_has_partial_index() -> None:
    assert "ix_tenant_users_principal_id" in _M181_SRC
    assert "WHERE principal_id IS NOT NULL" in _M181_SRC


def test_A4_migration_0181_has_rollback_comment() -> None:
    assert "Rollback" in _M181_SRC or "rollback" in _M181_SRC


def test_A5_orm_has_principal_id_column() -> None:
    assert "principal_id" in _MODELS_SRC
    assert "ix_tenant_users_principal_id" in _MODELS_SRC


def test_A6_orm_uses_uuid_type_for_principal_id() -> None:
    assert "Uuid(as_uuid=False)" in _MODELS_SRC


def test_A7_no_backfill_in_migration() -> None:
    assert "UPDATE" not in _M181_SRC.upper()
    assert "INSERT" not in _M181_SRC.upper()


# ---------------------------------------------------------------------------
# B — Column presence and nullability
# ---------------------------------------------------------------------------


def test_B1_principal_id_column_exists_in_schema(engine: Engine) -> None:
    with engine.connect() as conn:
        row = conn.execute(text("PRAGMA table_info(tenant_users)")).fetchall()
    col_names = [r[1] for r in row]
    assert "principal_id" in col_names


def test_B2_principal_id_is_nullable(engine: Engine) -> None:
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA table_info(tenant_users)")).fetchall()
    col = next(r for r in rows if r[1] == "principal_id")
    # notnull flag == 0 means nullable
    assert col[3] == 0


def test_B3_tenant_user_can_be_inserted_without_principal_id(engine: Engine) -> None:
    tid = str(uuid.uuid4())
    uid = str(uuid.uuid4())
    with engine.begin() as conn:
        _insert_tenant_user(conn, uid=uid, tenant_id=tid, principal_id=None)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": uid}
        ).fetchone()
    assert row is not None
    assert row.principal_id is None


def test_B4_tenant_user_can_be_inserted_with_principal_id(engine: Engine) -> None:
    pid = str(uuid.uuid4())
    uid = str(uuid.uuid4())
    tid = str(uuid.uuid4())
    with engine.begin() as conn:
        _insert_principal(conn, pid)
        _insert_tenant_user(conn, uid=uid, tenant_id=tid, principal_id=pid)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": uid}
        ).fetchone()
    assert row is not None
    assert row.principal_id == pid


# ---------------------------------------------------------------------------
# C — FK integrity
# ---------------------------------------------------------------------------


def test_C1_fk_rejects_nonexistent_principal(engine: Engine) -> None:
    uid = str(uuid.uuid4())
    tid = str(uuid.uuid4())
    ghost_pid = str(uuid.uuid4())
    with engine.begin() as conn:
        with pytest.raises(Exception):
            _insert_tenant_user(conn, uid=uid, tenant_id=tid, principal_id=ghost_pid)


def test_C2_multiple_tenant_users_can_share_same_principal(engine: Engine) -> None:
    """One principal may span multiple tenant memberships."""
    pid = str(uuid.uuid4())
    uid1 = str(uuid.uuid4())
    uid2 = str(uuid.uuid4())
    with engine.begin() as conn:
        _insert_principal(conn, pid)
        _insert_tenant_user(conn, uid=uid1, tenant_id="tenant-a", principal_id=pid)
        _insert_tenant_user(conn, uid=uid2, tenant_id="tenant-b", principal_id=pid)
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id FROM tenant_users WHERE principal_id = :pid"), {"pid": pid}
        ).fetchall()
    assert len(rows) == 2


def test_C3_principal_cannot_be_deleted_while_tenant_user_linked(
    engine: Engine,
) -> None:
    pid = str(uuid.uuid4())
    uid = str(uuid.uuid4())
    with engine.begin() as conn:
        _insert_principal(conn, pid)
        _insert_tenant_user(conn, uid=uid, tenant_id="tenant-x", principal_id=pid)
    with engine.begin() as conn:
        with pytest.raises(Exception):
            conn.execute(text("DELETE FROM fg_principals WHERE id = :id"), {"id": pid})


# ---------------------------------------------------------------------------
# D — Legacy identity columns unaffected
# ---------------------------------------------------------------------------


def test_D1_legacy_identity_columns_still_present(engine: Engine) -> None:
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA table_info(tenant_users)")).fetchall()
    col_names = {r[1] for r in rows}
    for col in (
        "identity_provider",
        "identity_subject",
        "identity_issuer",
        "identity_binding_status",
    ):
        assert col in col_names, f"Missing legacy column: {col}"


def test_D2_tenant_user_with_legacy_identity_and_no_principal_id(
    engine: Engine,
) -> None:
    uid = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_users"
                " (id, tenant_id, email, display_name, identity_provider,"
                "  identity_subject, identity_issuer, identity_binding_status,"
                "  created_at, updated_at)"
                " VALUES (:id, 'tenant-z', :email, :dn, 'auth0',"
                "  'auth0|legacy', 'https://example.auth0.com/', 'bound',"
                "  :now, :now)"
            ),
            {"id": uid, "email": f"{uid}@x.com", "dn": uid, "now": _NOW},
        )
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT principal_id, identity_provider FROM tenant_users WHERE id = :id"
            ),
            {"id": uid},
        ).fetchone()
    assert row is not None
    assert row.principal_id is None
    assert row.identity_provider == "auth0"


# ---------------------------------------------------------------------------
# E — ORM model attribute check
# ---------------------------------------------------------------------------


def test_E1_tenant_user_orm_has_principal_id_attribute() -> None:
    from api.db_models import TenantUser

    assert hasattr(TenantUser, "principal_id")


def test_E2_fg_principal_orm_exists() -> None:
    from api.db_models_principal import FgPrincipal

    assert hasattr(FgPrincipal, "id")
    assert hasattr(FgPrincipal, "lifecycle_state")
