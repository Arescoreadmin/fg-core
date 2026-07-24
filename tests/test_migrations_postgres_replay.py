from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import uuid

import pytest
from sqlalchemy import create_engine, text

from api.db_migrations import (
    apply_migrations,
    assert_migrations_applied,
    migration_status,
)
from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401 — registers FA ORM tables on Base

_MIGRATIONS_DIR = pathlib.Path(__file__).parent.parent / "migrations" / "postgres"


def test_postgres_migrations_replay_safe() -> None:
    db_url = os.getenv("FG_DB_URL")
    if not db_url:
        print(
            "SKIP tests/test_migrations_postgres_replay.py: FG_DB_URL not configured",
            file=sys.stderr,
        )
        pytest.skip("FG_DB_URL not configured")

    engine = create_engine(db_url, future=True)

    # FA tables are ORM-managed (not created by SQL migrations) — must exist before
    # SQL patches like ALTER TABLE fa_engagements run.
    Base.metadata.create_all(engine)

    schema_hash_before = _schema_signature(engine)
    print(f"schema_hash_before={schema_hash_before}")

    applied_first = apply_migrations(engine)
    assert applied_first, (
        "Expected first migration apply to mutate a clean CI DB. "
        f"Current status: {migration_status(engine)}"
    )

    schema_hash_first = _schema_signature(engine)
    print(f"schema_hash_after_first_apply={schema_hash_first}")

    applied_second = apply_migrations(engine)
    assert applied_second == []
    assert_migrations_applied(engine)

    schema_hash_second = _schema_signature(engine)
    print(f"schema_hash_after_replay={schema_hash_second}")
    assert schema_hash_second == schema_hash_first


# ─────────────────────────────────────────────────────────────────────────────
# Migration 0161 orphan-filtering regression tests (A–H)
#
# These tests verify that the canonical-tenant JOIN predicate in
# 0161_portal_access_migration.sql correctly filters orphaned portal_grants
# (those whose tenant_id has no row in the tenants table) without failing the
# migration, deleting source rows, or creating synthetic tenants.
#
# Each test runs inside a rolled-back transaction so it leaves the DB pristine.
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def _mig_engine():
    db_url = os.getenv("FG_DB_URL")
    if not db_url:
        pytest.skip("FG_DB_URL not configured")
    engine = create_engine(db_url, future=True)
    # ORM tables must precede SQL migration patches (mirrors the full replay test).
    Base.metadata.create_all(engine)
    apply_migrations(engine)  # idempotent — no-op if already applied
    yield engine
    engine.dispose()


@pytest.fixture
def _tx(_mig_engine):
    """Per-test rolled-back transaction — leaves no persistent test data."""
    with _mig_engine.connect() as conn:
        trans = conn.begin()
        try:
            yield conn
        finally:
            trans.rollback()


def _run_migration_body(conn, filename: str) -> None:
    """Execute every SQL statement in a migration file, skipping BEGIN/COMMIT."""
    sql = (_MIGRATIONS_DIR / filename).read_text()
    for raw in sql.split(";"):
        stmt = raw.strip()
        if not stmt:
            continue
        # Strip comment lines to check for bare transaction keywords.
        non_comment = "\n".join(
            ln for ln in stmt.splitlines() if not ln.strip().startswith("--")
        ).strip()
        if non_comment.upper() in ("BEGIN", "COMMIT"):
            continue
        if non_comment:
            conn.execute(text(stmt))


def _uid(prefix: str = "t") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def _insert_tenant(conn, tenant_id: str) -> None:
    conn.execute(
        text(
            "INSERT INTO tenants (tenant_id, display_name, lifecycle_state)"
            " VALUES (:tid, :dn, 'active') ON CONFLICT DO NOTHING"
        ),
        {"tid": tenant_id, "dn": f"Test {tenant_id}"},
    )


def _insert_portal_grant(
    conn,
    *,
    grant_id: str,
    tenant_id: str,
    client_id: str = "test-client",
    engagement_id: str = "test-eng",
) -> None:
    conn.execute(
        text(
            """
            INSERT INTO portal_grants
                (id, tenant_id, client_id, engagement_id, grant_type,
                 grant_hash, created_by, created_at, expires_at,
                 status, rotation_counter)
            VALUES
                (:id, :tid, :cid, :eid, 'client_portal',
                 'sentinel-not-for-auth', 'test-actor',
                 now()::text, (now() + interval '14 days')::text,
                 'active', 0)
            """
        ),
        {"id": grant_id, "tid": tenant_id, "cid": client_id, "eid": engagement_id},
    )


def _credential_row_exists(conn, grant_id: str) -> bool:
    row = conn.execute(
        text("SELECT 1 FROM tenant_credentials WHERE idempotency_key = :k"),
        {"k": f"legacy-migration:{grant_id}"},
    ).fetchone()
    return row is not None


def _slot_row_exists(
    conn, tenant_id: str, client_id: str, engagement_id: str, grant_id: str
) -> bool:
    slot = f"legacy:{client_id}:{engagement_id}:{grant_id}"
    row = conn.execute(
        text(
            "SELECT 1 FROM credential_slots"
            " WHERE tenant_id = :tid AND credential_slot = :slot"
        ),
        {"tid": tenant_id, "slot": slot},
    ).fetchone()
    return row is not None


def _portal_grant_exists(conn, grant_id: str) -> bool:
    row = conn.execute(
        text("SELECT 1 FROM portal_grants WHERE id = :id"),
        {"id": grant_id},
    ).fetchone()
    return row is not None


# A — canonical grant (tenant exists in tenants) migrates to tenant_credentials
def test_0161_a_canonical_grant_migrates(_tx) -> None:
    tid = _uid("tenant")
    gid = _uid("grant")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=gid, tenant_id=tid)
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert _credential_row_exists(_tx, gid), (
        "Canonical grant must appear in tenant_credentials"
    )
    assert _slot_row_exists(_tx, tid, "test-client", "test-eng", gid), (
        "Canonical grant must appear in credential_slots"
    )


# B — orphaned grant (tenant absent from tenants) is silently excluded
def test_0161_b_orphan_grant_excluded(_tx) -> None:
    gid = _uid("orphan")
    _insert_portal_grant(_tx, grant_id=gid, tenant_id="test-absent-tenant-b")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert not _credential_row_exists(_tx, gid), (
        "Orphaned grant must not appear in tenant_credentials"
    )


# C — orphan does not abort or error the migration
def test_0161_c_orphan_does_not_abort(_tx) -> None:
    gid = _uid("orphan")
    _insert_portal_grant(_tx, grant_id=gid, tenant_id="test-absent-tenant-c")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")  # must not raise


# D — source portal_grant row is NOT deleted or modified by the migration
def test_0161_d_source_row_survives(_tx) -> None:
    tid = _uid("tenant")
    gid = _uid("grant")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=gid, tenant_id=tid)
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert _portal_grant_exists(_tx, gid), (
        "Source portal_grant row must survive the migration"
    )


# E — mixed dataset: canonical migrates, orphan is skipped
def test_0161_e_mixed_dataset(_tx) -> None:
    tid = _uid("tenant")
    canonical_gid = _uid("canon")
    orphan_gid = _uid("orphan")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=canonical_gid, tenant_id=tid, client_id="c1")
    _insert_portal_grant(_tx, grant_id=orphan_gid, tenant_id="test-absent-tenant-e")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert _credential_row_exists(_tx, canonical_gid), "Canonical grant must migrate"
    assert not _credential_row_exists(_tx, orphan_gid), "Orphan grant must not migrate"


# F — replay is idempotent: re-running 0161 produces exactly one row per grant
def test_0161_f_idempotent_replay(_tx) -> None:
    tid = _uid("tenant")
    gid = _uid("grant")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=gid, tenant_id=tid)
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")  # second pass
    count = _tx.execute(
        text("SELECT COUNT(*) FROM tenant_credentials WHERE idempotency_key = :k"),
        {"k": f"legacy-migration:{gid}"},
    ).scalar()
    assert count == 1, (
        f"Expected exactly 1 tenant_credentials row after replay, got {count}"
    )


# G — foreign-key constraint on credential_slots.tenant_id is still enforced
def test_0161_g_fk_integrity_enforced(_tx) -> None:
    sp = _tx.begin_nested()
    caught: Exception | None = None
    try:
        _tx.execute(
            text(
                "INSERT INTO credential_slots"
                " (tenant_id, credential_type, credential_slot, current_generation, rotation_policy)"
                " VALUES ('nonexistent-fk-test-g', 'portal_access', 'legacy:fk:fk:fk', 1, 'immediate')"
            )
        )
        sp.commit()
    except Exception as exc:
        sp.rollback()
        caught = exc
    assert caught is not None, "Expected FK violation but no exception was raised"
    msg = str(caught).lower()
    assert "foreign key" in msg or "violates" in msg, f"Unexpected exception: {caught}"


# H — migration does not insert synthetic tenants as a side-effect
def test_0161_h_no_synthetic_tenants(_tx) -> None:
    count_before = _tx.execute(text("SELECT COUNT(*) FROM tenants")).scalar()
    gid = _uid("orphan")
    _insert_portal_grant(_tx, grant_id=gid, tenant_id="test-absent-tenant-h")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    count_after = _tx.execute(text("SELECT COUNT(*) FROM tenants")).scalar()
    assert count_after == count_before, (
        f"Migration must not create synthetic tenants; tenants count changed"
        f" from {count_before} to {count_after}"
    )


def _schema_signature(engine) -> str:
    with engine.begin() as conn:
        tables = conn.execute(
            text(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
                """
            )
        ).fetchall()
        columns = conn.execute(
            text(
                """
                SELECT table_name, column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                ORDER BY table_name, ordinal_position
                """
            )
        ).fetchall()
        indexes = conn.execute(
            text(
                """
                SELECT schemaname, tablename, indexname, indexdef
                FROM pg_indexes
                WHERE schemaname = 'public'
                ORDER BY tablename, indexname
                """
            )
        ).fetchall()
        policies = conn.execute(
            text(
                """
                SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public'
                ORDER BY tablename, policyname
                """
            )
        ).fetchall()

    payload = repr((tables, columns, indexes, policies)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
