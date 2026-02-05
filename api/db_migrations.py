from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy.engine import Engine

from api.db_models import Base

log = logging.getLogger("frostgate.db.migrations")

MIGRATIONS_DIR = Path("migrations")


@dataclass(frozen=True)
class Migration:
    version: str
    description: str
    apply: Callable[[Engine], None]
    rollback: Callable[[Engine], None]


def _schema_migrations_table(conn) -> None:
    conn.exec_driver_sql(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMP NOT NULL
        )
        """
    )


def _applied_versions(conn) -> set[str]:
    rows = conn.exec_driver_sql("SELECT version FROM schema_migrations")
    return {row[0] for row in rows.fetchall()}


def _record_version(conn, version: str) -> None:
    applied_at = datetime.now(timezone.utc)
    if conn.dialect.name == "sqlite":
        applied_at = applied_at.isoformat()
    conn.exec_driver_sql(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (:version, :applied_at)",
        {
            "version": version,
            "applied_at": applied_at,
        },
    )


def _run_sql_file(engine: Engine, path: Path) -> None:
    sql = path.read_text(encoding="utf-8")
    with engine.begin() as conn:
        conn.exec_driver_sql(sql)


def _sqlite_add_columns(conn, table: str, columns: dict[str, str]) -> None:
    existing = {
        row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    }
    for col, col_type in columns.items():
        if col in existing:
            continue
        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")


def _sqlite_add_immutable_triggers(conn, table: str) -> None:
    conn.exec_driver_sql(
        f"""
        CREATE TRIGGER IF NOT EXISTS {table}_immutable_update
        BEFORE UPDATE ON {table}
        BEGIN
            SELECT RAISE(ABORT, '{table} is append-only');
        END;
        """
    )
    conn.exec_driver_sql(
        f"""
        CREATE TRIGGER IF NOT EXISTS {table}_immutable_delete
        BEFORE DELETE ON {table}
        BEGIN
            SELECT RAISE(ABORT, '{table} is append-only');
        END;
        """
    )


def _auto_migrate_sqlite(engine: Engine) -> None:
    decisions_columns = {
        "prev_hash": "TEXT",
        "chain_hash": "TEXT",
        "chain_alg": "TEXT",
        "chain_ts": "TIMESTAMP",
        "policy_hash": "TEXT",
    }
    api_keys_columns = {
        "key_lookup": "TEXT",
        "hash_alg": "TEXT",
        "hash_params": "TEXT",
    }

    with engine.begin() as conn:
        tables = {
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "decisions" in tables:
            _sqlite_add_columns(conn, "decisions", decisions_columns)
            _sqlite_add_immutable_triggers(conn, "decisions")
        if "decision_evidence_artifacts" in tables:
            _sqlite_add_immutable_triggers(conn, "decision_evidence_artifacts")
        if "api_keys" in tables:
            _sqlite_add_columns(conn, "api_keys", api_keys_columns)


def _apply_schema(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "sqlite":
        _auto_migrate_sqlite(engine)


def _rollback_schema(_engine: Engine) -> None:
    log.warning(
        "Rollback for base schema is not supported; manual intervention required"
    )


def _apply_append_only_triggers(engine: Engine) -> None:
    sql_path = MIGRATIONS_DIR / "postgres" / "0002_append_only_triggers.sql"
    _run_sql_file(engine, sql_path)


def _rollback_append_only_triggers(engine: Engine) -> None:
    sql_path = MIGRATIONS_DIR / "postgres" / "0002_append_only_triggers.rollback.sql"
    _run_sql_file(engine, sql_path)


def _apply_tenant_rls(engine: Engine) -> None:
    sql_path = MIGRATIONS_DIR / "postgres" / "0003_tenant_rls.sql"
    _run_sql_file(engine, sql_path)


def _rollback_tenant_rls(engine: Engine) -> None:
    sql_path = MIGRATIONS_DIR / "postgres" / "0003_tenant_rls.rollback.sql"
    _run_sql_file(engine, sql_path)


MIGRATIONS: list[Migration] = [
    Migration(
        version="0001_base_schema",
        description="Base schema for core tables",
        apply=_apply_schema,
        rollback=_rollback_schema,
    ),
    Migration(
        version="0002_append_only_triggers",
        description="Append-only enforcement for decisions and artifacts",
        apply=_apply_append_only_triggers,
        rollback=_rollback_append_only_triggers,
    ),
    Migration(
        version="0003_tenant_rls",
        description="Tenant isolation with row-level security",
        apply=_apply_tenant_rls,
        rollback=_rollback_tenant_rls,
    ),
]


def run_migrations(engine: Engine, *, backend: str) -> None:
    with engine.begin() as conn:
        _schema_migrations_table(conn)
        applied = _applied_versions(conn)

    for migration in MIGRATIONS:
        if migration.version in applied:
            continue
        if backend != "postgres" and migration.version != "0001_base_schema":
            continue
        log.info("Applying migration %s: %s", migration.version, migration.description)
        migration.apply(engine)
        with engine.begin() as conn:
            _record_version(conn, migration.version)


def assert_append_only_triggers(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as conn:
        rows = conn.exec_driver_sql(
            """
            SELECT tgname
            FROM pg_trigger
            WHERE tgname IN (
                'decisions_append_only_update',
                'decisions_append_only_delete',
                'decision_evidence_artifacts_append_only_update',
                'decision_evidence_artifacts_append_only_delete'
            )
            """
        ).fetchall()
        found = {row[0] for row in rows}
        missing = {
            "decisions_append_only_update",
            "decisions_append_only_delete",
            "decision_evidence_artifacts_append_only_update",
            "decision_evidence_artifacts_append_only_delete",
        } - found
        if missing:
            raise RuntimeError(f"Append-only triggers missing: {sorted(missing)}")


def assert_tenant_rls(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as conn:
        rows = conn.exec_driver_sql(
            """
            SELECT polname
            FROM pg_policies
            WHERE schemaname = 'public'
              AND polname IN (
                'decisions_tenant_isolation',
                'decision_evidence_artifacts_tenant_isolation'
              )
            """
        ).fetchall()
        found = {row[0] for row in rows}
        missing = {
            "decisions_tenant_isolation",
            "decision_evidence_artifacts_tenant_isolation",
        } - found
        if missing:
            raise RuntimeError(f"Tenant RLS policies missing: {sorted(missing)}")


def _cli() -> int:
    import argparse
    import os

    parser = argparse.ArgumentParser(description="FrostGate DB migrations")
    parser.add_argument(
        "--backend",
        choices=["sqlite", "postgres"],
        default=os.getenv("FG_DB_BACKEND", "sqlite"),
    )
    parser.add_argument("--apply", action="store_true", help="Apply migrations")
    parser.add_argument(
        "--assert-append-only",
        action="store_true",
        help="Assert append-only triggers are present (postgres only)",
    )
    parser.add_argument(
        "--assert-rls",
        action="store_true",
        help="Assert tenant RLS policies are present (postgres only)",
    )
    args = parser.parse_args()

    backend = args.backend
    if not args.apply:
        return 0

    if backend == "postgres":
        db_url = os.getenv("FG_DB_URL", "").strip()
        if not db_url:
            raise SystemExit("FG_DB_URL is required for postgres migrations")
        from sqlalchemy import create_engine

        engine = create_engine(db_url, future=True)
    else:
        from sqlalchemy import create_engine

        sqlite_path = os.getenv("FG_SQLITE_PATH", "").strip() or "state/frostgate.db"
        engine = create_engine(
            f"sqlite+pysqlite:///{sqlite_path}",
            future=True,
            connect_args={"check_same_thread": False},
        )

    run_migrations(engine, backend=backend)
    if args.assert_append_only:
        assert_append_only_triggers(engine)
    if args.assert_rls:
        assert_tenant_rls(engine)
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
