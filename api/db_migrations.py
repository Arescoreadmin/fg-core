from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import sqlparse
from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.engine import Engine


@dataclass(frozen=True)
class Migration:
    version: str
    path: Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _migrations_dir() -> Path:
    return _repo_root() / "migrations" / "postgres"


def _load_migrations() -> list[Migration]:
    mig_dir = _migrations_dir()
    if not mig_dir.exists():
        raise RuntimeError(f"Missing migrations directory: {mig_dir}")
    migrations: list[Migration] = []
    for path in sorted(mig_dir.glob("*.sql")):
        if path.name.endswith(".rollback.sql"):
            continue
        version = path.name.split("_", 1)[0]
        migrations.append(Migration(version=version, path=path))
    if not migrations:
        raise RuntimeError("No postgres migrations found.")
    return migrations


def _ensure_schema_migrations(conn) -> None:
    conn.exec_driver_sql(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


def _applied_versions(conn) -> set[str]:
    _ensure_schema_migrations(conn)
    rows = conn.exec_driver_sql("SELECT version FROM schema_migrations").fetchall()
    return {row[0] for row in rows}


def _apply_sql(conn, sql: str) -> None:
    statements = [stmt.strip() for stmt in sqlparse.split(sql) if stmt.strip()]
    for statement in statements:
        conn.exec_driver_sql(statement)


def apply_migrations(engine: Engine) -> list[str]:
    applied: list[str] = []
    migrations = _load_migrations()
    with engine.begin() as conn:
        applied_versions = _applied_versions(conn)
        for migration in migrations:
            if migration.version in applied_versions:
                continue
            sql = migration.path.read_text(encoding="utf-8")
            _apply_sql(conn, sql)
            conn.execute(
                text("INSERT INTO schema_migrations (version) VALUES (:version)"),
                {"version": migration.version},
            )
            applied.append(migration.version)
    return applied


def assert_migrations_applied(engine: Engine) -> None:
    migrations = _load_migrations()
    with engine.begin() as conn:
        applied_versions = _applied_versions(conn)
        expected = {m.version for m in migrations}
        missing = sorted(expected - applied_versions)
        if missing:
            raise RuntimeError(f"Missing migrations: {', '.join(missing)}")


def assert_append_only_triggers(engine: Engine) -> None:
    expected_tables = {"decisions", "decision_evidence_artifacts"}
    with engine.begin() as conn:
        rows = conn.exec_driver_sql(
            """
            SELECT c.relname, t.tgname
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            WHERE NOT t.tgisinternal
            """
        ).fetchall()
        found = {(row[0], row[1]) for row in rows}

    for table in expected_tables:
        update_trigger = f"{table}_append_only_update"
        delete_trigger = f"{table}_append_only_delete"
        if (table, update_trigger) not in found or (table, delete_trigger) not in found:
            raise RuntimeError(f"Append-only triggers missing for {table}")


def assert_tenant_rls(engine: Engine) -> None:
    expected_tables = {
        "decisions",
        "decision_evidence_artifacts",
        "api_keys",
        "security_audit_log",
    }
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                FROM pg_class c
                WHERE c.relname IN :tables
                """
            ).bindparams(bindparam("tables", expanding=True)),
            {"tables": list(expected_tables)},
        ).fetchall()
        rls_status = {row[0]: (row[1], row[2]) for row in rows}

        policies = conn.execute(
            text(
                """
                SELECT tablename, policyname
                FROM pg_policies
                WHERE tablename IN :tables
                """
            ).bindparams(bindparam("tables", expanding=True)),
            {"tables": list(expected_tables)},
        ).fetchall()
        policy_names = {(row[0], row[1]) for row in policies}

    for table in expected_tables:
        relsecurity = rls_status.get(table)
        if relsecurity is None or not relsecurity[0] or not relsecurity[1]:
            raise RuntimeError(f"RLS not enforced on {table}")
        policy = (table, f"{table}_tenant_isolation")
        if policy not in policy_names:
            raise RuntimeError(f"Tenant isolation policy missing on {table}")


def assert_db_role_safe(engine: Engine) -> None:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT current_user, rolsuper, rolbypassrls
                FROM pg_roles
                WHERE rolname = current_user
                """
            )
        ).one()
    role_name, is_super, has_bypass = row[0], row[1], row[2]
    if is_super or has_bypass:
        raise RuntimeError(
            f"DB role {role_name!r} must not be superuser (got {is_super}) "
            f"and must not have BYPASSRLS (got {has_bypass}); "
            f'run: ALTER ROLE "{role_name}" NOSUPERUSER NOBYPASSRLS;'
        )


def migration_status(engine: Engine) -> list[str]:
    migrations = _load_migrations()
    with engine.begin() as conn:
        applied_versions = _applied_versions(conn)
    statuses = []
    for migration in migrations:
        marker = "applied" if migration.version in applied_versions else "pending"
        statuses.append(f"{migration.version} {marker} {migration.path.name}")
    return statuses


def _require_db_url() -> str:
    db_url = (os.getenv("FG_DB_URL") or "").strip()
    if not db_url:
        raise RuntimeError("FG_DB_URL is required for postgres migrations")
    return db_url


def build_engine() -> Engine:
    return create_engine(_require_db_url(), future=True)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FrostGate DB migrations")
    parser.add_argument("--backend", choices=["postgres"], required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--assert", dest="do_assert", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    engine = build_engine()

    if args.apply:
        applied = apply_migrations(engine)
        if applied:
            print("Applied migrations:", ", ".join(applied))
        else:
            print("No pending migrations.")

    if args.status:
        for line in migration_status(engine):
            print(line)

    if args.do_assert:
        assert_migrations_applied(engine)
        assert_append_only_triggers(engine)
        assert_tenant_rls(engine)
        assert_db_role_safe(engine)
        print("Migration assertions: OK")

    if not (args.apply or args.status or args.do_assert):
        parser.error("At least one of --apply, --status, --assert is required.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
