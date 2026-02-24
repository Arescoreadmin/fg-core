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
    # /app/api/db_migrations.py -> /app
    return Path(__file__).resolve().parents[1]


def _migrations_dir() -> Path:
    return _repo_root() / "migrations" / "postgres"


def _load_migrations() -> list[Migration]:
    mig_dir = _migrations_dir()
    if not mig_dir.exists():
        raise RuntimeError(f"Missing migrations directory: {mig_dir}")

    migrations: list[Migration] = []
    seen_versions: set[str] = set()

    for path in sorted(mig_dir.glob("*.sql")):
        if path.name.endswith(".rollback.sql"):
            continue
        version = path.name.split("_", 1)[0]
        if version in seen_versions:
            raise RuntimeError(f"Duplicate migration version detected: {version}")
        seen_versions.add(version)
        migrations.append(Migration(version=version, path=path))

    if not migrations:
        raise RuntimeError("No postgres migrations found.")
    return migrations


def _ensure_schema_migrations(conn) -> None:
    # Be explicit about schema to avoid search_path surprises.
    conn.exec_driver_sql(
        """
        CREATE TABLE IF NOT EXISTS public.schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


def _applied_versions(conn) -> set[str]:
    _ensure_schema_migrations(conn)
    rows = conn.exec_driver_sql(
        "SELECT version FROM public.schema_migrations"
    ).fetchall()
    return {row[0] for row in rows}


def _apply_sql(conn, sql: str) -> None:
    # Split into executable statements, preserving order.
    # sqlparse.split is generally safe for Postgres, including DO $$ blocks.
    statements = [stmt.strip() for stmt in sqlparse.split(sql) if stmt and stmt.strip()]
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
                text(
                    "INSERT INTO public.schema_migrations (version) VALUES (:version)"
                ),
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


def _existing_tables(conn, tables: set[str]) -> set[str]:
    rows = conn.execute(
        text(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relkind = 'r'
              AND c.relname IN :tables
            """
        ).bindparams(bindparam("tables", expanding=True)),
        {"tables": sorted(tables)},
    ).fetchall()
    return {r[0] for r in rows}


def assert_append_only_triggers(engine: Engine) -> None:
    # These are expected to be append-only and must be enforced by BEFORE UPDATE/DELETE
    # triggers calling public.fg_append_only_enforcer().
    expected_tables = {
        "decisions",
        "decision_evidence_artifacts",
        "device_coverage_ledger",
        "billing_identity_claim_events",
        "billing_invoice_state_events",
        "billing_credit_notes",
        "billing_device_enrollments",
        "billing_device_activity_proofs",
        "billing_coverage_daily_state",
        "billing_count_sync_checkpoint_events",
        "pricing_versions",
        "tenant_contracts",
        "audit_ledger",
        "compliance_requirements",
        "compliance_findings",
        "compliance_snapshots",
        "audit_exam_sessions",
        "compliance_requirement_updates",
        "ai_device_registry",
        "ai_token_usage",
        "ai_quota_daily",
    }

    with engine.begin() as conn:
        existing = _existing_tables(conn, expected_tables)
        missing_tables = sorted(expected_tables - existing)
        if missing_tables:
            raise RuntimeError(
                "Append-only expected tables missing (migrations/DDL drift): "
                + ", ".join(missing_tables)
            )

        rows = conn.exec_driver_sql(
            """
            SELECT
              c.relname AS table_name,
              t.tgname  AS trigger_name,
              pg_get_triggerdef(t.oid, true) AS trigger_def,
              p.proname AS func_name,
              n.nspname AS func_schema
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_proc  p ON p.oid = t.tgfoid
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE NOT t.tgisinternal
            """
        ).fetchall()

        # Map: table -> trigger_name -> (def, func_schema, func_name)
        found: dict[str, dict[str, tuple[str, str, str]]] = {}
        for table_name, trig_name, trig_def, func_name, func_schema in rows:
            found.setdefault(table_name, {})[trig_name] = (
                trig_def,
                func_schema,
                func_name,
            )

    for table in sorted(expected_tables):
        update_trigger = f"{table}_append_only_update"
        delete_trigger = f"{table}_append_only_delete"

        table_trigs = found.get(table, {})
        if update_trigger not in table_trigs or delete_trigger not in table_trigs:
            raise RuntimeError(f"Append-only triggers missing for {table}")

        # Verify correct function + BEFORE semantics (belt-and-suspenders, because humans).
        for trig_name, expected_event in (
            (update_trigger, "UPDATE"),
            (delete_trigger, "DELETE"),
        ):
            trig_def, func_schema, func_name = table_trigs[trig_name]

            ALLOWED_APPEND_ONLY_FUNCTIONS = {
                ("public", "fg_append_only_enforcer"),
                ("public", "audit_ledger_append_only_guard"),
            }

            if (func_schema, func_name) not in ALLOWED_APPEND_ONLY_FUNCTIONS:
                raise RuntimeError(
                    f"Append-only trigger {trig_name} on {table} calls "
                    f"{func_schema}.{func_name} (expected one of {ALLOWED_APPEND_ONLY_FUNCTIONS})"
                )

            # The trigger def string is like:
            # CREATE TRIGGER ... BEFORE UPDATE ON public.table FOR EACH ROW EXECUTE FUNCTION public.fg_append_only_enforcer()
            up = trig_def.upper()
            if "BEFORE" not in up or expected_event not in up:
                raise RuntimeError(
                    f"Append-only trigger {trig_name} on {table} is not BEFORE {expected_event}: {trig_def}"
                )


def assert_tenant_rls(engine: Engine) -> None:
    expected_tables = {
        "decisions",
        "decision_evidence_artifacts",
        "api_keys",
        "security_audit_log",
        "policy_change_requests",
        "billing_devices",
        "billing_identity_claims",
        "billing_identity_claim_events",
        "billing_invoice_state_events",
        "billing_credit_notes",
        "billing_device_enrollments",
        "billing_device_activity_proofs",
        "device_coverage_ledger",
        "billing_coverage_daily_state",
        "tenant_contracts",
        "billing_daily_counts",
        "billing_count_sync_checkpoints",
        "billing_count_sync_checkpoint_events",
        "billing_invoices",
        "billing_runs",
        "audit_ledger",
        "compliance_requirements",
        "compliance_findings",
        "compliance_snapshots",
        "audit_exam_sessions",
        "compliance_requirement_updates",
        "ai_device_registry",
        "ai_token_usage",
        "ai_quota_daily",
    }

    with engine.begin() as conn:
        existing = _existing_tables(conn, expected_tables)
        missing_tables = sorted(expected_tables - existing)
        if missing_tables:
            raise RuntimeError(
                "RLS expected tables missing (migrations/DDL drift): "
                + ", ".join(missing_tables)
            )

        rows = conn.execute(
            text(
                """
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relname IN :tables
                """
            ).bindparams(bindparam("tables", expanding=True)),
            {"tables": sorted(expected_tables)},
        ).fetchall()
        rls_status = {row[0]: (row[1], row[2]) for row in rows}

        policies = conn.execute(
            text(
                """
                SELECT tablename, policyname
                FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename IN :tables
                """
            ).bindparams(bindparam("tables", expanding=True)),
            {"tables": sorted(expected_tables)},
        ).fetchall()
        policy_names = {(row[0], row[1]) for row in policies}

    for table in sorted(expected_tables):
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

    statuses: list[str] = []
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
