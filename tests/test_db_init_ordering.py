"""tests/test_db_init_ordering.py — C2 + C3 + H5 regression guards.

Verifies that:
  1. init_db() on Postgres calls create_all() BEFORE apply_migrations() so that
     ALTER TABLE migrations on FA substrate tables don't fail on fresh databases.
  2. FA-targeting ALTER TABLE migrations (0073, 0074) use IF NOT EXISTS, making
     them safe to run after create_all() has already materialised the columns.
  3. No other migration ADD COLUMNs without IF NOT EXISTS target FA tables.
  4. Migration 0075 enables RLS + FORCE on all FA and governance tables (C3).
  5. assert_tenant_rls() expected_tables covers all FA and governance tables (C3).
  6. Migration 0076 adds append-only triggers on fa_engagement_audit_events (H5).
  7. assert_append_only_triggers() expected_tables includes fa_engagement_audit_events (H5).
"""
from __future__ import annotations

import inspect
import os
import re
from pathlib import Path

os.environ.setdefault("FG_ENV", "test")


_MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations" / "postgres"

# Tables created by ORM create_all(), not by a numbered CREATE TABLE migration.
_ORM_MANAGED_FA_TABLES = {
    "fa_engagements",
    "fa_field_observations",
    "fa_normalized_findings",
    "fa_scan_results",
    "fa_document_analyses",
    "fa_evidence_links",
    "fa_engagement_audit_events",
}


def _migration_sql(filename: str) -> str:
    return (_MIGRATIONS_DIR / filename).read_text(encoding="utf-8")


class TestFaMigrationSafety:
    def test_0073_uses_if_not_exists(self) -> None:
        """ALTER TABLE in 0073 must use ADD COLUMN IF NOT EXISTS."""
        sql = _migration_sql("0073_fa_engagement_client_access_code.sql")
        assert "IF NOT EXISTS" in sql.upper(), (
            "0073 must use ADD COLUMN IF NOT EXISTS so it is safe after create_all()"
        )

    def test_0074_uses_if_not_exists(self) -> None:
        """ALTER TABLE in 0074 must use ADD COLUMN IF NOT EXISTS."""
        sql = _migration_sql("0074_fa_field_obs_soft_delete.sql")
        assert "IF NOT EXISTS" in sql.upper(), (
            "0074 must use ADD COLUMN IF NOT EXISTS so it is safe after create_all()"
        )

    def test_no_unsafe_alter_on_orm_managed_tables(self) -> None:
        """Any future migration that alters an ORM-managed FA table must use IF NOT EXISTS."""
        unsafe: list[str] = []
        for path in sorted(_MIGRATIONS_DIR.glob("*.sql")):
            if path.name.endswith(".rollback.sql"):
                continue
            sql = path.read_text(encoding="utf-8")
            for line in sql.splitlines():
                stripped = line.strip().upper()
                if not stripped.startswith("ALTER TABLE"):
                    continue
                # Check if this ALTER TABLE targets one of the ORM-managed FA tables
                for table in _ORM_MANAGED_FA_TABLES:
                    if table.upper() in stripped:
                        # The next meaningful statement should use IF NOT EXISTS
                        # We check the full file for ADD COLUMN without IF NOT EXISTS
                        add_pattern = re.search(
                            r"ADD\s+COLUMN\s+(?!IF\s+NOT\s+EXISTS)", sql, re.IGNORECASE
                        )
                        if add_pattern:
                            unsafe.append(f"{path.name}: ADD COLUMN missing IF NOT EXISTS")
        assert not unsafe, "\n".join(unsafe)


_FA_RLS_TABLES = {
    "fa_engagements",
    "fa_scan_results",
    "fa_document_analyses",
    "fa_field_observations",
    "fa_normalized_findings",
    "fa_evidence_links",
    "fa_engagement_audit_events",
    "fa_quarantined_scans",
    "fa_questionnaires",
    "fa_questionnaire_responses",
    "governance_promotions",
}


class TestFaRls:
    """C3 structural guards — FA tenant RLS coverage."""

    def test_0075_enables_rls_on_all_fa_tables(self) -> None:
        """Migration 0075 must ENABLE ROW LEVEL SECURITY on every FA table."""
        sql = _migration_sql("0075_fa_rls.sql").upper()
        assert "ENABLE ROW LEVEL SECURITY" in sql, (
            "0075 must enable RLS"
        )
        for table in _FA_RLS_TABLES:
            assert table.upper() in sql, (
                f"0075 missing RLS coverage for {table}"
            )

    def test_0075_forces_rls_on_all_fa_tables(self) -> None:
        """Migration 0075 must FORCE ROW LEVEL SECURITY so table owners are also constrained."""
        sql = _migration_sql("0075_fa_rls.sql").upper()
        assert "FORCE ROW LEVEL SECURITY" in sql, (
            "0075 must use FORCE ROW LEVEL SECURITY"
        )

    def test_0075_creates_tenant_isolation_policies(self) -> None:
        """Migration 0075 must create {table}_tenant_isolation policies for each FA table."""
        sql = _migration_sql("0075_fa_rls.sql")
        assert "tenant_isolation" in sql, (
            "0075 must create tenant_isolation policies"
        )
        assert "app.tenant_id" in sql, (
            "0075 policies must reference app.tenant_id session variable"
        )

    def test_assert_tenant_rls_covers_all_fa_tables(self) -> None:
        """assert_tenant_rls() expected_tables must include every FA and governance table."""
        from api.db_migrations import assert_tenant_rls
        import inspect

        source = inspect.getsource(assert_tenant_rls)
        missing = [t for t in _FA_RLS_TABLES if t not in source]
        assert not missing, (
            f"assert_tenant_rls() is missing FA tables: {missing}"
        )


class TestFaAuditEventsAppendOnly:
    """H5 structural guards — fa_engagement_audit_events append-only enforcement."""

    def test_0076_creates_update_trigger(self) -> None:
        """Migration 0076 must create the append-only UPDATE trigger."""
        sql = _migration_sql("0076_fa_audit_events_append_only.sql")
        assert "fa_engagement_audit_events_append_only_update" in sql, (
            "0076 must create fa_engagement_audit_events_append_only_update trigger"
        )
        assert "BEFORE UPDATE" in sql.upper(), (
            "0076 update trigger must fire BEFORE UPDATE"
        )

    def test_0076_creates_delete_trigger(self) -> None:
        """Migration 0076 must create the append-only DELETE trigger."""
        sql = _migration_sql("0076_fa_audit_events_append_only.sql")
        assert "fa_engagement_audit_events_append_only_delete" in sql, (
            "0076 must create fa_engagement_audit_events_append_only_delete trigger"
        )
        assert "BEFORE DELETE" in sql.upper(), (
            "0076 delete trigger must fire BEFORE DELETE"
        )

    def test_0076_uses_append_only_guard(self) -> None:
        """Migration 0076 must wire triggers to the shared append_only_guard() function."""
        sql = _migration_sql("0076_fa_audit_events_append_only.sql")
        assert "append_only_guard" in sql, (
            "0076 triggers must use append_only_guard()"
        )

    def test_assert_append_only_triggers_covers_fa_audit_events(self) -> None:
        """assert_append_only_triggers() must include fa_engagement_audit_events."""
        from api.db_migrations import assert_append_only_triggers

        source = inspect.getsource(assert_append_only_triggers)
        assert "fa_engagement_audit_events" in source, (
            "assert_append_only_triggers() must include fa_engagement_audit_events"
        )


class TestInitDbOrdering:
    def test_create_all_before_apply_migrations_in_source(self) -> None:
        """Structural guard: create_all() must precede apply_migrations() in init_db()."""
        from api import db as db_module

        source = inspect.getsource(db_module.init_db)
        create_pos = source.find("create_all")
        migrate_pos = source.find("apply_migrations")

        assert create_pos != -1, "create_all not found in init_db source"
        assert migrate_pos != -1, "apply_migrations not found in init_db source"
        assert create_pos < migrate_pos, (
            "create_all() must appear before apply_migrations() in init_db() "
            "so FA substrate tables exist when ALTER TABLE migrations run on fresh Postgres"
        )
