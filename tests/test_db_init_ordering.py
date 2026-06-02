"""tests/test_db_init_ordering.py — C2 regression guard.

Verifies that:
  1. init_db() on Postgres calls create_all() BEFORE apply_migrations() so that
     ALTER TABLE migrations on FA substrate tables don't fail on fresh databases.
  2. FA-targeting ALTER TABLE migrations (0073, 0074) use IF NOT EXISTS, making
     them safe to run after create_all() has already materialised the columns.
  3. No other migration ADD COLUMNs without IF NOT EXISTS target FA tables.
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
