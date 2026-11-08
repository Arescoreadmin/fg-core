from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text


@pytest.mark.skipif(not os.getenv("FG_DB_URL"), reason="FG_DB_URL not configured")
def test_postgres_migrations_apply_smoke() -> None:
    engine = create_engine(os.environ["FG_DB_URL"], future=True)
    with engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname='public'")
            )
        }
        assert "schema_migrations" in tables
        assert "decisions" in tables

        versions = {
            row[0]
            for row in conn.execute(text("SELECT version FROM schema_migrations"))
        }
        assert "0007" in versions

        row = conn.execute(
            text(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = 'decisions'
                """
            )
        ).one()
        assert row[0] is True
        assert row[1] is True
