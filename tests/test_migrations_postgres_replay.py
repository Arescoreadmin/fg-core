from __future__ import annotations

import hashlib
import os
import sys

import pytest
from sqlalchemy import create_engine, text

from api.db_migrations import apply_migrations


def test_postgres_migrations_replay_safe() -> None:
    db_url = os.getenv("FG_DB_URL")
    if not db_url:
        print(
            "SKIP tests/test_migrations_postgres_replay.py: FG_DB_URL not configured",
            file=sys.stderr,
        )
        pytest.skip("FG_DB_URL not configured")

    engine = create_engine(db_url, future=True)

    schema_hash_before = _schema_signature(engine)
    print(f"schema_hash_before={schema_hash_before}")

    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
        conn.execute(text("GRANT ALL ON SCHEMA public TO fg_user"))
        conn.execute(text("GRANT ALL ON SCHEMA public TO public"))

    applied_first = apply_migrations(engine)
    assert applied_first

    schema_hash_first = _schema_signature(engine)
    print(f"schema_hash_after_first_apply={schema_hash_first}")

    applied_second = apply_migrations(engine)
    assert applied_second == []

    schema_hash_second = _schema_signature(engine)
    print(f"schema_hash_after_replay={schema_hash_second}")
    assert schema_hash_second == schema_hash_first


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
