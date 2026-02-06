from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

# ---------------------------------------------------------------------
# Postgres test lane control
#
# Default behavior: skip postgres tests unless explicitly enabled.
# Enable by setting:
#   FG_POSTGRES_TESTS=1
# And providing a DSN:
#   FG_POSTGRES_DSN=postgresql+psycopg://user:pass@host:5432/dbname
# ---------------------------------------------------------------------


def _pg_enabled() -> bool:
    return os.environ.get("FG_POSTGRES_TESTS", "").strip() in {"1", "true", "yes", "on"}


def _pg_dsn() -> str:
    dsn = os.environ.get("FG_POSTGRES_DSN", "").strip()
    if not dsn:
        # Common local default (adjust if you want), but we still require explicit enable.
        dsn = "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres"
    return dsn


@pytest.fixture(scope="session")
def pg_engine() -> Engine:
    """
    Session-scoped Postgres engine for postgres-only tests.
    Skips cleanly unless FG_POSTGRES_TESTS=1.
    """
    if not _pg_enabled():
        pytest.skip("Postgres tests disabled (set FG_POSTGRES_TESTS=1 to enable).")

    engine = create_engine(_pg_dsn(), pool_pre_ping=True)

    # Sanity ping so failures are obvious.
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        pytest.skip(f"Postgres not reachable for tests: {e}")

    return engine


@pytest.fixture(autouse=True)
def _pg_clean_session(pg_engine: Engine):
    """
    Optional hook: make sure each test runs with a clean session state.
    Keeps weird cross-test leakage down.
    """
    with pg_engine.connect() as conn:
        conn.execute(text("RESET ALL"))
    yield
