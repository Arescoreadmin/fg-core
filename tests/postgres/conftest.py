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
#
# Makefile lanes often pass FG_DB_URL, so we also accept that as a fallback.
# ---------------------------------------------------------------------


def _pg_enabled() -> bool:
    return os.environ.get("FG_POSTGRES_TESTS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _pg_dsn() -> str:
    # Prefer explicit postgres test DSN
    dsn = os.environ.get("FG_POSTGRES_DSN", "").strip()
    if dsn:
        return dsn

    # Fall back to main DB URL if provided (common in Makefile targets)
    db_url = os.environ.get("FG_DB_URL", "").strip()
    if db_url:
        return db_url

    # Last resort local default (still requires explicit enable)
    return "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres"


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
def _pg_clean_state(pg_engine: Engine):
    """
    Hard isolation between tests:
    - Reset session vars
    - Clear tenant context
    - TRUNCATE tables used by tests to prevent cross-test pollution

    TRUNCATE is used (not DELETE) because append-only triggers will block DELETE.
    """
    with pg_engine.begin() as conn:
        conn.execute(text("RESET ALL"))
        # Clear tenant context explicitly
        conn.execute(text("SELECT set_config('app.tenant_id', '', true)"))

        # Clean tables touched by postgres tests. CASCADE handles FKs.
        conn.execute(
            text(
                """
                TRUNCATE TABLE
                    decision_evidence_artifacts,
                    decisions,
                    api_keys,
                    security_audit_log,
                    policy_change_requests
                RESTART IDENTITY CASCADE
                """
            )
        )
    yield
