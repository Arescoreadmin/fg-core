from __future__ import annotations

import os

import pytest

from api.db import get_engine, init_db, reset_engine_cache


def _postgres_url() -> str | None:
    url = (os.getenv("FG_DB_URL") or "").strip()
    backend = (os.getenv("FG_DB_BACKEND") or "").strip().lower()
    if backend != "postgres" or not url:
        return None
    return url


@pytest.fixture(scope="session")
def postgres_url() -> str:
    """
    Postgres lane is opt-in.

    - In sqlite/fast lanes, this fixture should NOT fail the run.
    - In postgres lane, Makefile/CI should set FG_DB_BACKEND=postgres and FG_DB_URL.
    """
    url = _postgres_url()
    if not url:
        pytest.skip(
            "postgres tests skipped: set FG_DB_BACKEND=postgres and FG_DB_URL to enable"
        )
    return url


@pytest.fixture()
def postgres_engine(postgres_url: str):
    reset_engine_cache()

    # Ensure downstream code sees consistent env for the duration of the test.
    prev_backend = os.environ.get("FG_DB_BACKEND")
    prev_url = os.environ.get("FG_DB_URL")
    os.environ["FG_DB_BACKEND"] = "postgres"
    os.environ["FG_DB_URL"] = postgres_url

    init_db()
    engine = get_engine()

    try:
        yield engine
    finally:
        # Best-effort cleanup so tests remain isolated (and failures don't poison later runs).
        try:
            with engine.begin() as conn:
                conn.exec_driver_sql(
                    "TRUNCATE decision_evidence_artifacts, decisions RESTART IDENTITY CASCADE"
                )
                conn.exec_driver_sql("TRUNCATE api_keys RESTART IDENTITY CASCADE")
        finally:
            # Restore original env to avoid leaking state across unrelated tests.
            if prev_backend is None:
                os.environ.pop("FG_DB_BACKEND", None)
            else:
                os.environ["FG_DB_BACKEND"] = prev_backend

            if prev_url is None:
                os.environ.pop("FG_DB_URL", None)
            else:
                os.environ["FG_DB_URL"] = prev_url

            reset_engine_cache()
