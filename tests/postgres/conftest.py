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


def pytest_configure() -> None:
    os.environ.setdefault("FG_DB_BACKEND", "postgres")


@pytest.fixture(scope="session")
def postgres_url() -> str:
    url = _postgres_url()
    if not url:
        pytest.fail("FG_DB_BACKEND=postgres and FG_DB_URL required for postgres tests")
    return url


@pytest.fixture()
def postgres_engine(postgres_url: str):
    reset_engine_cache()
    os.environ["FG_DB_BACKEND"] = "postgres"
    os.environ["FG_DB_URL"] = postgres_url
    init_db()
    engine = get_engine()
    yield engine
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "TRUNCATE decision_evidence_artifacts, decisions RESTART IDENTITY CASCADE"
        )
        conn.exec_driver_sql("TRUNCATE api_keys RESTART IDENTITY CASCADE")
