from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from api.db_migrations import apply_migrations


def _require_db_url() -> str:
    db_url = (os.getenv("FG_DB_URL") or "").strip()
    if not db_url:
        raise RuntimeError("FG_DB_URL is required for postgres tests")
    return db_url


@pytest.fixture(scope="session")
def pg_engine() -> Engine:
    engine = create_engine(_require_db_url(), future=True)
    apply_migrations(engine)
    return engine
