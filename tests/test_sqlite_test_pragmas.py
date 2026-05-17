"""Tests for the test-mode SQLite PRAGMA synchronous=OFF optimization.

Verifies:
- synchronous=OFF is applied when FG_ENV=test and engine is SQLite.
- synchronous=OFF is NOT applied for non-test environments.
- init_db() completes in under 5 seconds in test mode (budget guard).
- Production environment never receives the test pragma.
- The optimization does not compromise schema correctness.
- Determinism: repeated init_db calls on separate paths produce identical schemas.
"""

from __future__ import annotations

import time

import pytest


@pytest.fixture()
def _isolated_engine(tmp_path, monkeypatch):
    """Provide a fresh engine + cleanup for pragma tests.

    Yields the engine object; caller runs assertions on it.
    Resets the module-level engine cache before and after to prevent leakage.
    """
    from api.db import reset_engine_cache

    reset_engine_cache()
    db_path = str(tmp_path / "pragma_test.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    yield db_path
    reset_engine_cache()


def _read_synchronous_pragma(engine) -> int:
    """Return the current PRAGMA synchronous value (0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA)."""
    from sqlalchemy import text

    with engine.connect() as conn:
        row = conn.execute(text("PRAGMA synchronous")).fetchone()
    assert row is not None
    return row[0]


# ---------------------------------------------------------------------------
# Core pragma correctness
# ---------------------------------------------------------------------------


def test_test_env_sqlite_applies_synchronous_off(_isolated_engine, monkeypatch):
    """FG_ENV=test: synchronous=OFF must be applied to every new connection."""
    monkeypatch.setenv("FG_ENV", "test")

    from api.db import get_engine

    engine = get_engine(sqlite_path=_isolated_engine)
    assert _read_synchronous_pragma(engine) == 0, (
        "Expected PRAGMA synchronous=OFF (0) in test mode"
    )


def test_non_test_env_sqlite_does_not_apply_synchronous_off(
    _isolated_engine, monkeypatch
):
    """FG_ENV!=test: synchronous=OFF must NOT be applied.

    The SQLite default is FULL (2). Applying synchronous=OFF in production
    would make the database unsafe against OS crashes and power loss.
    """
    monkeypatch.setenv("FG_ENV", "dev")

    from api.db import get_engine

    engine = get_engine(sqlite_path=_isolated_engine)
    synchronous_val = _read_synchronous_pragma(engine)
    assert synchronous_val != 0, (
        f"PRAGMA synchronous=OFF must NOT be applied in dev env; got {synchronous_val}"
    )


def test_production_env_sqlite_does_not_apply_synchronous_off(
    _isolated_engine, monkeypatch
):
    """FG_ENV=prod: synchronous=OFF must NOT be applied.

    Safety gate: production databases must never use synchronous=OFF.
    """
    monkeypatch.setenv("FG_ENV", "prod")

    from api.db import get_engine

    engine = get_engine(sqlite_path=_isolated_engine)
    synchronous_val = _read_synchronous_pragma(engine)
    assert synchronous_val != 0, (
        f"PRAGMA synchronous=OFF must NOT be applied in prod env; got {synchronous_val}"
    )


# ---------------------------------------------------------------------------
# Runtime budget guard
# ---------------------------------------------------------------------------


def test_init_db_completes_under_budget_in_test_mode(tmp_path, monkeypatch):
    """init_db() must complete in under 5 seconds in FG_ENV=test.

    This is the primary regression guard for the fg-fast runtime budget fix.
    Before the synchronous=OFF optimization, Base.metadata.create_all() took
    ~14 seconds per call due to per-table fsync overhead on file-based SQLite.

    5-second budget is conservative: the fix brings init_db to ~200ms.
    If this test fails, a performance regression has been introduced.
    """
    from api.db import init_db, reset_engine_cache

    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )

    db_path = str(tmp_path / "budget_test.db")
    reset_engine_cache()

    t0 = time.perf_counter()
    init_db(sqlite_path=db_path)
    elapsed = time.perf_counter() - t0

    reset_engine_cache()

    assert elapsed < 5.0, (
        f"init_db() took {elapsed:.2f}s in test mode — "
        f"expected <5s. Performance regression detected. "
        f"Check PRAGMA synchronous=OFF is applied for FG_ENV=test."
    )


# ---------------------------------------------------------------------------
# Schema correctness after optimization
# ---------------------------------------------------------------------------


def test_schema_is_complete_after_fast_init(tmp_path, monkeypatch):
    """Schema must contain all expected tables even with synchronous=OFF."""
    from sqlalchemy import inspect as sa_inspect

    from api.db import get_engine, init_db, reset_engine_cache

    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )

    db_path = str(tmp_path / "schema_test.db")
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    engine = get_engine(sqlite_path=db_path)

    tables = set(sa_inspect(engine).get_table_names())
    reset_engine_cache()

    required_tables = {
        "decisions",
        "api_keys",
        "readiness_frameworks",
        "readiness_assessments",
        "provisioning_organizations",
        "provisioning_workflows",
        "deployment_records",
        "deployment_environments",
    }
    missing = required_tables - tables
    assert not missing, f"Tables missing after fast init: {missing}"


def test_repeated_init_db_produces_identical_schemas(tmp_path, monkeypatch):
    """Two fresh init_db() calls on separate paths must produce the same schema.

    Determinism guard: synchronous=OFF must not affect schema correctness.
    """
    from sqlalchemy import inspect as sa_inspect

    from api.db import get_engine, init_db, reset_engine_cache

    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )

    db1 = str(tmp_path / "schema_a.db")
    db2 = str(tmp_path / "schema_b.db")

    reset_engine_cache()
    init_db(sqlite_path=db1)
    engine1 = get_engine(sqlite_path=db1)
    tables1 = set(sa_inspect(engine1).get_table_names())

    reset_engine_cache()
    init_db(sqlite_path=db2)
    engine2 = get_engine(sqlite_path=db2)
    tables2 = set(sa_inspect(engine2).get_table_names())

    reset_engine_cache()

    assert tables1 == tables2, (
        f"Schema mismatch between two init_db() calls.\n"
        f"Only in first: {tables1 - tables2}\n"
        f"Only in second: {tables2 - tables1}"
    )
