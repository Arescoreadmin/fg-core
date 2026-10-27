from __future__ import annotations

import os
from collections.abc import Iterator

# Set test defaults before any module-level import that may touch DB paths or credentials.
# Mirrors the pattern in tests/conftest.py so the backend subtree is self-sufficient
# when collected without the root tests/ conftest (e.g., a shard containing only
# backend/tests/ files).
os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")

import pytest

from api.db import init_db, reset_engine_cache
from api.main import build_app as _build_app


def pytest_configure() -> None:
    os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")


_CI_TEST_KEY = "ci-test-key-00000000000000000000000000000000"


@pytest.fixture(scope="session", autouse=True)
def _test_env_defaults() -> None:
    os.environ.setdefault("FG_API_KEY", _CI_TEST_KEY)
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")


@pytest.fixture(scope="session", autouse=True)
def _backend_session_db(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Pre-initialize a writable SQLite DB for the backend test session.

    Tests that call mint_key() without the build_app fixture (e.g., the module-level
    TestClient in test_stats_endpoint.py) need the engine initialized with a valid,
    writable path before any request fires the app lifespan.  This mirrors _session_env
    in tests/conftest.py so the backend subtree works in isolation.

    Root causes this fixture resolves:
    - FG_KEY_PEPPER was absent → RuntimeError in _get_pepper() on first mint_key() call.
    - FG_SQLITE_PATH defaulted to /tmp/frostgate/fg-conftest.db whose parent directory
      was only created lazily by _sqlite_url(); in some orderings the engine cache was
      stale and _sqlite_url() never ran for that path → sqlite3.OperationalError.
    """
    db_path = str(tmp_path_factory.mktemp("backend-session") / "backend-session.db")
    os.environ["FG_SQLITE_PATH"] = db_path
    os.environ["FG_KEY_PEPPER"] = "ci-test-pepper"
    os.environ["FG_ENV"] = "test"
    os.environ["FG_API_KEY"] = _CI_TEST_KEY
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    yield
    reset_engine_cache()


@pytest.fixture(autouse=True)
def _restore_env() -> Iterator[None]:
    before = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(before)


def _require_api_key() -> str:
    api_key = os.environ.get("FG_API_KEY", "").strip()
    return api_key or _CI_TEST_KEY


@pytest.fixture()
def build_app(tmp_path, monkeypatch):
    def _factory(auth_enabled: bool = True, sqlite_path: str | None = None):
        db_path = sqlite_path or str(tmp_path / "fg-test.db")
        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_AUTH_ENABLED", "1" if auth_enabled else "0")
        monkeypatch.setenv("FG_API_KEY", _require_api_key())
        monkeypatch.setenv("FG_UI_TOKEN_GET_ENABLED", "1")
        monkeypatch.setenv("FG_ENV", "test")
        monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

        reset_engine_cache()
        init_db(sqlite_path=db_path)
        return _build_app()

    return _factory
