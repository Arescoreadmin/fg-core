from __future__ import annotations

import os

# Set deterministic, writable defaults before importing modules that may touch DB paths.
os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
os.environ.setdefault("FG_STATE_DIR", "/tmp/frostgate/state")
os.environ.setdefault("FG_SQLITE_PATH", "/tmp/frostgate/fg-conftest.db")
os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
os.environ.setdefault("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

import pytest

from api.db import init_db, reset_engine_cache
from api.main import build_app as _build_app


def _setenv(key: str, val: str) -> None:
    os.environ[str(key)] = str(val)


def pytest_configure() -> None:
    os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")


@pytest.fixture(scope="session", autouse=True)
def _test_env_defaults() -> None:
    os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")


@pytest.fixture(autouse=True)
def _restore_env():
    before = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(before)


def _require_api_key() -> str:
    api_key = os.environ.get("FG_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("FG_API_KEY must be set for test runs.")
    return api_key


@pytest.fixture(autouse=True, scope="session")
def _session_env(tmp_path_factory: pytest.TempPathFactory):
    """
    Ensure a deterministic sqlite path + schema exists even for tests that call mint_key()
    before building an app.
    """
    db_path = str(tmp_path_factory.mktemp("fg-session") / "fg-session.db")
    _setenv("FG_ENV", "test")
    _setenv("FG_SQLITE_PATH", db_path)
    _setenv("FG_API_KEY", _require_api_key())
    _setenv("FG_KEY_PEPPER", "ci-test-pepper")
    _setenv("FG_UI_TOKEN_GET_ENABLED", "1")
    _setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    _setenv("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

    reset_engine_cache()
    init_db(sqlite_path=db_path)

    yield


@pytest.fixture()
def build_app(tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch):
    """
    Factory fixture so tests can build an app with controlled env.
    """

    def _factory(
        auth_enabled: bool = True,
        sqlite_path: str | None = None,
        dev_events_enabled: bool = False,
        api_key: str | None = None,
        ui_token_get_enabled: bool = True,
    ):
        api_key_value = api_key or _require_api_key()
        db_path = sqlite_path or str(tmp_path / "fg-test.db")

        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_ENV", "test")
        monkeypatch.setenv("FG_AUTH_ENABLED", "1" if auth_enabled else "0")
        monkeypatch.setenv("FG_API_KEY", api_key_value)
        monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
        monkeypatch.setenv("FG_DEV_EVENTS_ENABLED", "1" if dev_events_enabled else "0")
        monkeypatch.setenv(
            "FG_UI_TOKEN_GET_ENABLED", "1" if ui_token_get_enabled else "0"
        )
        monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
        monkeypatch.setenv("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

        reset_engine_cache()
        init_db(sqlite_path=db_path)

        return _build_app()

    return _factory


@pytest.fixture
def fresh_db(tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> str:
    """
    Compatibility fixture for tests that expect `fresh_db` to be a sqlite DB path (str).
    These tests insert rows via sqlite3 directly, so we must create schema in that file.
    """
    db_path = str(tmp_path / "fg-fresh.db")

    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_API_KEY", _require_api_key())
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_UI_TOKEN_GET_ENABLED", "1")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

    reset_engine_cache()
    init_db(sqlite_path=db_path)

    return db_path


@pytest.fixture
def app(build_app):
    """
    Default app fixture.
    If FG_SQLITE_PATH was already set by a prior fixture (e.g., fresh_db),
    build the app against that same sqlite file so inserts and API reads match.
    """
    sqlite_path = os.environ.get("FG_SQLITE_PATH")
    return build_app(auth_enabled=True, sqlite_path=sqlite_path)
