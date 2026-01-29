import os
import pytest

from api.main import build_app as _build_app
from api.db import init_db, reset_engine_cache


@pytest.fixture(scope="session", autouse=True)
def _test_env_defaults() -> None:
    os.environ.setdefault(
        "FG_API_KEY", "ci-test-key-00000000000000000000000000000000"
    )
    os.environ.setdefault("FG_ENV", "test")


def pytest_configure() -> None:
    os.environ.setdefault(
        "FG_API_KEY", "ci-test-key-00000000000000000000000000000000"
    )
    os.environ.setdefault("FG_ENV", "test")


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


@pytest.fixture()
def build_app(tmp_path, monkeypatch):
    def _factory(auth_enabled: bool = True, sqlite_path: str | None = None):
        db_path = sqlite_path or str(tmp_path / "fg-test.db")
        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_AUTH_ENABLED", "1" if auth_enabled else "0")
        monkeypatch.setenv("FG_API_KEY", _require_api_key())
        monkeypatch.setenv("FG_UI_TOKEN_GET_ENABLED", "1")
        monkeypatch.setenv("FG_ENV", "test")

        reset_engine_cache()
        init_db(sqlite_path=db_path)
        return _build_app()

    return _factory
