from __future__ import annotations

import os
import sys
import pytest

from api.main import build_app as _build_app
from api.db import init_db, reset_engine_cache

if "pytest" in sys.modules:
    os.environ.setdefault(
        "FG_API_KEY", "ci-test-key-00000000000000000000000000000000"
    )
    os.environ.setdefault("FG_ENV", "test")


def _setenv(key: str, val: str) -> None:
    os.environ[str(key)] = str(val)


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
    _setenv("FG_UI_TOKEN_GET_ENABLED", "1")

    # Critical: make sure schema exists in this session DB
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
        monkeypatch.setenv("FG_DEV_EVENTS_ENABLED", "1" if dev_events_enabled else "0")
        monkeypatch.setenv(
            "FG_UI_TOKEN_GET_ENABLED", "1" if ui_token_get_enabled else "0"
        )

        reset_engine_cache()
        init_db(sqlite_path=db_path)

        return _build_app()

    return _factory
