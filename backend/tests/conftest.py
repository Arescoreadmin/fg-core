import os
import pytest

from api.main import build_app as _build_app
from api.db import init_db, reset_engine_cache


def _require_api_key() -> str:
    api_key = os.environ.get("FG_API_KEY", "").strip()
    if not api_key:
        in_pytest = bool(os.environ.get("PYTEST_CURRENT_TEST")) or os.environ.get(
            "FG_ENV"
        ) in {"test", "ci"}
        if in_pytest:
            # Deterministic test-only key to avoid CI/local env drift.
            api_key = "pytest-fg-api-key"
            os.environ["FG_API_KEY"] = api_key
        else:
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
