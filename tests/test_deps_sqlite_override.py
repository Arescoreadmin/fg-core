from __future__ import annotations

from api import deps


def test_sqlite_override_disabled_outside_test(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.delenv("FG_ALLOW_SQLITE_PATH_OVERRIDE", raising=False)
    assert deps._allow_sqlite_override() is False


def test_sqlite_override_allowed_in_test(monkeypatch) -> None:
    monkeypatch.setenv("FG_ENV", "test")
    assert deps._allow_sqlite_override() is True
