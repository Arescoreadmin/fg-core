from __future__ import annotations

import pytest

from api.config.startup_validation import validate_startup_config


def test_strict_env_requires_fg_env(monkeypatch):
    monkeypatch.delenv("FG_ENV", raising=False)
    monkeypatch.setenv("FG_REQUIRE_STRICT_ENV", "1")

    with pytest.raises(RuntimeError):
        validate_startup_config(fail_on_error=False, log_results=False)


def test_fg_env_dev_allowed(monkeypatch):
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_REQUIRE_STRICT_ENV", "1")

    report = validate_startup_config(fail_on_error=False, log_results=False)
    assert report.env == "dev"
