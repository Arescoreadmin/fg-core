from __future__ import annotations

import pytest

from api.config.startup_validation import validate_startup_config


def test_startup_validation_fails_closed_in_production(monkeypatch):
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_API_KEY", "")
    with pytest.raises(RuntimeError):
        validate_startup_config(fail_on_error=True, log_results=False)
