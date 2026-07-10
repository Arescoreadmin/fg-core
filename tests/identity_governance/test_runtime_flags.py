"""Tests for identity runtime feature flags.

Covers PR-01a.1 flag semantics:
    * All flags default to False.
    * Truthy values ("1", "true", "yes", "on", "y", case-insensitive) enable.
    * Falsy values (missing, "", "0", "false") disable.
"""

from __future__ import annotations

import pytest

from api.config.identity_runtime import IdentityRuntimeFlags, _env_flag, get_flags

_ALL_FLAG_NAMES = (
    "FG_IDENTITY_AUTHORITY_ENABLED",
    "FG_SESSION_EVALUATOR_ENABLED",
    "FG_DEVICE_TRUST_ENFORCEMENT_ENABLED",
    "FG_RISK_ENGINE_ENABLED",
    "FG_CONDITIONAL_ACCESS_ENABLED",
    "FG_BREAK_GLASS_RUNTIME_ENABLED",
    "FG_IDENTITY_TIMELINE_ENABLED",
    "FG_IDENTITY_PERSISTENCE_ENABLED",
)


def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ALL_FLAG_NAMES:
        monkeypatch.delenv(name, raising=False)


def test_flags_default_false(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    flags = get_flags()
    for name in _ALL_FLAG_NAMES:
        assert getattr(flags, name) is False, f"{name} must default to False"


@pytest.mark.parametrize(
    "value", ["1", "true", "TRUE", "True", "yes", "YES", "on", "y", "Y"]
)
def test_truthy_env_values_enable(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", value)
    assert get_flags().FG_SESSION_EVALUATOR_ENABLED is True


@pytest.mark.parametrize("value", ["0", "false", "False", "no", "off", "", "banana"])
def test_falsy_env_values_disable(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", value)
    assert get_flags().FG_SESSION_EVALUATOR_ENABLED is False


def test_flags_are_immutable() -> None:
    flags = IdentityRuntimeFlags()
    with pytest.raises((AttributeError, TypeError)):
        flags.FG_SESSION_EVALUATOR_ENABLED = True  # type: ignore[misc]


def test_any_enabled_reflects_runtime_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    assert get_flags().any_enabled() is False
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", "1")
    assert get_flags().any_enabled() is True


def test_env_flag_helper_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FG_UNIT_TEST_FLAG", raising=False)
    assert _env_flag("FG_UNIT_TEST_FLAG") is False
    assert _env_flag("FG_UNIT_TEST_FLAG", default=True) is True


def test_flags_read_fresh_each_call(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    assert get_flags().FG_SESSION_EVALUATOR_ENABLED is False
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", "yes")
    assert get_flags().FG_SESSION_EVALUATOR_ENABLED is True
    monkeypatch.setenv("FG_SESSION_EVALUATOR_ENABLED", "no")
    assert get_flags().FG_SESSION_EVALUATOR_ENABLED is False
