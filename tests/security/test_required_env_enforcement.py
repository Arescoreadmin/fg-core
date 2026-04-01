"""
Regression tests for required production env var enforcement.

Invariants proven:
- Non-prod environments skip required-env enforcement (explicit, not accidental).
- Prod-like environments fail closed when any required env var is absent.
- The runtime startup path (assert_prod_invariants) enforces the same list.
- A full prod env with all required vars present does not raise.
- Single source of truth: tests exercise api.config.required_env directly,
  not duplicated set logic.
"""

from __future__ import annotations

import pytest

from api.config.prod_invariants import assert_prod_invariants
from api.config.required_env import (
    REQUIRED_PROD_ENV_VARS,
    enforce_required_env,
    get_missing_required_env,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_PROD_ENV: dict[str, str] = {
    "FG_ENV": "production",
    "FG_AUTH_ENABLED": "1",
    "FG_DB_URL": "postgresql://x",
    "FG_DB_BACKEND": "postgres",
    "FG_ENFORCEMENT_MODE": "enforce",
    "DATABASE_URL": "postgresql://x",
    "FG_SIGNING_SECRET": "test-signing-secret",
    "FG_INTERNAL_AUTH_SECRET": "test-internal-secret",
}


# ---------------------------------------------------------------------------
# A) Non-prod skip behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fg_env", ["dev", "test", "local", "development", ""])
def test_required_env_non_prod_skips_check(fg_env: str) -> None:
    """Non-prod envs must never raise due to missing prod-only requirements."""
    enforce_required_env({"FG_ENV": fg_env})


def test_required_env_missing_fg_env_skips_check() -> None:
    """Missing FG_ENV is treated as non-prod — must not raise."""
    enforce_required_env({})


# ---------------------------------------------------------------------------
# B) Prod-like missing-env failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing_var", list(REQUIRED_PROD_ENV_VARS))
def test_required_env_prod_fails_when_var_missing(missing_var: str) -> None:
    """Each required var, when absent, must cause enforce_required_env to raise."""
    env = {**_VALID_PROD_ENV}
    del env[missing_var]
    with pytest.raises(RuntimeError, match="Missing required production env vars"):
        enforce_required_env(env)


@pytest.mark.parametrize("missing_var", list(REQUIRED_PROD_ENV_VARS))
def test_required_env_prod_fails_when_var_blank(missing_var: str) -> None:
    """Blank (whitespace-only) values must also be treated as missing."""
    env = {**_VALID_PROD_ENV, missing_var: "   "}
    with pytest.raises(RuntimeError, match="Missing required production env vars"):
        enforce_required_env(env)


@pytest.mark.parametrize("fg_env", ["prod", "production", "staging"])
def test_required_env_all_prod_envs_covered(fg_env: str) -> None:
    """prod, production, and staging all trigger required-env enforcement."""
    env = {k: v for k, v in _VALID_PROD_ENV.items()}
    env["FG_ENV"] = fg_env
    del env["DATABASE_URL"]
    with pytest.raises(RuntimeError, match="Missing required production env vars"):
        enforce_required_env(env)


def test_get_missing_required_env_returns_correct_names() -> None:
    """get_missing_required_env must report exactly the missing var names."""
    env = {**_VALID_PROD_ENV}
    del env["FG_SIGNING_SECRET"]
    missing = get_missing_required_env(env)
    assert missing == ["FG_SIGNING_SECRET"]


# ---------------------------------------------------------------------------
# C) Startup path failure (assert_prod_invariants wired to enforce_required_env)
# ---------------------------------------------------------------------------


def test_prod_startup_fails_when_database_url_missing() -> None:
    """assert_prod_invariants must raise when DATABASE_URL is absent in prod."""
    env = {**_VALID_PROD_ENV}
    del env["DATABASE_URL"]
    with pytest.raises(RuntimeError, match="Missing required production env vars"):
        assert_prod_invariants(env)


def test_prod_startup_fails_when_signing_secret_missing() -> None:
    """assert_prod_invariants must raise when FG_SIGNING_SECRET is absent in prod."""
    env = {**_VALID_PROD_ENV}
    del env["FG_SIGNING_SECRET"]
    with pytest.raises(RuntimeError, match="Missing required production env vars"):
        assert_prod_invariants(env)


def test_prod_startup_fails_when_internal_auth_secret_missing() -> None:
    """assert_prod_invariants must raise when FG_INTERNAL_AUTH_SECRET is absent."""
    env = {**_VALID_PROD_ENV}
    del env["FG_INTERNAL_AUTH_SECRET"]
    with pytest.raises(RuntimeError, match="Missing required production env vars"):
        assert_prod_invariants(env)


# ---------------------------------------------------------------------------
# D) Startup path success
# ---------------------------------------------------------------------------


def test_prod_startup_succeeds_when_all_required_env_present() -> None:
    """assert_prod_invariants must not raise when all required env vars are present."""
    assert_prod_invariants(_VALID_PROD_ENV)


def test_required_env_prod_passes_when_all_present() -> None:
    """enforce_required_env must not raise when all required vars are set."""
    enforce_required_env(_VALID_PROD_ENV)


# ---------------------------------------------------------------------------
# E) No duplicate logic drift
# ---------------------------------------------------------------------------


def test_required_env_authoritative_list_is_not_empty() -> None:
    """REQUIRED_PROD_ENV_VARS must be non-empty — guards against accidental erasure."""
    assert len(REQUIRED_PROD_ENV_VARS) >= 1


def test_required_env_check_script_uses_shared_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CI check script must use get_missing_required_env from shared module."""
    import inspect

    import tools.ci.check_required_env as script

    # Verify the script imports from the shared module (no inline reimplementation).
    src = inspect.getsource(script)
    assert "from api.config.required_env import" in src, (
        "check_required_env.py must import from api.config.required_env"
    )
    assert "REQUIRED_ENV_VARS" not in src or "REQUIRED_PROD_ENV_VARS" in src, (
        "check_required_env.py must not define its own REQUIRED_ENV_VARS list"
    )
