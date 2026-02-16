from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

_PROD_ENVS = {"prod", "production", "staging"}
_TRUE = {"1", "true", "yes", "y", "on"}


@dataclass
class ProdInvariantViolation(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}:{self.message}"


def _env_bool(env: Mapping[str, str], key: str, default: bool = False) -> bool:
    raw = env.get(key)
    if raw is None:
        return default
    return str(raw).strip().lower() in _TRUE


def assert_prod_invariants(settings: Mapping[str, str] | None = None) -> None:
    env = settings or os.environ
    fg_env = (env.get("FG_ENV") or "dev").strip().lower()
    if fg_env not in _PROD_ENVS:
        return

    if not _env_bool(env, "FG_AUTH_ENABLED", True):
        raise ProdInvariantViolation(
            "FG-PROD-001", "FG_AUTH_ENABLED must be true in prod/staging"
        )

    for flag in ("FG_AUTH_DB_FAIL_OPEN", "FG_RL_FAIL_OPEN", "FG_AUTH_ALLOW_FALLBACK"):
        if _env_bool(env, flag, False):
            raise ProdInvariantViolation(
                "FG-PROD-002", f"{flag} must be false in prod/staging"
            )

    db_url = (env.get("FG_DB_URL") or "").strip()
    if not db_url:
        raise ProdInvariantViolation(
            "FG-PROD-003", "FG_DB_URL is required in prod/staging"
        )
    if db_url.lower().startswith("sqlite"):
        raise ProdInvariantViolation(
            "FG-PROD-004", "sqlite FG_DB_URL is forbidden in prod/staging"
        )

    if (env.get("FG_DB_BACKEND") or "postgres").strip().lower() != "postgres":
        raise ProdInvariantViolation(
            "FG-PROD-005", "FG_DB_BACKEND must be postgres in prod/staging"
        )

    if (env.get("FG_CONTRACT_SPEC") or "").strip():
        raise ProdInvariantViolation(
            "FG-PROD-006",
            "FG_CONTRACT_SPEC must not be set at runtime in prod/staging",
        )

    raw_mode = (env.get("FG_ENFORCEMENT_MODE") or "").strip()
    if not raw_mode:
        raise ProdInvariantViolation(
            "FG-PROD-007",
            "FG_ENFORCEMENT_MODE must be explicitly set to enforce in prod/staging",
        )

    mode = raw_mode.lower()
    if mode != "enforce":
        raise ProdInvariantViolation(
            "FG-PROD-007", "FG_ENFORCEMENT_MODE must be enforce in prod/staging"
        )
