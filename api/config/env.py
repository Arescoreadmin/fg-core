from __future__ import annotations

import os

VALID_FG_ENVS = {"dev", "test", "staging", "prod", "production"}


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def is_strict_env_required() -> bool:
    return _env_bool("FG_REQUIRE_STRICT_ENV", False) or _env_bool(
        "FG_FAIL_CLOSED", False
    )


def fg_env(*, require_explicit: bool = False) -> str:
    raw = os.getenv("FG_ENV")
    if raw is None or not str(raw).strip():
        if require_explicit:
            raise RuntimeError(
                "FG_ENV must be set to one of: dev, test, staging, prod."
            )
        return "dev"

    env = str(raw).strip().lower()
    if env not in VALID_FG_ENVS:
        raise RuntimeError("FG_ENV must be set to one of: dev, test, staging, prod.")

    return "prod" if env == "production" else env


def resolve_env() -> str:
    return fg_env(require_explicit=is_strict_env_required())


def is_production_env() -> bool:
    return resolve_env() in {"prod", "staging"}

