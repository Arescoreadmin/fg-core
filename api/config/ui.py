from __future__ import annotations

import os

from api.config.env import is_production_env


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def ui_enabled() -> bool:
    raw = os.getenv("FG_UI_ENABLED")
    if raw is None or not str(raw).strip():
        return False if is_production_env() else True
    return _env_bool("FG_UI_ENABLED", default=False)


__all__ = ["ui_enabled"]
