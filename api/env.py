# api/env.py
import os


def resolve_effective_env() -> tuple[str, str]:
    fg = os.getenv("FG_ENV")
    legacy = os.getenv("FROSTGATE_ENV")

    if fg:
        # canonical wins
        return fg, "FG_ENV"

    if legacy:
        # map legacy -> canonical (and optionally delete legacy)
        os.environ["FG_ENV"] = legacy
        return legacy, "FROSTGATE_ENV(mapped)"

    os.environ["FG_ENV"] = "dev"
    return "dev", "default(dev)"
