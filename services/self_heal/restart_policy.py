from __future__ import annotations

import os


def self_heal_enabled() -> bool:
    return (os.getenv("FG_SELF_HEAL_ENABLED") or "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def restart_threshold() -> int:
    return int(os.getenv("FG_SELF_HEAL_RESTART_THRESHOLD", "3"))
