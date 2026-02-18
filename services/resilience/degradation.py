from __future__ import annotations

import os


SAFE_ALWAYS_PREFIXES = ("/health", "/ready", "/metrics", "/audit", "/evidence")


def is_degraded_mode() -> bool:
    return (os.getenv("FG_DEGRADED_MODE") or "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def allow_in_degraded(path: str, method: str) -> bool:
    _ = method
    if path.startswith(SAFE_ALWAYS_PREFIXES):
        return True
    return False


def current_service_state() -> str:
    return "degraded" if is_degraded_mode() else "normal"
