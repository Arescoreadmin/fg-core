from __future__ import annotations

import os


NON_CRITICAL_PREFIXES = (
    "/ai",
    "/ai-plane",
    "/enterprise-controls",
    "/compliance-cp",
)


def shed_non_critical(path: str) -> bool:
    enabled = (os.getenv("FG_BACKPRESSURE_ENABLED") or "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not enabled:
        return False
    return path.startswith(NON_CRITICAL_PREFIXES)
