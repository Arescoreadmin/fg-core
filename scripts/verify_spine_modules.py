#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from importlib import import_module

REQUIRED_MODULES = [
    "api.admin",
    "api.graceful_shutdown",
    "api.governance",
    "api.mission_envelope",
    "api.ring_router",
    "api.roe_engine",
    "engine.doctrine",
    "engine.pipeline",
]


def main() -> int:
    os.environ.setdefault("FG_ADMIN_API_ENABLED", "1")
    os.environ.setdefault("FG_GRACEFUL_SHUTDOWN_ENABLED", "1")

    failures: list[str] = []
    for module_path in REQUIRED_MODULES:
        try:
            import_module(module_path)
        except Exception as exc:
            failures.append(f"{module_path} ({exc})")

    if failures:
        print(
            "❌ Spine module import failures:\n- " + "\n- ".join(failures),
            file=sys.stderr,
        )
        return 1

    print("✅ Spine module imports succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
