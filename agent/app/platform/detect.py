from __future__ import annotations

import platform


def detect_platform() -> str:
    return platform.system().lower()
