from __future__ import annotations

import os
from pathlib import Path


def dependency_health() -> dict[str, str]:
    db_url = (os.getenv("FG_DB_URL") or "").strip()
    state_dir = Path(os.getenv("FG_STATE_DIR") or "state")
    return {
        "db": "configured" if db_url or (os.getenv("FG_SQLITE_PATH") or "") else "unknown",
        "filesystem": "ok" if state_dir.exists() else "degraded",
        "dns": "unknown",
        "opa": "unknown",
    }
