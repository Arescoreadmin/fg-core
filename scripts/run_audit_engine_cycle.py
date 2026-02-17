#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from services.audit_engine.engine import AuditEngine


def main() -> int:
    db_path = Path(os.getenv("FG_SQLITE_PATH", "/tmp/fg-audit-engine.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("FG_ENV", "test")
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    reset_engine_cache()
    init_db()
    engine = get_engine()
    audit = AuditEngine()
    with Session(engine) as db:
        audit.evaluate_light(db, tenant_id="system")
    print("audit-engine cycle: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
