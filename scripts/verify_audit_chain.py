#!/usr/bin/env python3
from __future__ import annotations

# ruff: noqa: E402

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from api.security_audit import (
    AuditEvent,
    EventType,
    Severity,
    SecurityAuditor,
    verify_audit_chain,
)


def main() -> int:
    db_path = Path("/tmp/fg-audit-chain-check.db")
    if db_path.exists():
        db_path.unlink()

    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ.pop("FG_DB_URL", None)
    reset_engine_cache()
    init_db()

    auditor = SecurityAuditor(persist_to_db=True)
    auditor.log_event(
        AuditEvent(
            event_type=EventType.STARTUP, severity=Severity.INFO, tenant_id="tenant-a"
        )
    )
    auditor.log_event(
        AuditEvent(
            event_type=EventType.ADMIN_ACTION,
            severity=Severity.WARNING,
            tenant_id="tenant-a",
            details={"op": "x"},
        )
    )

    ok = verify_audit_chain("tenant-a")
    if not ok.get("ok"):
        raise SystemExit(f"verify should pass, got {ok}")

    engine = get_engine()
    with Session(engine) as session:
        session.execute(
            text(
                "UPDATE security_audit_log SET reason='tampered' WHERE id=(SELECT max(id) FROM security_audit_log)"
            )
        )
        session.commit()

    bad = verify_audit_chain("tenant-a")
    if bad.get("ok"):
        raise SystemExit("verify should fail after tamper")

    print("audit chain verification gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
