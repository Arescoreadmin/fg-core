#!/usr/bin/env python3
from __future__ import annotations

# ruff: noqa: E402

import os
from pathlib import Path
import sys

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.db import init_db, reset_engine_cache
from services.audit_engine import AuditEngine, AuditTamperDetected


def main() -> int:
    db_path = Path("/tmp/fg-audit-chain-check.db")
    db_path.unlink(missing_ok=True)

    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUDIT_HMAC_KEY_CURRENT"] = "test-audit-key-test-audit-key-0000"
    os.environ["FG_AUDIT_HMAC_KEY_ID_CURRENT"] = "ak1"
    os.environ["FG_AUDIT_TENANT_ID"] = "tenant-a"
    os.environ.pop("FG_DB_URL", None)
    reset_engine_cache()
    init_db()

    engine = AuditEngine()
    sid = engine.run_cycle("light")

    # append-only enforcement
    with Session(engine.engine) as session:
        try:
            session.execute(text("UPDATE audit_ledger SET decision='pass' WHERE id=1"))
            session.commit()
            raise SystemExit("append-only invariant violated")
        except SQLAlchemyError:
            session.rollback()

    # tamper detection
    with Session(engine.engine) as session:
        session.execute(
            text(
                "INSERT INTO audit_ledger(session_id,cycle_kind,timestamp_utc,invariant_id,decision,config_hash,policy_hash,git_commit,runtime_version,host_id,tenant_id,sha256_engine_code_hash,sha256_self_hash,previous_record_hash,signature,details_json) VALUES ('x','light','2026-01-01T00:00:00Z','tampered','pass','a','b','c','d','tenant-a','tenant-a','e','f','g','h','{}')"
            )
        )
        session.commit()
    try:
        engine.run_cycle("light")
        raise SystemExit("tamper detection failed")
    except AuditTamperDetected:
        pass

    db_path.unlink(missing_ok=True)
    reset_engine_cache()
    init_db()
    engine = AuditEngine()
    sid = engine.run_cycle("light")
    a = engine.export_bundle(
        "1970-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
        app_openapi={"openapi": "3.1.0"},
        tenant_id="tenant-a",
    )
    b = engine.export_bundle(
        "1970-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
        app_openapi={"openapi": "3.1.0"},
        tenant_id="tenant-a",
    )
    if a["manifest"]["bundle_sha256"] != b["manifest"]["bundle_sha256"]:
        raise SystemExit("nondeterministic export hash")

    repro = engine.reproduce_session(sid)
    if not repro.get("ok"):
        raise SystemExit(f"reproducibility mismatch: {repro}")

    print("audit chain verification gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
