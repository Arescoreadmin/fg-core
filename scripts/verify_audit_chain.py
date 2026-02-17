#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from services.audit_engine.engine import AuditEngine, verify_audit_chain


def main() -> int:
    db_path = Path('/tmp/fg-audit-chain-check.db')
    if db_path.exists():
        db_path.unlink()
    os.environ['FG_ENV'] = 'test'
    os.environ['FG_SQLITE_PATH'] = str(db_path)
    reset_engine_cache()
    init_db()
    engine = get_engine()
    with Session(engine) as db:
        AuditEngine().evaluate_light(db, tenant_id='system')
        result = verify_audit_chain(db, tenant_id='system')
        if not result.get('ok'):
            raise SystemExit(f"audit-chain-verify failed: {result}")
    print('audit chain verification gate: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
