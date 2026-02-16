#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from services.audit_engine.engine import append_audit_record, verify_audit_chain


def main() -> int:
    db_path = Path('/tmp/fg-audit-checkpoint.db')
    if db_path.exists():
        db_path.unlink()
    os.environ['FG_ENV'] = 'test'
    os.environ['FG_SQLITE_PATH'] = str(db_path)
    os.environ['FG_AUDIT_CHECKPOINT_INTERVAL'] = '3'
    reset_engine_cache()
    init_db()
    engine = get_engine()
    with Session(engine) as db:
        for i in range(7):
            append_audit_record(db, tenant_id='t1', invariant_id=f'inv-{i}', decision='pass', config_hash='a'*64, policy_hash='b'*64)
        db.commit()
        ok = verify_audit_chain(db, tenant_id='t1')
        if not ok.get('ok'):
            raise SystemExit(f'checkpoint verify failed: {ok}')
        db.execute(text("INSERT INTO audit_ledger(tenant_id,timestamp_utc,invariant_id,decision,config_hash,policy_hash,git_commit,runtime_version,host_id,sha256_self_hash,previous_record_hash,signature) VALUES ('t1','2026-01-01T00:00:00Z','tamper','pass',:c,:p,'x','x','x',:h,'broken-prev','dead')"),{'c':'a'*64,'p':'b'*64,'h':'f'*64})
        db.commit()
        bad = verify_audit_chain(db, tenant_id='t1')
        if bad.get('ok'):
            raise SystemExit('tamper not detected')
    print('audit checkpoint verification: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
