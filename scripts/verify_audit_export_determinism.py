#!/usr/bin/env python3
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from services.audit_engine.engine import append_audit_record, export_evidence_bundle


def main() -> int:
    db_path = Path('/tmp/fg-audit-determinism.db')
    if db_path.exists():
        db_path.unlink()
    os.environ['FG_ENV'] = 'test'
    os.environ['FG_SQLITE_PATH'] = str(db_path)
    reset_engine_cache()
    init_db()
    engine = get_engine()
    with Session(engine) as db:
        append_audit_record(db, tenant_id='t1', invariant_id='soc-invariants', decision='pass', config_hash='a'*64, policy_hash='b'*64)
        db.commit()
        now = datetime.now(tz=UTC)
        a = export_evidence_bundle(db, tenant_id='t1', start=now-timedelta(days=1), end=now, purpose='test', triggered_by='ci', retention_class='regulated')
        b = export_evidence_bundle(db, tenant_id='t1', start=now-timedelta(days=1), end=now, purpose='test', triggered_by='ci', retention_class='regulated')
        if a['manifest']['bundle_sha256'] != b['manifest']['bundle_sha256']:
            raise SystemExit('nondeterministic export hash')
        if not b.get('deduplicated'):
            raise SystemExit('no-churn dedupe failed')
    print('audit export determinism: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
