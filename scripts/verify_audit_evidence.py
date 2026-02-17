#!/usr/bin/env python3
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from api.db_models import AuditExport
from services.audit_engine.engine import append_audit_record, export_evidence_bundle, verify_export_manifest


def main() -> int:
    db_path = Path('/tmp/fg-audit-evidence.db')
    if db_path.exists():
        db_path.unlink()
    os.environ['FG_ENV'] = 'test'
    os.environ['FG_SQLITE_PATH'] = str(db_path)
    reset_engine_cache()
    init_db()
    engine = get_engine()
    with Session(engine) as db:
        append_audit_record(db, tenant_id='t1', invariant_id='inv', decision='pass', config_hash='a'*64, policy_hash='b'*64)
        db.commit()
        now = datetime.now(tz=UTC)
        out = export_evidence_bundle(db, tenant_id='t1', start=now-timedelta(days=1), end=now, purpose='ci', triggered_by='ci', retention_class='regulated', force=True)
        if not verify_export_manifest(out['manifest'], out['bundle']):
            raise SystemExit('manifest verification failed')
        row = db.query(AuditExport).filter(AuditExport.tenant_id == 't1').first()
        if row is None or row.size_bytes <= 0:
            raise SystemExit('evidence metadata missing')
    print('audit evidence verify: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
