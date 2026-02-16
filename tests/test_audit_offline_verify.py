from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from services.audit_engine.engine import append_audit_record, export_evidence_bundle


def test_offline_verifier_pass(tmp_path, monkeypatch):
    db_path = tmp_path / "verify.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    engine = get_engine(sqlite_path=str(db_path))
    with Session(engine) as db:
        append_audit_record(db, tenant_id="t1", invariant_id="inv", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()
        now = datetime.now(tz=UTC)
        out = export_evidence_bundle(db, tenant_id="t1", start=now - timedelta(days=1), end=now, purpose="audit", triggered_by="tester", retention_class="regulated", force=True)
        uri = out["storage_uri"]
    bundle_path = uri.replace("file://", "")
    proc = subprocess.run([".venv/bin/python", "scripts/fg_audit_verify.py", "--bundle", bundle_path, "--json"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "\"status\":\"PASS\"" in proc.stdout


def test_offline_verifier_reason_code_on_missing_file(tmp_path):
    proc = subprocess.run([".venv/bin/python", "scripts/fg_audit_verify.py", "--bundle", str(tmp_path / "missing.zip"), "--json"], capture_output=True, text=True)
    assert proc.returncode == 1
    assert '"code":"MISSING_FILE"' in proc.stdout
