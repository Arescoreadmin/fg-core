from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import get_engine, init_db, reset_engine_cache
from api.security_audit import (
    AuditEvent,
    EventType,
    SecurityAuditor,
    verify_audit_chain,
)


def test_audit_chain_detects_tamper(tmp_path, monkeypatch):
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "audit.db"))
    monkeypatch.delenv("FG_DB_URL", raising=False)
    reset_engine_cache()
    init_db()

    auditor = SecurityAuditor(persist_to_db=True)
    auditor.log_event(AuditEvent(event_type=EventType.STARTUP, tenant_id="tenant-a"))
    auditor.log_event(AuditEvent(event_type=EventType.SHUTDOWN, tenant_id="tenant-a"))

    assert verify_audit_chain("tenant-a")["ok"] is True

    engine = get_engine()
    with Session(engine) as session:
        session.execute(text("UPDATE security_audit_log SET reason='evil' WHERE id=2"))
        session.commit()

    result = verify_audit_chain("tenant-a")
    assert result["ok"] is False


def test_audit_persistence_fails_closed_in_prod(monkeypatch):
    monkeypatch.setenv("FG_ENV", "prod")
    auditor = SecurityAuditor(persist_to_db=True)

    def boom(*args, **kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr("api.db.get_engine", boom)

    import pytest

    with pytest.raises(Exception) as exc:
        auditor.log_event(AuditEvent(event_type=EventType.STARTUP))

    assert "FG-AUDIT-001" in str(exc.value)
