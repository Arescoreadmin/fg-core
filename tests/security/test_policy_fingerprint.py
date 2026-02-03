from __future__ import annotations

import re

from sqlalchemy.orm import Session, sessionmaker

from api.db import get_engine, init_db
from api.db_models import DecisionRecord
from engine.policy_fingerprint import get_active_policy_fingerprint


def _session_for(db_path: str) -> Session:
    init_db(sqlite_path=db_path)
    engine = get_engine(sqlite_path=db_path)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)()


def test_policy_hash_is_64_hex():
    fingerprint = get_active_policy_fingerprint()
    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint.policy_hash)


def test_decision_record_persists_policy_hash(tmp_path):
    db_path = str(tmp_path / "policy_hash.db")
    db = _session_for(db_path)

    fingerprint = get_active_policy_fingerprint()

    rec = DecisionRecord(
        tenant_id="tenant-a",
        source="unit",
        event_id="evt-1",
        event_type="login",
        policy_hash=fingerprint.policy_hash,
        threat_level="low",
        anomaly_score=0.0,
        ai_adversarial_score=0.0,
        pq_fallback=False,
        rules_triggered_json=[],
        request_json={"request_id": "req-1"},
        response_json={"policy_hash": fingerprint.policy_hash, "decision": "allow"},
    )
    db.add(rec)
    db.commit()

    fetched = db.query(DecisionRecord).filter(DecisionRecord.id == rec.id).first()
    assert fetched is not None
    assert fetched.policy_hash == fingerprint.policy_hash
