from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session, sessionmaker

from api.db import get_engine, init_db
from api.db_models import DecisionRecord
from api.evidence_chain import chain_fields_for_decision, verify_chain_for_tenant


def _session_for(db_path: str) -> Session:
    init_db(sqlite_path=db_path)
    engine = get_engine(sqlite_path=db_path)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)()


def test_chain_verification_detects_tamper(tmp_path):
    db_path = str(tmp_path / "tamper.db")
    db = _session_for(db_path)

    ts1 = datetime(2024, 2, 1, tzinfo=timezone.utc)
    ts2 = ts1 + timedelta(seconds=10)

    rec1 = DecisionRecord(
        created_at=ts1,
        tenant_id="tenant-a",
        source="unit",
        event_id="evt-1",
        event_type="login",
        threat_level="low",
        anomaly_score=0.0,
        ai_adversarial_score=0.0,
        pq_fallback=False,
        rules_triggered_json=[],
        request_json={"request_id": "req-1", "input": {"a": 1}},
        response_json={"policy_version": "v1", "decision": "allow"},
    )
    chain1 = chain_fields_for_decision(
        db,
        tenant_id="tenant-a",
        request_json=rec1.request_json,
        response_json=rec1.response_json,
        threat_level=rec1.threat_level,
        chain_ts=ts1,
        event_id=rec1.event_id,
    )
    rec1.prev_hash = chain1["prev_hash"]
    rec1.chain_hash = chain1["chain_hash"]
    rec1.chain_alg = chain1["chain_alg"]
    rec1.chain_ts = chain1["chain_ts"]
    db.add(rec1)
    db.commit()

    rec2 = DecisionRecord(
        created_at=ts2,
        tenant_id="tenant-a",
        source="unit",
        event_id="evt-2",
        event_type="login",
        threat_level="high",
        anomaly_score=0.0,
        ai_adversarial_score=0.0,
        pq_fallback=False,
        rules_triggered_json=[],
        request_json={"request_id": "req-2", "input": {"a": 2}},
        response_json={"policy_version": "v1", "decision": "block"},
    )
    chain2 = chain_fields_for_decision(
        db,
        tenant_id="tenant-a",
        request_json=rec2.request_json,
        response_json=rec2.response_json,
        threat_level=rec2.threat_level,
        chain_ts=ts2,
        event_id=rec2.event_id,
    )
    rec2.prev_hash = chain2["prev_hash"]
    rec2.chain_hash = chain2["chain_hash"]
    rec2.chain_alg = chain2["chain_alg"]
    rec2.chain_ts = chain2["chain_ts"]
    db.add(rec2)
    db.commit()

    rec1.threat_level = "critical"
    db.commit()

    result = verify_chain_for_tenant(db, tenant_id="tenant-a")
    assert result["ok"] is False
    assert result["first_bad_id"] == rec1.id
