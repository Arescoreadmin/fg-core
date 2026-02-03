from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session, sessionmaker

from api.db import get_engine, init_db
from api.db_models import DecisionRecord
from api.evidence_chain import (
    CHAIN_ALG,
    GENESIS_HASH,
    build_chain_payload,
    chain_fields_for_decision,
    compute_chain_hash,
)


def _session_for(db_path: str) -> Session:
    init_db(sqlite_path=db_path)
    engine = get_engine(sqlite_path=db_path)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)()


def test_chain_persistence_per_tenant(tmp_path):
    db_path = str(tmp_path / "chain.db")
    db = _session_for(db_path)

    ts1 = datetime(2024, 1, 1, tzinfo=timezone.utc)
    req_a = {"request_id": "req-1", "input": {"a": 1}}
    resp_a = {"policy_version": "v1", "decision": "allow"}

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
        request_json=req_a,
        response_json=resp_a,
    )
    chain1 = chain_fields_for_decision(
        db,
        tenant_id="tenant-a",
        request_json=req_a,
        response_json=resp_a,
        threat_level="low",
        chain_ts=ts1,
        event_id="evt-1",
    )
    rec1.prev_hash = chain1["prev_hash"]
    rec1.chain_hash = chain1["chain_hash"]
    rec1.chain_alg = chain1["chain_alg"]
    rec1.chain_ts = chain1["chain_ts"]
    db.add(rec1)
    db.commit()

    ts2 = ts1 + timedelta(seconds=5)
    req_a2 = {"request_id": "req-2", "input": {"a": 2}}
    resp_a2 = {"policy_version": "v1", "decision": "block"}
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
        request_json=req_a2,
        response_json=resp_a2,
    )
    chain2 = chain_fields_for_decision(
        db,
        tenant_id="tenant-a",
        request_json=req_a2,
        response_json=resp_a2,
        threat_level="high",
        chain_ts=ts2,
        event_id="evt-2",
    )
    rec2.prev_hash = chain2["prev_hash"]
    rec2.chain_hash = chain2["chain_hash"]
    rec2.chain_alg = chain2["chain_alg"]
    rec2.chain_ts = chain2["chain_ts"]
    db.add(rec2)
    db.commit()

    assert rec1.prev_hash == GENESIS_HASH
    assert rec2.prev_hash == rec1.chain_hash
    assert rec2.chain_alg == CHAIN_ALG

    payload = build_chain_payload(
        tenant_id="tenant-a",
        request_json=req_a2,
        response_json=resp_a2,
        threat_level="high",
        chain_ts=ts2,
        event_id="evt-2",
    )
    expected = compute_chain_hash(rec1.chain_hash, payload)
    assert expected == rec2.chain_hash
    assert compute_chain_hash(rec1.chain_hash, payload) == rec2.chain_hash

    rec_b = DecisionRecord(
        created_at=ts1,
        tenant_id="tenant-b",
        source="unit",
        event_id="evt-b1",
        event_type="login",
        threat_level="low",
        anomaly_score=0.0,
        ai_adversarial_score=0.0,
        pq_fallback=False,
        rules_triggered_json=[],
        request_json=req_a,
        response_json=resp_a,
    )
    chain_b = chain_fields_for_decision(
        db,
        tenant_id="tenant-b",
        request_json=req_a,
        response_json=resp_a,
        threat_level="low",
        chain_ts=ts1,
        event_id="evt-b1",
    )
    rec_b.prev_hash = chain_b["prev_hash"]
    rec_b.chain_hash = chain_b["chain_hash"]
    rec_b.chain_alg = chain_b["chain_alg"]
    rec_b.chain_ts = chain_b["chain_ts"]
    db.add(rec_b)
    db.commit()

    assert rec_b.prev_hash == GENESIS_HASH
