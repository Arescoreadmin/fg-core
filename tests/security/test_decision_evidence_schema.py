from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from api.db import get_engine, init_db, reset_engine_cache
from api.db_models import DecisionRecord
from api.evidence_artifacts import emit_decision_evidence
from engine.policy_fingerprint import get_active_policy_fingerprint

SCHEMA_PATH = Path("contracts/artifacts/decision_evidence.schema.json")


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_decision_evidence_artifact_matches_schema(tmp_path) -> None:
    reset_engine_cache()
    db_path = str(tmp_path / "evidence.db")
    init_db(sqlite_path=db_path)
    engine = get_engine(sqlite_path=db_path)

    fingerprint = get_active_policy_fingerprint()

    with engine.begin() as conn:
        record = DecisionRecord(
            created_at=datetime.now(timezone.utc),
            tenant_id="tenant-schema",
            source="unit-test",
            event_id="event-1",
            event_type="test.event",
            policy_hash=fingerprint.policy_hash,
            threat_level="low",
            anomaly_score=0.0,
            ai_adversarial_score=0.0,
            pq_fallback=False,
            rules_triggered_json=["rule:baseline"],
            request_json={"request_id": "req-1", "payload": {"foo": "bar"}},
            response_json={
                "decision": "allow",
                "policy_version": fingerprint.policy_id,
            },
            prev_hash="GENESIS",
            chain_hash="chain-hash",
            chain_alg="sha256/canonical-json/v1",
            chain_ts=datetime.now(timezone.utc),
        )
        from sqlalchemy.orm import Session

        session = Session(bind=conn, expire_on_commit=False)
        session.add(record)
        session.flush()
        artifact = emit_decision_evidence(session, record)
        session.commit()

    payload = artifact.payload_json
    schema = _load_schema()
    Draft202012Validator(schema).validate(payload)
