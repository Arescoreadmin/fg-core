from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from api.db import get_engine, init_db
from api.db_models import DecisionEvidenceArtifact, DecisionRecord
from api.evidence_artifacts import emit_decision_evidence
from api.evidence_chain import chain_fields_for_decision


def _session_for(db_path: str) -> Session:
    init_db(sqlite_path=db_path)
    engine = get_engine(sqlite_path=db_path)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)()


def _seed_decision(db: Session) -> DecisionRecord:
    ts = datetime(2024, 2, 1, tzinfo=timezone.utc)
    rec = DecisionRecord(
        created_at=ts,
        tenant_id="tenant-imm",
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
    chain = chain_fields_for_decision(
        db,
        tenant_id=rec.tenant_id,
        request_json=rec.request_json,
        response_json=rec.response_json,
        threat_level=rec.threat_level,
        chain_ts=ts,
        event_id=rec.event_id,
    )
    rec.prev_hash = chain["prev_hash"]
    rec.chain_hash = chain["chain_hash"]
    rec.chain_alg = chain["chain_alg"]
    rec.chain_ts = chain["chain_ts"]
    db.add(rec)
    db.flush()
    emit_decision_evidence(db, rec)
    db.commit()
    return rec


def test_decision_updates_rejected(tmp_path):
    db = _session_for(str(tmp_path / "immutability.db"))
    rec = _seed_decision(db)

    rec.threat_level = "critical"
    with pytest.raises(ValueError):
        db.commit()


def test_evidence_artifact_written_and_immutable(tmp_path):
    db = _session_for(str(tmp_path / "evidence.db"))
    rec = _seed_decision(db)

    artifact = (
        db.query(DecisionEvidenceArtifact)
        .filter(DecisionEvidenceArtifact.decision_id == rec.id)
        .first()
    )
    assert artifact is not None
    payload = artifact.payload_json
    payload_str = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    digest = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    assert digest == artifact.evidence_sha256
    assert artifact.storage_path
    assert Path(artifact.storage_path).exists()

    artifact.payload_json = {"tamper": True}
    with pytest.raises(ValueError):
        db.commit()
