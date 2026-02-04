from __future__ import annotations

import json

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def _insert_decision(conn, tenant_id: str) -> int:
    conn.execute(text("SET LOCAL app.tenant_id = :tenant_id"), {"tenant_id": tenant_id})
    payload = {
        "tenant_id": tenant_id,
        "source": "test",
        "event_id": "event-append",
        "event_type": "test.append",
        "policy_hash": "a" * 64,
        "threat_level": "low",
        "anomaly_score": 0.0,
        "ai_adversarial_score": 0.0,
        "pq_fallback": False,
        "rules_triggered_json": json.dumps([]),
        "decision_diff_json": None,
        "request_json": json.dumps({"request_id": "req-1"}),
        "response_json": json.dumps({"decision": "allow"}),
        "prev_hash": "GENESIS",
        "chain_hash": "chain-hash",
        "chain_alg": "sha256/canonical-json/v1",
        "chain_ts": "2024-01-01T00:00:00Z",
    }
    stmt = text(
        """
        INSERT INTO decisions
        (tenant_id, source, event_id, event_type, policy_hash, threat_level,
         anomaly_score, ai_adversarial_score, pq_fallback, rules_triggered_json,
         decision_diff_json, request_json, response_json, prev_hash, chain_hash,
         chain_alg, chain_ts)
        VALUES
        (:tenant_id, :source, :event_id, :event_type, :policy_hash, :threat_level,
         :anomaly_score, :ai_adversarial_score, :pq_fallback, :rules_triggered_json,
         :decision_diff_json, :request_json, :response_json, :prev_hash, :chain_hash,
         :chain_alg, :chain_ts)
        RETURNING id
        """
    )
    return conn.execute(stmt, payload).scalar_one()


def _insert_artifact(conn, tenant_id: str, decision_id: int) -> int:
    conn.execute(text("SET LOCAL app.tenant_id = :tenant_id"), {"tenant_id": tenant_id})
    payload = {
        "tenant_id": tenant_id,
        "decision_id": decision_id,
        "evidence_sha256": "b" * 64,
        "storage_path": "/tmp/artifact.json",
        "payload_json": json.dumps({"policy_hash": "a" * 64}),
    }
    stmt = text(
        """
        INSERT INTO decision_evidence_artifacts
        (tenant_id, decision_id, evidence_sha256, storage_path, payload_json)
        VALUES
        (:tenant_id, :decision_id, :evidence_sha256, :storage_path, :payload_json)
        RETURNING id
        """
    )
    return conn.execute(stmt, payload).scalar_one()


def test_append_only_triggers_block_update_delete(postgres_engine) -> None:
    with postgres_engine.begin() as conn:
        decision_id = _insert_decision(conn, "tenant-append")
        artifact_id = _insert_artifact(conn, "tenant-append", decision_id)

        with pytest.raises(DBAPIError):
            conn.execute(
                text("UPDATE decisions SET threat_level='high' WHERE id=:id"),
                {"id": decision_id},
            )

        with pytest.raises(DBAPIError):
            conn.execute(
                text("DELETE FROM decisions WHERE id=:id"),
                {"id": decision_id},
            )

        with pytest.raises(DBAPIError):
            conn.execute(
                text(
                    "UPDATE decision_evidence_artifacts SET storage_path='x' WHERE id=:id"
                ),
                {"id": artifact_id},
            )

        with pytest.raises(DBAPIError):
            conn.execute(
                text("DELETE FROM decision_evidence_artifacts WHERE id=:id"),
                {"id": artifact_id},
            )
