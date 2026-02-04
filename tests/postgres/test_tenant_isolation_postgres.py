from __future__ import annotations

import json

from sqlalchemy import text


def _insert_decision(conn, tenant_id: str, event_id: str) -> None:
    conn.execute(text("SET LOCAL app.tenant_id = :tenant_id"), {"tenant_id": tenant_id})
    payload = {
        "tenant_id": tenant_id,
        "source": "test",
        "event_id": event_id,
        "event_type": "test.tenant",
        "policy_hash": "a" * 64,
        "threat_level": "low",
        "anomaly_score": 0.0,
        "ai_adversarial_score": 0.0,
        "pq_fallback": False,
        "rules_triggered_json": json.dumps([]),
        "decision_diff_json": None,
        "request_json": json.dumps({"request_id": event_id}),
        "response_json": json.dumps({"decision": "allow"}),
        "prev_hash": "GENESIS",
        "chain_hash": "chain-hash",
        "chain_alg": "sha256/canonical-json/v1",
        "chain_ts": "2024-01-01T00:00:00Z",
    }
    conn.execute(
        text(
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
            """
        ),
        payload,
    )


def test_tenant_isolation_rls_blocks_cross_tenant_reads(postgres_engine) -> None:
    with postgres_engine.begin() as conn:
        _insert_decision(conn, "tenant-a", "event-a")

    with postgres_engine.begin() as conn:
        _insert_decision(conn, "tenant-b", "event-b")

    with postgres_engine.begin() as conn:
        conn.execute(text("SET LOCAL app.tenant_id = :tenant_id"), {"tenant_id": "tenant-a"})
        rows = conn.execute(text("SELECT tenant_id FROM decisions"))
        tenants = {row[0] for row in rows.fetchall()}
        assert tenants == {"tenant-a"}

        rows = conn.execute(
            text("SELECT tenant_id FROM decisions WHERE tenant_id != 'tenant-a'")
        ).fetchall()
        assert rows == []
