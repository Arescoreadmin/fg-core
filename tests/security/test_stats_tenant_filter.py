from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import DecisionRecord


def _seed_decision(session: Session, tenant_id: str, event_id: str) -> None:
    session.add(
        DecisionRecord(
            tenant_id=tenant_id,
            source="unit-test",
            event_id=event_id,
            event_type="auth.bruteforce",
            threat_level="low",
            anomaly_score=0.1,
            ai_adversarial_score=0.0,
            pq_fallback=False,
            rules_triggered_json=[],
            decision_diff_json=None,
            request_json={"timestamp": datetime.now(timezone.utc).isoformat()},
            response_json={"decision": "allow"},
        )
    )


def test_stats_requires_tenant_filter(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key(tenant_id="tenant-a")

    engine = get_engine()
    with Session(engine) as session:
        _seed_decision(session, "tenant-a", "evt-a")
        _seed_decision(session, "tenant-b", "evt-b")
        session.commit()

    resp = client.get(
        "/stats?tenant_id=tenant-a",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["decisions_24h"] == 1
    assert payload["decisions_7d"] == 1

    forbidden = client.get(
        "/stats?tenant_id=tenant-b",
        headers={"X-API-Key": key},
    )
    assert forbidden.status_code == 403
