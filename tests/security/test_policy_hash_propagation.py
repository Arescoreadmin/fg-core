from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import DecisionRecord
from api.ingest import router as ingest_router
from engine.pipeline import PipelineInput, evaluate as pipeline_evaluate
from engine.policy_fingerprint import get_active_policy_fingerprint


def test_pipeline_policy_hash_propagates():
    expected = get_active_policy_fingerprint().policy_hash
    inp = PipelineInput(
        tenant_id="tenant-1",
        source="unit-test",
        event_type="auth.bruteforce",
        payload={"failed_auths": 6, "src_ip": "203.0.113.10"},
    )
    result = pipeline_evaluate(inp)

    assert re.fullmatch(r"[0-9a-f]{64}", result.policy_hash)
    assert result.policy_hash == expected
    result_dict = result.to_dict()
    assert re.fullmatch(r"[0-9a-f]{64}", result_dict["policy_hash"])
    assert result_dict["policy_hash"] == expected


def test_defend_response_includes_policy_hash(build_app, monkeypatch):
    expected = get_active_policy_fingerprint().policy_hash
    monkeypatch.setenv("FG_RL_ENABLED", "0")
    app = build_app()
    client = TestClient(app)
    key = mint_key("defend:write", tenant_id="tenant-a")

    payload = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_id": "evt-policy-hash-001",
        "event_type": "auth.bruteforce",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"failed_auths": 7, "src_ip": "203.0.113.11"},
    }

    resp = client.post(
        "/defend",
        headers={"Content-Type": "application/json", "X-API-Key": key},
        json=payload,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert re.fullmatch(r"[0-9a-f]{64}", body.get("policy_hash", ""))
    assert body["policy_hash"] == expected


def test_ingest_persists_policy_hash(build_app):
    expected = get_active_policy_fingerprint().policy_hash
    app = build_app()
    app.include_router(ingest_router)
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-a")

    payload = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_id": "evt-policy-hash-ingest-001",
        "event_type": "auth.bruteforce",
        "payload": {"failed_auths": 9, "src_ip": "203.0.113.12"},
    }

    resp = client.post(
        "/ingest",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key,
            "X-Tenant-Id": "tenant-a",
        },
        json=payload,
    )
    assert resp.status_code == 200, resp.text

    db_path = os.environ["FG_SQLITE_PATH"]
    engine = get_engine(sqlite_path=db_path)
    session = sessionmaker(bind=engine, expire_on_commit=False, future=True)()
    try:
        record = (
            session.query(DecisionRecord).order_by(DecisionRecord.id.desc()).first()
        )
        assert record is not None
        assert record.policy_hash is not None
        assert re.fullmatch(r"[0-9a-f]{64}", record.policy_hash)
        assert record.policy_hash == expected
    finally:
        session.close()
