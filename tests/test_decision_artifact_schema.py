from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from api.auth_scopes import mint_key
from api.ingest import router as ingest_router

DEFEND_SCHEMA_PATH = Path("contracts/artifacts/defend_decision.v1.json")
INGEST_SCHEMA_PATH = Path("contracts/artifacts/ingest_decision.v1.json")


def _load_schema(path: Path) -> dict:
    assert path.exists(), f"Missing decision schema at {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def _defend_payload(failed_auths: int = 12) -> dict:
    return {
        "event_type": "auth.bruteforce",
        "tenant_id": "test-tenant",
        "source": "unit-test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"src_ip": "1.2.3.4", "failed_auths": failed_auths},
    }


@pytest.fixture()
def defend_schema_validator() -> Draft202012Validator:
    schema = _load_schema(DEFEND_SCHEMA_PATH)
    return Draft202012Validator(schema)


@pytest.fixture()
def ingest_schema_validator() -> Draft202012Validator:
    schema = _load_schema(INGEST_SCHEMA_PATH)
    return Draft202012Validator(schema)


def test_schema_exists() -> None:
    assert DEFEND_SCHEMA_PATH.exists()
    assert INGEST_SCHEMA_PATH.exists()


def test_defend_response_matches_schema(
    defend_schema_validator: Draft202012Validator,
) -> None:
    # Schema validation should not require Redis.
    # Ensure rate limiting is disabled BEFORE importing api.main (app is built at import time).
    os.environ["FG_RL_ENABLED"] = "0"

    from api.main import app as main_app  # import after env is set

    client = TestClient(main_app)
    key = mint_key("defend:write", tenant_id="test-tenant")

    resp = client.post(
        "/defend",
        headers={
            "Content-Type": "application/json",
            "x-api-key": key,
            "x-pq-fallback": "1",
        },
        json=_defend_payload(12),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    defend_schema_validator.validate(body)


def test_ingest_decision_matches_schema(
    build_app, ingest_schema_validator: Draft202012Validator
) -> None:
    app = build_app()
    app.include_router(ingest_router)
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-a")

    payload = {
        "tenant_id": "tenant-a",
        "source": "unit-test",
        "event_id": "evt-artifact-schema-001",
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
    body = resp.json()
    ingest_schema_validator.validate(body["decision"])
