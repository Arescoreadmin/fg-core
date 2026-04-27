"""
tests/agent/test_agent_evidence_ingest.py

Tests for task 17.3 — Agent evidence ingestion path.

All tests in this file match pytest -k '(agent and evidence) or (ingest and tenant)'
because the file path contains "agent", "evidence", and "ingest".

Coverage:
- Adapter: CollectorEvent → ingest payload conversion
- Adapter: missing tenant_id fails explicitly
- Adapter: missing agent_id fails explicitly
- Adapter: payload tenant_id override is stripped (not passed through)
- Adapter: payload agent_id override is stripped
- Adapter: malformed payload fails explicitly
- Adapter: event_id is deterministic (same input → same id)
- Adapter: event_id matches /ingest required pattern
- Adapter: source field carries agent identity
- Adapter: collector identity embedded in payload
- Evidence queryable: tenant can query own decisions by event_type
- Tenant isolation: tenant A cannot query tenant B evidence
- Tenant isolation: empty result returned for wrong tenant (not error/leak)
- Decision record contains agent_id, event_type, tenant_id
- Existing read-path tenant isolation tests remain green (regression)

Integration tests use two patterns:
- Direct DB seeding (DecisionRecord) for isolation/query tests — avoids config dependency.
- Real POST /ingest via TestClient for E2E tests — requires seeding a config version first.
  Uses create_config_version() following the pattern in tests/test_config_hash_binding.py.

All tests are offline-safe and deterministic.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from agent.app.collector.base import CollectorEvent
from agent.app.collector.ingest_adapter import (
    AGENT_SOURCE_PREFIX,
    _FORBIDDEN_PAYLOAD_KEYS,
    _derive_event_id,
    collector_event_to_ingest_payload,
)
from api.auth_scopes import mint_key
from api.config_versioning import create_config_version
from api.db import get_engine
from api.db_models import DecisionRecord


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_FIXED_OCCURRED_AT = "2024-01-01T00:00:00+00:00"
_FIXED_PAYLOAD: dict[str, Any] = {
    "platform": "linux",
    "os_release": "5.15.0",
    "cpu_count": 4,
    "hostname_hash": "abcdef0123456789",
}


def _make_event(
    collector_name: str = "process_inventory",
    event_type: str = "inventory.process_snapshot",
    tenant_id: str = "tenant-a",
    agent_id: str = "agent-1",
    payload: dict[str, Any] | None = None,
    occurred_at: str = _FIXED_OCCURRED_AT,
) -> CollectorEvent:
    return CollectorEvent(
        collector_name=collector_name,
        event_type=event_type,
        tenant_id=tenant_id,
        agent_id=agent_id,
        occurred_at=occurred_at,
        payload=payload if payload is not None else dict(_FIXED_PAYLOAD),
    )


def _seed_agent_evidence(
    session: Session,
    *,
    tenant_id: str,
    event_id: str,
    agent_id: str = "agent-1",
    event_type: str = "inventory.process_snapshot",
) -> None:
    """Seed a DecisionRecord representing agent collector evidence."""
    session.add(
        DecisionRecord(
            tenant_id=tenant_id,
            source=f"{AGENT_SOURCE_PREFIX}:{agent_id}",
            event_id=event_id,
            event_type=event_type,
            threat_level="low",
            anomaly_score=0.0,
            ai_adversarial_score=0.0,
            pq_fallback=False,
            rules_triggered_json=[],
            decision_diff_json=None,
            request_json={
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {
                    "_collector": {"name": "process_inventory", "agent_id": agent_id}
                },
            },
            response_json={"decision": "allow"},
        )
    )


# ---------------------------------------------------------------------------
# Adapter — conversion correctness
# ---------------------------------------------------------------------------


def test_agent_evidence_adapter_produces_event_id() -> None:
    """Adapter produces a non-empty event_id in the output dict."""
    evt = _make_event()
    result = collector_event_to_ingest_payload(evt)
    assert "event_id" in result
    assert result["event_id"]


def test_agent_evidence_adapter_event_id_is_deterministic() -> None:
    """Same CollectorEvent produces identical event_id on every call."""
    evt = _make_event()
    id1 = collector_event_to_ingest_payload(evt)["event_id"]
    id2 = collector_event_to_ingest_payload(evt)["event_id"]
    assert id1 == id2


def test_agent_evidence_adapter_event_id_matches_ingest_pattern() -> None:
    """event_id matches POST /ingest required pattern ^[A-Za-z0-9._:-]+$."""
    import re

    evt = _make_event()
    event_id = collector_event_to_ingest_payload(evt)["event_id"]
    assert re.match(r"^[A-Za-z0-9._:-]+$", event_id), (
        f"event_id {event_id!r} does not match /ingest pattern"
    )
    assert len(event_id) <= 128


def test_agent_evidence_adapter_event_id_differs_for_different_occurrences() -> None:
    """Different occurred_at produces different event_id (idempotency boundary)."""
    evt1 = _make_event(occurred_at="2024-01-01T00:00:00+00:00")
    evt2 = _make_event(occurred_at="2024-01-01T00:01:00+00:00")
    assert (
        collector_event_to_ingest_payload(evt1)["event_id"]
        != collector_event_to_ingest_payload(evt2)["event_id"]
    )


def test_agent_evidence_adapter_tenant_id_from_event_not_payload() -> None:
    """tenant_id in output comes from CollectorEvent.tenant_id, not from payload."""
    evt = _make_event(tenant_id="correct-tenant")
    result = collector_event_to_ingest_payload(evt)
    assert result["tenant_id"] == "correct-tenant"


def test_agent_evidence_adapter_event_type_preserved() -> None:
    """event_type in output matches CollectorEvent.event_type."""
    evt = _make_event(event_type="inventory.process_snapshot")
    result = collector_event_to_ingest_payload(evt)
    assert result["event_type"] == "inventory.process_snapshot"


def test_agent_evidence_adapter_source_carries_agent_id() -> None:
    """source field in output encodes agent identity."""
    evt = _make_event(agent_id="agent-42")
    result = collector_event_to_ingest_payload(evt)
    assert "agent-42" in result["source"]
    assert result["source"].startswith(f"{AGENT_SOURCE_PREFIX}:")


def test_agent_evidence_adapter_timestamp_from_occurred_at() -> None:
    """timestamp in output matches CollectorEvent.occurred_at."""
    evt = _make_event(occurred_at=_FIXED_OCCURRED_AT)
    result = collector_event_to_ingest_payload(evt)
    assert result["timestamp"] == _FIXED_OCCURRED_AT


def test_agent_evidence_adapter_collector_identity_in_payload() -> None:
    """Adapter embeds _collector metadata in payload for operator visibility."""
    evt = _make_event(collector_name="process_inventory", agent_id="agent-7")
    result = collector_event_to_ingest_payload(evt)
    meta = result["payload"].get("_collector")
    assert meta is not None, "_collector metadata must be present"
    assert meta["name"] == "process_inventory"
    assert meta["agent_id"] == "agent-7"


# ---------------------------------------------------------------------------
# Adapter — tenant/agent safety: override prevention
# ---------------------------------------------------------------------------


def test_agent_evidence_adapter_payload_tenant_id_override_stripped() -> None:
    """payload containing tenant_id must not override the CollectorEvent.tenant_id."""
    payload_with_override = dict(_FIXED_PAYLOAD)
    payload_with_override["tenant_id"] = "attacker-tenant"
    evt = _make_event(tenant_id="real-tenant", payload=payload_with_override)
    result = collector_event_to_ingest_payload(evt)
    # Top-level tenant_id must be from CollectorEvent.
    assert result["tenant_id"] == "real-tenant"
    # payload must not contain the override key.
    assert "tenant_id" not in result["payload"]


def test_agent_evidence_adapter_payload_agent_id_override_stripped() -> None:
    """payload containing agent_id must not override the CollectorEvent.agent_id."""
    payload_with_override = dict(_FIXED_PAYLOAD)
    payload_with_override["agent_id"] = "attacker-agent"
    evt = _make_event(agent_id="real-agent", payload=payload_with_override)
    result = collector_event_to_ingest_payload(evt)
    assert "agent_id" not in result["payload"]
    # Source must still reflect the real agent_id.
    assert "real-agent" in result["source"]
    assert "attacker-agent" not in result["source"]


def test_agent_evidence_adapter_both_forbidden_keys_stripped() -> None:
    """Both tenant_id and agent_id in payload are stripped together."""
    payload_with_both = {
        "platform": "linux",
        "tenant_id": "injected-tenant",
        "agent_id": "injected-agent",
    }
    evt = _make_event(payload=payload_with_both)
    result = collector_event_to_ingest_payload(evt)
    for k in _FORBIDDEN_PAYLOAD_KEYS:
        assert k not in result["payload"], f"{k!r} must be stripped from payload"
    # Platform field is preserved.
    assert result["payload"]["platform"] == "linux"


# ---------------------------------------------------------------------------
# Adapter — validation failures
# ---------------------------------------------------------------------------


def test_agent_evidence_adapter_missing_tenant_id_raises() -> None:
    """CollectorEvent with empty tenant_id raises ValueError before conversion."""
    evt = CollectorEvent(
        collector_name="process_inventory",
        event_type="inventory.process_snapshot",
        tenant_id="",
        agent_id="agent-1",
        occurred_at=_FIXED_OCCURRED_AT,
        payload={},
    )
    with pytest.raises(ValueError, match="tenant_id"):
        collector_event_to_ingest_payload(evt)


def test_agent_evidence_adapter_missing_agent_id_raises() -> None:
    """CollectorEvent with empty agent_id raises ValueError before conversion."""
    evt = CollectorEvent(
        collector_name="process_inventory",
        event_type="inventory.process_snapshot",
        tenant_id="tenant-a",
        agent_id="",
        occurred_at=_FIXED_OCCURRED_AT,
        payload={},
    )
    with pytest.raises(ValueError, match="agent_id"):
        collector_event_to_ingest_payload(evt)


def test_agent_evidence_adapter_malformed_payload_raises() -> None:
    """CollectorEvent with non-dict payload raises ValueError before conversion."""
    evt = CollectorEvent(
        collector_name="process_inventory",
        event_type="inventory.process_snapshot",
        tenant_id="tenant-a",
        agent_id="agent-1",
        occurred_at=_FIXED_OCCURRED_AT,
        payload="not-a-dict",  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="payload"):
        collector_event_to_ingest_payload(evt)


def test_agent_evidence_adapter_whitespace_tenant_id_raises() -> None:
    """CollectorEvent with whitespace-only tenant_id raises ValueError."""
    evt = CollectorEvent(
        collector_name="process_inventory",
        event_type="inventory.process_snapshot",
        tenant_id="   ",
        agent_id="agent-1",
        occurred_at=_FIXED_OCCURRED_AT,
        payload={},
    )
    with pytest.raises(ValueError, match="tenant_id"):
        collector_event_to_ingest_payload(evt)


# ---------------------------------------------------------------------------
# _derive_event_id unit tests
# ---------------------------------------------------------------------------


def test_agent_evidence_derive_event_id_is_32_hex_chars() -> None:
    """_derive_event_id returns exactly 32 lowercase hex characters."""
    eid = _derive_event_id("process_inventory", "agent-1", _FIXED_OCCURRED_AT)
    assert len(eid) == 32
    assert all(c in "0123456789abcdef" for c in eid)


def test_agent_evidence_derive_event_id_deterministic() -> None:
    """Same inputs produce same event_id every call."""
    a = _derive_event_id("process_inventory", "agent-1", _FIXED_OCCURRED_AT)
    b = _derive_event_id("process_inventory", "agent-1", _FIXED_OCCURRED_AT)
    assert a == b


def test_agent_evidence_derive_event_id_differs_by_agent() -> None:
    """Different agent_ids produce different event_ids."""
    a = _derive_event_id("process_inventory", "agent-1", _FIXED_OCCURRED_AT)
    b = _derive_event_id("process_inventory", "agent-2", _FIXED_OCCURRED_AT)
    assert a != b


def test_agent_evidence_derive_event_id_differs_by_collector() -> None:
    """Different collector names produce different event_ids."""
    a = _derive_event_id("collector-a", "agent-1", _FIXED_OCCURRED_AT)
    b = _derive_event_id("collector-b", "agent-1", _FIXED_OCCURRED_AT)
    assert a != b


# ---------------------------------------------------------------------------
# Evidence queryable per tenant — integration tests via DB seed
# ---------------------------------------------------------------------------


def test_agent_evidence_ingest_tenant_can_query_own_evidence(build_app) -> None:
    """
    Tenant A can query its own agent evidence via GET /decisions.

    Seeds a DecisionRecord representing agent collector output for tenant-a,
    then confirms GET /decisions with tenant-a credentials returns it.
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"ev-tenant-a-{suffix}"
    agent_id = f"agent-{suffix}"
    event_id = _derive_event_id("process_inventory", agent_id, _FIXED_OCCURRED_AT)

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_a = mint_key("decisions:read", tenant_id=tenant_a)

    engine = get_engine()
    with Session(engine) as session:
        _seed_agent_evidence(
            session,
            tenant_id=tenant_a,
            event_id=event_id,
            agent_id=agent_id,
            event_type="inventory.process_snapshot",
        )
        session.commit()

    resp = client.get(
        "/decisions",
        params={"event_type": "inventory.process_snapshot"},
        headers={"X-API-Key": key_a, "X-Tenant-Id": tenant_a},
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    event_ids = [item["event_id"] for item in items]
    assert event_id in event_ids, "tenant-a must be able to query own agent evidence"
    # Confirm tenant isolation: all returned items belong to tenant-a.
    assert all(item["tenant_id"] == tenant_a for item in items)


def test_agent_evidence_ingest_tenant_isolation_cross_tenant_denied(build_app) -> None:
    """
    Tenant B cannot query Tenant A agent evidence.

    Seeds evidence for tenant-a, then confirms GET /decisions with tenant-b
    credentials does not return tenant-a's evidence.
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"ev-isol-a-{suffix}"
    tenant_b = f"ev-isol-b-{suffix}"
    agent_id = f"agent-{suffix}"
    event_id = _derive_event_id("process_inventory", agent_id, _FIXED_OCCURRED_AT)

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_b = mint_key("decisions:read", tenant_id=tenant_b)

    engine = get_engine()
    with Session(engine) as session:
        _seed_agent_evidence(
            session,
            tenant_id=tenant_a,
            event_id=event_id,
            agent_id=agent_id,
            event_type="inventory.process_snapshot",
        )
        session.commit()

    resp = client.get(
        "/decisions",
        params={"event_type": "inventory.process_snapshot"},
        headers={"X-API-Key": key_b, "X-Tenant-Id": tenant_b},
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    event_ids = [item["event_id"] for item in items]
    assert event_id not in event_ids, (
        "tenant-b must not be able to query tenant-a agent evidence"
    )


def test_agent_evidence_ingest_empty_result_for_wrong_tenant(build_app) -> None:
    """
    Wrong-tenant query returns empty result (not error, not other-tenant data).
    Anti-enumeration: existence of tenant-a evidence is not leaked.
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"ev-enum-a-{suffix}"
    tenant_b = f"ev-enum-b-{suffix}"
    agent_id = f"agent-{suffix}"
    event_id = _derive_event_id("process_inventory", agent_id, _FIXED_OCCURRED_AT)

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_b = mint_key("decisions:read", tenant_id=tenant_b)

    engine = get_engine()
    with Session(engine) as session:
        _seed_agent_evidence(
            session,
            tenant_id=tenant_a,
            event_id=event_id,
            agent_id=agent_id,
        )
        session.commit()

    resp = client.get(
        "/decisions",
        params={"event_type": "inventory.process_snapshot"},
        headers={"X-API-Key": key_b, "X-Tenant-Id": tenant_b},
    )
    assert resp.status_code == 200
    # Empty result — not 404, not error, not tenant-a's data.
    assert resp.json()["items"] == []


def test_agent_evidence_ingest_decision_contains_agent_metadata(build_app) -> None:
    """
    Queried agent evidence decision contains agent_id (via source), event_type,
    and tenant_id — sufficient metadata for operator usefulness.
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"ev-meta-a-{suffix}"
    agent_id = f"agent-meta-{suffix}"
    event_id = _derive_event_id("process_inventory", agent_id, _FIXED_OCCURRED_AT)

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_a = mint_key("decisions:read", tenant_id=tenant_a)

    engine = get_engine()
    with Session(engine) as session:
        _seed_agent_evidence(
            session,
            tenant_id=tenant_a,
            event_id=event_id,
            agent_id=agent_id,
            event_type="inventory.process_snapshot",
        )
        session.commit()

    resp = client.get(
        "/decisions",
        headers={"X-API-Key": key_a, "X-Tenant-Id": tenant_a},
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    target = next((i for i in items if i["event_id"] == event_id), None)
    assert target is not None, "seeded evidence must be queryable"
    assert target["tenant_id"] == tenant_a
    assert target["event_type"] == "inventory.process_snapshot"
    assert agent_id in target["source"], "source must carry agent_id"


def test_agent_evidence_ingest_tenant_a_b_fully_isolated(build_app) -> None:
    """
    Tenant A and B each have evidence; each sees only their own.
    Proves full bilateral isolation, not just one-direction leakage.
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"ev-bil-a-{suffix}"
    tenant_b = f"ev-bil-b-{suffix}"
    agent_id_a = f"agent-a-{suffix}"
    agent_id_b = f"agent-b-{suffix}"
    event_id_a = _derive_event_id("process_inventory", agent_id_a, _FIXED_OCCURRED_AT)
    event_id_b = _derive_event_id("process_inventory", agent_id_b, _FIXED_OCCURRED_AT)

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_a = mint_key("decisions:read", tenant_id=tenant_a)
    key_b = mint_key("decisions:read", tenant_id=tenant_b)

    engine = get_engine()
    with Session(engine) as session:
        _seed_agent_evidence(
            session, tenant_id=tenant_a, event_id=event_id_a, agent_id=agent_id_a
        )
        _seed_agent_evidence(
            session, tenant_id=tenant_b, event_id=event_id_b, agent_id=agent_id_b
        )
        session.commit()

    resp_a = client.get(
        "/decisions", headers={"X-API-Key": key_a, "X-Tenant-Id": tenant_a}
    )
    resp_b = client.get(
        "/decisions", headers={"X-API-Key": key_b, "X-Tenant-Id": tenant_b}
    )

    assert resp_a.status_code == 200
    assert resp_b.status_code == 200

    ids_a = {i["event_id"] for i in resp_a.json()["items"]}
    ids_b = {i["event_id"] for i in resp_b.json()["items"]}

    assert event_id_a in ids_a, "tenant-a must see own evidence"
    assert event_id_b not in ids_a, "tenant-a must not see tenant-b evidence"
    assert event_id_b in ids_b, "tenant-b must see own evidence"
    assert event_id_a not in ids_b, "tenant-b must not see tenant-a evidence"


def test_agent_evidence_ingest_unauthenticated_denied(build_app) -> None:
    """
    GET /decisions without auth returns 401/403 — operator surface requires auth.
    """
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    resp = client.get("/decisions")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# End-to-end: real ingest path (Addendum — REQUIRED CHANGE 2)
# ---------------------------------------------------------------------------


def test_agent_collector_event_reaches_ingest_and_is_queryable(build_app) -> None:
    """
    End-to-end: CollectorEvent → adapter → POST /ingest → GET /decisions.

    Proves the collector-derived payload flows through the REAL ingest handler,
    not a direct DB write.  Verifies:
    - event_id from adapter output is persisted and queryable
    - tenant_id is correct
    - event_type is preserved
    - agent_id identity is present in the source field
    - Cross-tenant GET returns empty result (no leak)
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_e2e = f"ev-e2e-{suffix}"
    tenant_other = f"ev-e2e-other-{suffix}"
    agent_id = f"agent-e2e-{suffix}"
    occurred_at = "2024-06-01T12:00:00+00:00"

    app = build_app(auth_enabled=True)
    client = TestClient(app)

    # Seed an active config version so /ingest can resolve it (required by route).
    engine = get_engine()
    with Session(engine) as db:
        create_config_version(
            db,
            tenant_id=tenant_e2e,
            config_payload={"mode": "test"},
            created_by="pytest",
            set_active=True,
        )
        db.commit()

    evt = _make_event(tenant_id=tenant_e2e, agent_id=agent_id, occurred_at=occurred_at)
    ingest_payload = collector_event_to_ingest_payload(evt)
    expected_event_id = ingest_payload["event_id"]

    ingest_key = mint_key("ingest:write", tenant_id=tenant_e2e)
    resp_ingest = client.post(
        "/ingest",
        json=ingest_payload,
        headers={"X-API-Key": ingest_key, "X-Tenant-Id": tenant_e2e},
    )
    assert resp_ingest.status_code == 200, resp_ingest.text

    read_key = mint_key("decisions:read", tenant_id=tenant_e2e)
    resp_read = client.get(
        "/decisions",
        params={"event_type": "inventory.process_snapshot"},
        headers={"X-API-Key": read_key, "X-Tenant-Id": tenant_e2e},
    )
    assert resp_read.status_code == 200
    items = resp_read.json()["items"]
    event_ids = [item["event_id"] for item in items]
    assert expected_event_id in event_ids, "adapter-derived event_id must be queryable"

    target = next(i for i in items if i["event_id"] == expected_event_id)
    assert target["tenant_id"] == tenant_e2e
    assert target["event_type"] == "inventory.process_snapshot"
    assert agent_id in target["source"], "source must carry agent_id"

    # Cross-tenant isolation: other tenant must not see this event.
    other_key = mint_key("decisions:read", tenant_id=tenant_other)
    resp_other = client.get(
        "/decisions",
        params={"event_type": "inventory.process_snapshot"},
        headers={"X-API-Key": other_key, "X-Tenant-Id": tenant_other},
    )
    assert resp_other.status_code == 200
    other_ids = [i["event_id"] for i in resp_other.json()["items"]]
    assert expected_event_id not in other_ids, "cross-tenant must not see this event"


# ---------------------------------------------------------------------------
# Negative: malformed payload through ingest path (Addendum — REQUIRED CHANGE 3)
# ---------------------------------------------------------------------------


def test_agent_collector_event_ingest_missing_event_id_returns_400(build_app) -> None:
    """
    Malformed ingest payload (event_id removed) → POST /ingest returns 400.

    Verifies the real ingest route rejects malformed adapter output explicitly
    (not silently accepting or crashing). Simulates a hypothetical adapter bug
    where the required event_id field is absent.
    """
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ingest:write", tenant_id="tenant-neg")

    # Start with valid adapter output, then strip event_id to simulate bad output.
    evt = _make_event(tenant_id="tenant-neg", agent_id="agent-neg")
    bad_payload = collector_event_to_ingest_payload(evt)
    del bad_payload["event_id"]

    resp = client.post(
        "/ingest",
        json=bad_payload,
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-neg"},
    )
    assert resp.status_code == 400, (
        f"missing event_id must return 400, got {resp.status_code}: {resp.text}"
    )
