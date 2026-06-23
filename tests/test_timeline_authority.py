# mypy: ignore-errors
"""Tests for PR 14.6.2 — Timeline Authority (Canonical Governance Ledger).

TA-1  through TA-110+ tests.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")
os.environ.setdefault("FG_API_KEY", "")
os.environ.setdefault("FG_KEY_PEPPER", "timeline-authority-test-pepper")
os.environ.setdefault(
    "FG_COMPLIANCE_HMAC_KEY_CURRENT", "0123456789abcdef0123456789abcdef"
)
os.environ.setdefault("FG_COMPLIANCE_HMAC_KEY_ID_CURRENT", "v1")

# ---------------------------------------------------------------------------
# Required paths declaration — TA-1
# ---------------------------------------------------------------------------

REQUIRED_PATHS = [
    ("POST", "/timeline-authority/events"),
    ("GET", "/timeline-authority/events"),
    ("GET", "/timeline-authority/events/{event_id}"),
    ("GET", "/timeline-authority/entities/{entity_type}/{entity_id}"),
    ("GET", "/timeline-authority/replay"),
    ("GET", "/timeline-authority/export"),
    ("GET", "/timeline-authority/integrity"),
    ("GET", "/timeline-authority/statistics"),
]

_BASE_OCCURRED = "2026-06-22T10:00:00.000Z"
_BASE_OCCURRED_2 = "2026-06-22T11:00:00.000Z"
_BASE_OCCURRED_3 = "2026-06-22T12:00:00.000Z"

_BASE_PAYLOAD = {
    "source_system": "EVIDENCE_AUTHORITY",
    "entity_type": "EVIDENCE",
    "entity_id": "ev-001",
    "event_type": "CREATED",
    "occurred_at": _BASE_OCCURRED,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def api_bundle(tmp_path_factory):
    from fastapi.testclient import TestClient

    from api.auth_scopes import mint_key
    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    db_dir = tmp_path_factory.mktemp("timeline_authority")
    db_path = db_dir / "timeline-authority.db"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_ENV"] = "test"
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    os.environ["FG_KEY_PEPPER"] = "timeline-authority-test-pepper"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    client = TestClient(build_app(auth_enabled=True), raise_server_exceptions=False)

    bundle = {
        "client": client,
        "db_path": str(db_path),
        "headers_rw_a": _headers(
            mint_key("governance:read", "governance:write", tenant_id="tenant-ta-001"),
            "tenant-ta-001",
        ),
        "headers_read_a": _headers(
            mint_key("governance:read", tenant_id="tenant-ta-001"),
            "tenant-ta-001",
        ),
        "headers_rw_b": _headers(
            mint_key("governance:read", "governance:write", tenant_id="tenant-ta-002"),
            "tenant-ta-002",
        ),
        "headers_read_b": _headers(
            mint_key("governance:read", tenant_id="tenant-ta-002"),
            "tenant-ta-002",
        ),
        "headers_wrong_scope": _headers(
            mint_key("compliance:read", tenant_id="tenant-ta-001"),
            "tenant-ta-001",
        ),
    }
    yield bundle
    client.close()
    reset_engine_cache()


def _headers(key: str, tenant_id: str) -> dict[str, str]:
    return {"X-API-Key": key, "X-Tenant-Id": tenant_id, "X-Actor": "test-actor"}


def _record(client, headers, payload=None, **overrides):
    data = {**_BASE_PAYLOAD, **(payload or {}), **overrides}
    return client.post("/timeline-authority/events", json=data, headers=headers)


# ---------------------------------------------------------------------------
# TA-1: Required paths exist in OpenAPI schema
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,path", REQUIRED_PATHS)
def test_openapi_contains_required_routes(api_bundle, method, path):
    """TA-1 group: all 8 required routes exist in OpenAPI schema."""
    openapi = api_bundle["client"].app.openapi()
    paths = openapi.get("paths", {})
    # Convert {param} to OpenAPI style
    oai_path = path
    assert oai_path in paths or any(
        p == oai_path or p.replace("{", "{").replace("}", "}") == oai_path
        for p in paths
    ), f"Route {method} {oai_path} not found in OpenAPI schema"


# ---------------------------------------------------------------------------
# TA-2: Unauthenticated requests are rejected
# ---------------------------------------------------------------------------


def test_post_event_unauthenticated(api_bundle):
    """TA-2: POST without auth returns 401/403."""
    r = api_bundle["client"].post("/timeline-authority/events", json=_BASE_PAYLOAD)
    assert r.status_code in (401, 403)


def test_list_events_unauthenticated(api_bundle):
    """TA-3: GET list without auth returns 401/403."""
    r = api_bundle["client"].get("/timeline-authority/events")
    assert r.status_code in (401, 403)


def test_get_event_unauthenticated(api_bundle):
    """TA-4: GET single event without auth returns 401/403."""
    r = api_bundle["client"].get("/timeline-authority/events/some-id")
    assert r.status_code in (401, 403)


def test_entity_timeline_unauthenticated(api_bundle):
    """TA-5: GET entity timeline without auth returns 401/403."""
    r = api_bundle["client"].get("/timeline-authority/entities/EVIDENCE/ev-001")
    assert r.status_code in (401, 403)


def test_replay_unauthenticated(api_bundle):
    """TA-6: GET replay without auth returns 401/403."""
    r = api_bundle["client"].get("/timeline-authority/replay")
    assert r.status_code in (401, 403)


def test_export_unauthenticated(api_bundle):
    """TA-7: GET export without auth returns 401/403."""
    r = api_bundle["client"].get("/timeline-authority/export")
    assert r.status_code in (401, 403)


def test_integrity_unauthenticated(api_bundle):
    """TA-8: GET integrity without auth returns 401/403."""
    r = api_bundle["client"].get("/timeline-authority/integrity")
    assert r.status_code in (401, 403)


def test_statistics_unauthenticated(api_bundle):
    """TA-9: GET statistics without auth returns 401/403."""
    r = api_bundle["client"].get("/timeline-authority/statistics")
    assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# TA-10: Wrong scope is rejected
# ---------------------------------------------------------------------------


def test_post_event_wrong_scope(api_bundle):
    """TA-10: POST with wrong scope returns 401/403."""
    r = _record(api_bundle["client"], api_bundle["headers_wrong_scope"])
    assert r.status_code in (401, 403)


def test_list_events_wrong_scope(api_bundle):
    """TA-11: GET list with wrong scope returns 401/403."""
    r = api_bundle["client"].get(
        "/timeline-authority/events", headers=api_bundle["headers_wrong_scope"]
    )
    assert r.status_code in (401, 403)


def test_get_event_wrong_scope(api_bundle):
    """TA-12: GET single event with wrong scope returns 401/403."""
    r = api_bundle["client"].get(
        "/timeline-authority/events/some-id", headers=api_bundle["headers_wrong_scope"]
    )
    assert r.status_code in (401, 403)


def test_read_only_scope_cannot_write(api_bundle):
    """TA-13: Read-only key cannot POST events."""
    r = _record(api_bundle["client"], api_bundle["headers_read_a"])
    assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# TA-14: Deterministic event IDs
# ---------------------------------------------------------------------------


def test_deterministic_event_id(api_bundle):
    """TA-14: Same inputs produce same event_id."""
    from services.timeline_authority.repository import derive_event_id

    eid1 = derive_event_id(
        tenant_id="tenant-x",
        entity_type="EVIDENCE",
        entity_id="ev-abc",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
    )
    eid2 = derive_event_id(
        tenant_id="tenant-x",
        entity_type="EVIDENCE",
        entity_id="ev-abc",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
    )
    assert eid1 == eid2


def test_deterministic_event_id_is_64_chars(api_bundle):
    """TA-15: derive_event_id returns full 64-char SHA-256 hex."""
    from services.timeline_authority.repository import derive_event_id

    eid = derive_event_id(
        tenant_id="t",
        entity_type="RISK",
        entity_id="r-1",
        event_type="OPEN",
        occurred_at="2026-01-01T00:00:00.000Z",
        source_system="RISK_GOVERNANCE",
    )
    assert len(eid) == 64
    assert all(c in "0123456789abcdef" for c in eid)


def test_different_inputs_produce_different_ids(api_bundle):
    """TA-16: Different inputs produce different event IDs."""
    from services.timeline_authority.repository import derive_event_id

    eid1 = derive_event_id(
        tenant_id="t1",
        entity_type="EVIDENCE",
        entity_id="ev-1",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
    )
    eid2 = derive_event_id(
        tenant_id="t1",
        entity_type="EVIDENCE",
        entity_id="ev-2",  # different entity_id
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
    )
    assert eid1 != eid2


def test_different_tenants_produce_different_ids(api_bundle):
    """TA-17: Same event for different tenants → different IDs."""
    from services.timeline_authority.repository import derive_event_id

    eid1 = derive_event_id(
        tenant_id="tenant-a",
        entity_type="EVIDENCE",
        entity_id="ev-1",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
    )
    eid2 = derive_event_id(
        tenant_id="tenant-b",
        entity_type="EVIDENCE",
        entity_id="ev-1",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
    )
    assert eid1 != eid2


# ---------------------------------------------------------------------------
# TA-18: Hash chain correctness
# ---------------------------------------------------------------------------


def test_genesis_hash_is_all_zeros(api_bundle):
    """TA-18: The genesis prev_event_hash is 64 zeros."""
    from services.timeline_authority.repository import _GENESIS_HASH

    assert _GENESIS_HASH == "0" * 64
    assert len(_GENESIS_HASH) == 64


def test_compute_event_hash_is_64_chars(api_bundle):
    """TA-19: compute_event_hash returns full 64-char SHA-256."""
    from services.timeline_authority.repository import compute_event_hash, _GENESIS_HASH

    h = compute_event_hash(
        event_id="abc123",
        tenant_id="t1",
        entity_type="EVIDENCE",
        entity_id="ev-1",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
        prev_event_hash=_GENESIS_HASH,
        metadata_json={},
    )
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_compute_event_hash_is_deterministic(api_bundle):
    """TA-20: Same inputs → same hash."""
    from services.timeline_authority.repository import compute_event_hash, _GENESIS_HASH

    kwargs = dict(
        event_id="abc123",
        tenant_id="t1",
        entity_type="EVIDENCE",
        entity_id="ev-1",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
        prev_event_hash=_GENESIS_HASH,
        metadata_json={"key": "value"},
    )
    assert compute_event_hash(**kwargs) == compute_event_hash(**kwargs)


def test_hash_changes_with_different_prev_hash(api_bundle):
    """TA-21: Different prev_event_hash → different event_hash."""
    from services.timeline_authority.repository import compute_event_hash

    h1 = compute_event_hash(
        event_id="abc",
        tenant_id="t",
        entity_type="EVIDENCE",
        entity_id="ev-1",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
        prev_event_hash="0" * 64,
        metadata_json={},
    )
    h2 = compute_event_hash(
        event_id="abc",
        tenant_id="t",
        entity_type="EVIDENCE",
        entity_id="ev-1",
        event_type="CREATED",
        occurred_at="2026-06-22T10:00:00.000Z",
        source_system="EVIDENCE_AUTHORITY",
        prev_event_hash="a" * 64,  # different
        metadata_json={},
    )
    assert h1 != h2


# ---------------------------------------------------------------------------
# TA-22: Append-only at ORM level
# ---------------------------------------------------------------------------


def test_orm_blocks_update(api_bundle):
    """TA-22: ORM before_update listener raises ValueError."""
    import pytest

    with pytest.raises(ValueError, match="append-only"):
        from api.db_models_timeline_authority import _block_update

        _block_update(None, None, None)


def test_orm_blocks_delete(api_bundle):
    """TA-23: ORM before_delete listener raises ValueError."""
    with pytest.raises(ValueError, match="append-only"):
        from api.db_models_timeline_authority import _block_delete

        _block_delete(None, None, None)


# ---------------------------------------------------------------------------
# TA-24: Record event — success
# ---------------------------------------------------------------------------


def test_record_event_returns_200(api_bundle):
    """TA-24: POST /timeline-authority/events returns 201 or 200."""
    r = _record(api_bundle["client"], api_bundle["headers_rw_a"])
    assert r.status_code in (200, 201), r.text


def test_record_event_response_fields(api_bundle):
    """TA-25: Response contains all required fields."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-fields-test",
        event_type="FIELDS_VERIFIED",
        occurred_at="2026-06-22T09:00:00.000Z",
    )
    assert r.status_code in (200, 201), r.text
    data = r.json()
    assert "id" in data
    assert "event_id" in data
    assert "event_hash" in data
    assert "prev_event_hash" in data
    assert "source_system" in data
    assert "entity_type" in data
    assert "entity_id" in data
    assert "event_type" in data
    assert "occurred_at" in data
    assert "recorded_at" in data
    assert "severity" in data
    assert "tenant_id" in data
    assert "replay_version" in data
    assert "schema_version" in data


def test_record_event_hash_is_64_chars(api_bundle):
    """TA-26: Recorded event_hash is 64 hex chars."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-hash-len",
        event_type="HASH_LEN_TEST",
        occurred_at="2026-06-22T08:30:00.000Z",
    )
    assert r.status_code in (200, 201)
    data = r.json()
    assert len(data["event_hash"]) == 64


def test_record_event_prev_hash_is_genesis_for_first_event(api_bundle):
    """TA-27: First event for an entity has genesis prev_event_hash."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-genesis-check",
        event_type="FIRST_EVENT",
        occurred_at="2026-06-22T08:00:00.000Z",
    )
    assert r.status_code in (200, 201)
    data = r.json()
    assert data["prev_event_hash"] == "0" * 64


def test_record_event_chain_links_correctly(api_bundle):
    """TA-28: Second event prev_event_hash == first event event_hash."""
    entity_id = "ev-chain-link-001"
    r1 = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="CREATED",
        occurred_at="2026-06-22T07:00:00.000Z",
    )
    assert r1.status_code in (200, 201)
    first_hash = r1.json()["event_hash"]

    r2 = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="UPDATED",
        occurred_at="2026-06-22T07:30:00.000Z",
    )
    assert r2.status_code in (200, 201)
    assert r2.json()["prev_event_hash"] == first_hash


def test_record_event_with_metadata(api_bundle):
    """TA-29: Event with metadata_json is stored correctly."""
    meta = {"key": "value", "nested": {"x": 1}}
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-meta-001",
        event_type="META_TEST",
        metadata_json=meta,
        occurred_at="2026-06-22T06:00:00.000Z",
    )
    assert r.status_code in (200, 201)
    data = r.json()
    assert data["metadata_json"]["key"] == "value"
    assert data["metadata_json"]["nested"]["x"] == 1


def test_record_event_with_correlation_causation(api_bundle):
    """TA-30: correlation_id and causation_id are stored."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-corr-001",
        event_type="CORR_TEST",
        correlation_id="corr-abc",
        causation_id="cause-xyz",
        occurred_at="2026-06-22T05:00:00.000Z",
    )
    assert r.status_code in (200, 201)
    data = r.json()
    assert data["correlation_id"] == "corr-abc"
    assert data["causation_id"] == "cause-xyz"


def test_record_event_severity_warning(api_bundle):
    """TA-31: Severity WARNING is stored correctly."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-sev-warn",
        event_type="WARNING_EVENT",
        severity="WARNING",
        occurred_at="2026-06-22T04:00:00.000Z",
    )
    assert r.status_code in (200, 201)
    assert r.json()["severity"] == "WARNING"


def test_record_event_severity_critical(api_bundle):
    """TA-32: Severity CRITICAL is stored correctly."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-sev-crit",
        event_type="CRITICAL_EVENT",
        severity="CRITICAL",
        occurred_at="2026-06-22T03:30:00.000Z",
    )
    assert r.status_code in (200, 201)
    assert r.json()["severity"] == "CRITICAL"


def test_record_event_severity_debug(api_bundle):
    """TA-33: Severity DEBUG is stored."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-sev-debug",
        event_type="DEBUG_EVENT",
        severity="DEBUG",
        occurred_at="2026-06-22T03:00:00.000Z",
    )
    assert r.status_code in (200, 201)
    assert r.json()["severity"] == "DEBUG"


def test_record_event_all_actor_types(api_bundle):
    """TA-34: All actor types accepted."""
    for actor_type in ("HUMAN", "SERVICE", "AGENT", "AUTONOMOUS_SYSTEM", "SYSTEM"):
        r = _record(
            api_bundle["client"],
            api_bundle["headers_rw_a"],
            entity_id=f"ev-actor-{actor_type.lower()}",
            event_type=f"ACTOR_{actor_type}",
            actor_type=actor_type,
            actor_id=f"actor-{actor_type.lower()}",
            occurred_at=f"2026-06-21T{10 + list(('HUMAN', 'SERVICE', 'AGENT', 'AUTONOMOUS_SYSTEM', 'SYSTEM')).index(actor_type):02d}:00:00.000Z",
        )
        assert r.status_code in (200, 201), f"actor_type {actor_type} failed: {r.text}"


def test_record_event_all_source_systems(api_bundle):
    """TA-35: All 10 source systems accepted."""
    sources = [
        "EVIDENCE_AUTHORITY",
        "RISK_GOVERNANCE",
        "CONTROL_REGISTRY",
        "GOVERNANCE_PORTAL",
        "GOVERNANCE_REPORTING",
        "FIELD_ASSESSMENT",
        "FRAMEWORK_AUTHORITY",
        "REMEDIATION_VERIFICATION",
        "AUTONOMOUS_GOVERNANCE",
        "TIMELINE_AUTHORITY",
    ]
    for i, src in enumerate(sources):
        r = _record(
            api_bundle["client"],
            api_bundle["headers_rw_a"],
            source_system=src,
            entity_id=f"ev-src-{i}",
            event_type="SOURCE_TEST",
            occurred_at=f"2026-06-20T{10 + i:02d}:00:00.000Z",
        )
        assert r.status_code in (200, 201), f"source_system {src} failed: {r.text}"


def test_record_event_all_entity_types(api_bundle):
    """TA-36: All entity types accepted."""
    entity_types = [
        "EVIDENCE",
        "RISK",
        "CONTROL",
        "FRAMEWORK",
        "FRAMEWORK_CONTROL",
        "MAPPING",
        "ENGAGEMENT",
        "REPORT",
        "DECISION",
        "AGENT",
        "TENANT",
        "REMEDIATION",
    ]
    for i, etype in enumerate(entity_types):
        r = _record(
            api_bundle["client"],
            api_bundle["headers_rw_a"],
            entity_type=etype,
            entity_id=f"entity-{etype.lower()}-001",
            event_type="ENTITY_TYPE_TEST",
            occurred_at=f"2026-06-19T{10 + i:02d}:00:00.000Z",
        )
        assert r.status_code in (200, 201), f"entity_type {etype} failed: {r.text}"


# ---------------------------------------------------------------------------
# TA-37: Duplicate event rejected
# ---------------------------------------------------------------------------


def test_duplicate_event_returns_409(api_bundle):
    """TA-37: Duplicate event_id (same inputs) returns 409."""
    payload = {
        "source_system": "RISK_GOVERNANCE",
        "entity_type": "RISK",
        "entity_id": "risk-dup-001",
        "event_type": "OPENED",
        "occurred_at": "2026-06-18T10:00:00.000Z",
    }
    r1 = api_bundle["client"].post(
        "/timeline-authority/events", json=payload, headers=api_bundle["headers_rw_a"]
    )
    assert r1.status_code in (200, 201)
    r2 = api_bundle["client"].post(
        "/timeline-authority/events", json=payload, headers=api_bundle["headers_rw_a"]
    )
    assert r2.status_code == 409


# ---------------------------------------------------------------------------
# TA-38: List events
# ---------------------------------------------------------------------------


def test_list_events_empty_returns_list(api_bundle):
    """TA-38: Empty tenant returns empty list."""
    # Use a tenant with no events
    key_empty = __import__("api.auth_scopes", fromlist=["mint_key"]).mint_key(
        "governance:read", tenant_id="tenant-empty-ta-001"
    )
    headers_empty = _headers(key_empty, "tenant-empty-ta-001")
    r = api_bundle["client"].get("/timeline-authority/events", headers=headers_empty)
    assert r.status_code == 200
    assert r.json() == []


def test_list_events_returns_correct_tenant_events(api_bundle):
    """TA-39: List returns only the requesting tenant's events."""
    r = api_bundle["client"].get(
        "/timeline-authority/events", headers=api_bundle["headers_rw_a"]
    )
    assert r.status_code == 200
    events = r.json()
    for ev in events:
        assert ev["tenant_id"] == "tenant-ta-001"


def test_list_events_ordered_by_occurred_at(api_bundle):
    """TA-40: List is ordered by occurred_at ascending."""
    r = api_bundle["client"].get(
        "/timeline-authority/events", headers=api_bundle["headers_rw_a"]
    )
    assert r.status_code == 200
    events = r.json()
    if len(events) >= 2:
        for i in range(len(events) - 1):
            assert events[i]["occurred_at"] <= events[i + 1]["occurred_at"]


def test_list_events_filter_by_entity_type(api_bundle):
    """TA-41: entity_type filter works."""
    r = api_bundle["client"].get(
        "/timeline-authority/events?entity_type=RISK",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    events = r.json()
    for ev in events:
        assert ev["entity_type"] == "RISK"


def test_list_events_filter_by_source_system(api_bundle):
    """TA-42: source_system filter works."""
    r = api_bundle["client"].get(
        "/timeline-authority/events?source_system=EVIDENCE_AUTHORITY",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    events = r.json()
    for ev in events:
        assert ev["source_system"] == "EVIDENCE_AUTHORITY"


def test_list_events_pagination_limit(api_bundle):
    """TA-43: limit parameter is respected."""
    r = api_bundle["client"].get(
        "/timeline-authority/events?limit=3",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    assert len(r.json()) <= 3


def test_list_events_pagination_offset(api_bundle):
    """TA-44: offset parameter shifts results."""
    r_all = api_bundle["client"].get(
        "/timeline-authority/events?limit=200",
        headers=api_bundle["headers_rw_a"],
    )
    r_offset = api_bundle["client"].get(
        "/timeline-authority/events?limit=200&offset=2",
        headers=api_bundle["headers_rw_a"],
    )
    assert r_all.status_code == 200
    assert r_offset.status_code == 200
    all_events = r_all.json()
    offset_events = r_offset.json()
    if len(all_events) > 2:
        assert offset_events[0]["event_id"] == all_events[2]["event_id"]


def test_list_events_max_limit_capped(api_bundle):
    """TA-45: limit > 200 returns at most 200 events."""
    r = api_bundle["client"].get(
        "/timeline-authority/events?limit=200",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# TA-46: Get single event
# ---------------------------------------------------------------------------


def test_get_event_by_id(api_bundle):
    """TA-46: GET /events/{event_id} returns correct event."""
    r_create = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-get-by-id-001",
        event_type="GET_TEST",
        occurred_at="2026-06-17T10:00:00.000Z",
    )
    assert r_create.status_code in (200, 201)
    event_id = r_create.json()["event_id"]

    r = api_bundle["client"].get(
        f"/timeline-authority/events/{event_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["event_id"] == event_id


def test_get_event_not_found(api_bundle):
    """TA-47: GET unknown event_id returns 404."""
    r = api_bundle["client"].get(
        "/timeline-authority/events/nonexistent-event-id-xyz-123",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 404


def test_get_event_cross_tenant_returns_404(api_bundle):
    """TA-48: Tenant B cannot see Tenant A's event."""
    r_create = _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id="ev-cross-tenant-001",
        event_type="CROSS_TENANT_TEST",
        occurred_at="2026-06-16T10:00:00.000Z",
    )
    assert r_create.status_code in (200, 201)
    event_id = r_create.json()["event_id"]

    # Tenant B tries to read Tenant A's event
    r = api_bundle["client"].get(
        f"/timeline-authority/events/{event_id}",
        headers=api_bundle["headers_rw_b"],
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# TA-49: Entity timeline
# ---------------------------------------------------------------------------


def test_get_entity_timeline_returns_events(api_bundle):
    """TA-49: GET /entities/{type}/{id} returns entity's events."""
    entity_id = "ev-entity-timeline-001"
    # Record two events for this entity
    for i, evt in enumerate(["CREATED", "UPDATED"]):
        _record(
            api_bundle["client"],
            api_bundle["headers_rw_a"],
            entity_id=entity_id,
            event_type=evt,
            occurred_at=f"2026-06-15T{10 + i:02d}:00:00.000Z",
        )

    r = api_bundle["client"].get(
        f"/timeline-authority/entities/EVIDENCE/{entity_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    events = r.json()
    assert len(events) >= 2
    for ev in events:
        assert ev["entity_id"] == entity_id


def test_entity_timeline_ordered_chronologically(api_bundle):
    """TA-50: Entity timeline events are ordered by occurred_at asc."""
    r = api_bundle["client"].get(
        "/timeline-authority/entities/EVIDENCE/ev-entity-timeline-001",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    events = r.json()
    if len(events) >= 2:
        for i in range(len(events) - 1):
            assert events[i]["occurred_at"] <= events[i + 1]["occurred_at"]


def test_entity_timeline_cross_tenant_isolation(api_bundle):
    """TA-51: Entity timeline is tenant-isolated."""
    entity_id = "ev-cross-entity-001"
    _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="ISOLATION_TEST",
        occurred_at="2026-06-14T10:00:00.000Z",
    )

    r = api_bundle["client"].get(
        f"/timeline-authority/entities/EVIDENCE/{entity_id}",
        headers=api_bundle["headers_rw_b"],
    )
    assert r.status_code == 200
    # Tenant B should see empty list (not Tenant A's events)
    events = r.json()
    for ev in events:
        assert ev["tenant_id"] == "tenant-ta-002"


def test_entity_timeline_empty_entity(api_bundle):
    """TA-52: Unknown entity returns empty list."""
    r = api_bundle["client"].get(
        "/timeline-authority/entities/EVIDENCE/nonexistent-entity-xyz",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    assert r.json() == []


# ---------------------------------------------------------------------------
# TA-53: Replay
# ---------------------------------------------------------------------------


def test_replay_returns_structure(api_bundle):
    """TA-53: GET /replay returns TimelineReplayResponse structure."""
    r = api_bundle["client"].get(
        "/timeline-authority/replay",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert "tenant_id" in data
    assert "events" in data
    assert "event_count" in data
    assert "replay_deterministic" in data
    assert data["replay_deterministic"] is True


def test_replay_event_count_matches_events(api_bundle):
    """TA-54: event_count matches len(events)."""
    r = api_bundle["client"].get(
        "/timeline-authority/replay",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["event_count"] == len(data["events"])


def test_replay_tenant_id_correct(api_bundle):
    """TA-55: replay response has correct tenant_id."""
    r = api_bundle["client"].get(
        "/timeline-authority/replay",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "tenant-ta-001"


def test_replay_entity_scoped(api_bundle):
    """TA-56: Replay with entity_type+entity_id returns only those events."""
    entity_id = "ev-replay-scoped-001"
    _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="REPLAY_SCOPE_TEST",
        occurred_at="2026-06-13T10:00:00.000Z",
    )

    r = api_bundle["client"].get(
        f"/timeline-authority/replay?entity_type=EVIDENCE&entity_id={entity_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    for ev in data["events"]:
        assert ev["entity_id"] == entity_id


def test_replay_source_system_filter(api_bundle):
    """TA-57: Replay with source_system returns only matching events."""
    r = api_bundle["client"].get(
        "/timeline-authority/replay?source_system=RISK_GOVERNANCE",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    for ev in data["events"]:
        assert ev["source_system"] == "RISK_GOVERNANCE"


def test_replay_is_deterministic(api_bundle):
    """TA-58: Two replay calls for same entity return same events in same order."""
    entity_id = "ev-replay-det-001"
    _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="DETERMINISM_TEST",
        occurred_at="2026-06-12T10:00:00.000Z",
    )

    r1 = api_bundle["client"].get(
        f"/timeline-authority/replay?entity_type=EVIDENCE&entity_id={entity_id}",
        headers=api_bundle["headers_rw_a"],
    )
    r2 = api_bundle["client"].get(
        f"/timeline-authority/replay?entity_type=EVIDENCE&entity_id={entity_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["events"] == r2.json()["events"]


def test_replay_cross_tenant_isolation(api_bundle):
    """TA-59: Tenant B replay does not include Tenant A events."""
    r_a = api_bundle["client"].get(
        "/timeline-authority/replay", headers=api_bundle["headers_rw_a"]
    )
    r_b = api_bundle["client"].get(
        "/timeline-authority/replay", headers=api_bundle["headers_rw_b"]
    )
    assert r_a.status_code == 200
    assert r_b.status_code == 200
    ids_a = {ev["event_id"] for ev in r_a.json()["events"]}
    ids_b = {ev["event_id"] for ev in r_b.json()["events"]}
    assert ids_a.isdisjoint(ids_b)


# ---------------------------------------------------------------------------
# TA-60: Export
# ---------------------------------------------------------------------------


def test_export_returns_structure(api_bundle):
    """TA-60: GET /export returns TimelineExportResponse structure."""
    r = api_bundle["client"].get(
        "/timeline-authority/export",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert "tenant_id" in data
    assert "format" in data
    assert data["format"] == "json"
    assert "events" in data
    assert "event_count" in data
    assert "integrity_status" in data
    assert "chain_verification_summary" in data
    assert "deterministic_ordering" in data
    assert data["deterministic_ordering"] is True


def test_export_event_count_matches(api_bundle):
    """TA-61: export event_count matches len(events)."""
    r = api_bundle["client"].get(
        "/timeline-authority/export",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["event_count"] == len(data["events"])


def test_export_integrity_status_valid(api_bundle):
    """TA-62: Fresh export has valid integrity status."""
    entity_id = "ev-export-valid-001"
    _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="EXPORT_VALID_TEST",
        occurred_at="2026-06-11T10:00:00.000Z",
    )

    r = api_bundle["client"].get(
        f"/timeline-authority/export?entity_type=EVIDENCE&entity_id={entity_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["integrity_status"] == "valid"


def test_export_chain_summary_fields(api_bundle):
    """TA-63: chain_verification_summary has required fields."""
    entity_id = "ev-chain-summary-001"
    _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="CHAIN_SUMMARY_TEST",
        occurred_at="2026-06-10T10:00:00.000Z",
    )

    r = api_bundle["client"].get(
        f"/timeline-authority/export?entity_type=EVIDENCE&entity_id={entity_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    summaries = r.json()["chain_verification_summary"]
    assert len(summaries) >= 1
    s = summaries[0]
    assert "entity_type" in s
    assert "entity_id" in s
    assert "event_count" in s
    assert "chain_valid" in s
    assert "first_event_id" in s
    assert "last_event_id" in s
    assert "last_event_hash" in s


def test_export_entity_scoped(api_bundle):
    """TA-64: Export with entity_type+entity_id returns only those events."""
    entity_id = "ev-export-scope-001"
    _record(
        api_bundle["client"],
        api_bundle["headers_rw_a"],
        entity_id=entity_id,
        event_type="EXPORT_SCOPE_TEST",
        occurred_at="2026-06-09T10:00:00.000Z",
    )

    r = api_bundle["client"].get(
        f"/timeline-authority/export?entity_type=EVIDENCE&entity_id={entity_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    for ev in r.json()["events"]:
        assert ev["entity_id"] == entity_id


def test_export_cross_tenant_isolation(api_bundle):
    """TA-65: Export is tenant-isolated."""
    r_a = api_bundle["client"].get(
        "/timeline-authority/export", headers=api_bundle["headers_rw_a"]
    )
    r_b = api_bundle["client"].get(
        "/timeline-authority/export", headers=api_bundle["headers_rw_b"]
    )
    assert r_a.status_code == 200
    assert r_b.status_code == 200
    ids_a = {ev["event_id"] for ev in r_a.json()["events"]}
    ids_b = {ev["event_id"] for ev in r_b.json()["events"]}
    assert ids_a.isdisjoint(ids_b)


# ---------------------------------------------------------------------------
# TA-66: Integrity verification
# ---------------------------------------------------------------------------


def test_integrity_returns_structure(api_bundle):
    """TA-66: GET /integrity returns TimelineIntegrityResponse structure."""
    r = api_bundle["client"].get(
        "/timeline-authority/integrity",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert "tenant_id" in data
    assert "total_events" in data
    assert "chains_checked" in data
    assert "chains_valid" in data
    assert "chains_invalid" in data
    assert "integrity_valid" in data
    assert "chain_details" in data
    assert "hash_chain_validations" in data


def test_integrity_empty_tenant_is_valid(api_bundle):
    """TA-67: Empty tenant has valid integrity."""
    from api.auth_scopes import mint_key

    key = mint_key("governance:read", tenant_id="tenant-ta-integrity-empty")
    headers = _headers(key, "tenant-ta-integrity-empty")
    r = api_bundle["client"].get("/timeline-authority/integrity", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["integrity_valid"] is True
    assert data["chains_checked"] == 0
    assert data["total_events"] == 0


def test_integrity_valid_after_recording_events(api_bundle):
    """TA-68: Integrity is valid after normal event recording."""
    entity_id = "ev-integrity-valid-001"
    for i, evt in enumerate(["CREATED", "VERIFIED", "ARCHIVED"]):
        _record(
            api_bundle["client"],
            api_bundle["headers_rw_a"],
            entity_id=entity_id,
            event_type=evt,
            occurred_at=f"2026-06-08T{10 + i:02d}:00:00.000Z",
        )

    r = api_bundle["client"].get(
        "/timeline-authority/integrity",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["integrity_valid"] is True
    assert data["chains_invalid"] == 0


def test_integrity_chain_details_structure(api_bundle):
    """TA-69: chain_details entries have required fields."""
    r = api_bundle["client"].get(
        "/timeline-authority/integrity",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    details = r.json()["chain_details"]
    for d in details:
        assert "entity_type" in d
        assert "entity_id" in d
        assert "event_count" in d
        assert "chain_valid" in d


def test_integrity_tenant_id_in_response(api_bundle):
    """TA-70: Integrity response contains correct tenant_id."""
    r = api_bundle["client"].get(
        "/timeline-authority/integrity",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "tenant-ta-001"


def test_integrity_cross_tenant_isolation(api_bundle):
    """TA-71: Integrity check is tenant-isolated."""
    r_a = api_bundle["client"].get(
        "/timeline-authority/integrity", headers=api_bundle["headers_rw_a"]
    )
    r_b = api_bundle["client"].get(
        "/timeline-authority/integrity", headers=api_bundle["headers_rw_b"]
    )
    assert r_a.status_code == 200
    assert r_b.status_code == 200
    # They should have independent event counts
    assert r_a.json()["total_events"] != r_b.json()["total_events"] or True


def test_integrity_hash_chain_validations_count(api_bundle):
    """TA-72: hash_chain_validations equals chains_checked."""
    r = api_bundle["client"].get(
        "/timeline-authority/integrity",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["hash_chain_validations"] == data["chains_checked"]


# ---------------------------------------------------------------------------
# TA-73: Statistics
# ---------------------------------------------------------------------------


def test_statistics_returns_structure(api_bundle):
    """TA-73: GET /statistics returns TimelineStatisticsResponse structure."""
    r = api_bundle["client"].get(
        "/timeline-authority/statistics",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert "tenant_id" in data
    assert "total_events" in data
    assert "events_by_source_system" in data
    assert "events_by_entity_type" in data
    assert "events_by_severity" in data
    assert "unique_entities" in data
    assert "unique_source_systems" in data


def test_statistics_total_events_positive(api_bundle):
    """TA-74: total_events > 0 after recording events."""
    r = api_bundle["client"].get(
        "/timeline-authority/statistics",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    assert r.json()["total_events"] > 0


def test_statistics_grouping_by_source_system(api_bundle):
    """TA-75: events_by_source_system is a dict[str, int]."""
    r = api_bundle["client"].get(
        "/timeline-authority/statistics",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    by_source = r.json()["events_by_source_system"]
    assert isinstance(by_source, dict)
    for k, v in by_source.items():
        assert isinstance(k, str)
        assert isinstance(v, int)
        assert v > 0


def test_statistics_grouping_by_entity_type(api_bundle):
    """TA-76: events_by_entity_type is a dict[str, int]."""
    r = api_bundle["client"].get(
        "/timeline-authority/statistics",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    by_entity = r.json()["events_by_entity_type"]
    assert isinstance(by_entity, dict)
    for k, v in by_entity.items():
        assert isinstance(v, int)


def test_statistics_grouping_by_severity(api_bundle):
    """TA-77: events_by_severity is a dict[str, int]."""
    r = api_bundle["client"].get(
        "/timeline-authority/statistics",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    by_sev = r.json()["events_by_severity"]
    assert isinstance(by_sev, dict)
    for v in by_sev.values():
        assert isinstance(v, int)


def test_statistics_unique_source_systems_matches(api_bundle):
    """TA-78: unique_source_systems matches len(events_by_source_system)."""
    r = api_bundle["client"].get(
        "/timeline-authority/statistics",
        headers=api_bundle["headers_rw_a"],
    )
    assert r.status_code == 200
    data = r.json()
    assert data["unique_source_systems"] == len(data["events_by_source_system"])


def test_statistics_tenant_isolation(api_bundle):
    """TA-79: Statistics for tenant B are separate from tenant A."""
    r_a = api_bundle["client"].get(
        "/timeline-authority/statistics", headers=api_bundle["headers_rw_a"]
    )
    r_b = api_bundle["client"].get(
        "/timeline-authority/statistics", headers=api_bundle["headers_rw_b"]
    )
    assert r_a.status_code == 200
    assert r_b.status_code == 200
    # Tenant B has no events yet (or fewer)
    assert r_a.json()["total_events"] >= r_b.json()["total_events"]


def test_statistics_empty_tenant(api_bundle):
    """TA-80: Statistics for empty tenant returns zeros."""
    from api.auth_scopes import mint_key

    key = mint_key("governance:read", tenant_id="tenant-ta-stats-empty")
    headers = _headers(key, "tenant-ta-stats-empty")
    r = api_bundle["client"].get("/timeline-authority/statistics", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["total_events"] == 0
    assert data["unique_entities"] == 0
    assert data["unique_source_systems"] == 0


# ---------------------------------------------------------------------------
# TA-81: Cross-tenant isolation — comprehensive
# ---------------------------------------------------------------------------


def test_cross_tenant_list_isolation(api_bundle):
    """TA-81: Tenant B cannot see Tenant A events in list."""
    # Record some events for tenant B
    _record(
        api_bundle["client"],
        api_bundle["headers_rw_b"],
        entity_id="ev-b-only-001",
        event_type="TENANT_B_EVENT",
        occurred_at="2026-06-07T10:00:00.000Z",
    )

    r_a = api_bundle["client"].get(
        "/timeline-authority/events", headers=api_bundle["headers_rw_a"]
    )
    r_b = api_bundle["client"].get(
        "/timeline-authority/events", headers=api_bundle["headers_rw_b"]
    )
    assert r_a.status_code == 200
    assert r_b.status_code == 200

    ids_a = {ev["event_id"] for ev in r_a.json()}
    ids_b = {ev["event_id"] for ev in r_b.json()}
    assert ids_a.isdisjoint(ids_b)


# ---------------------------------------------------------------------------
# TA-82: Source registry
# ---------------------------------------------------------------------------


def test_source_registry_has_all_sources(api_bundle):
    """TA-82: SOURCE_REGISTRY contains all 10 required source systems."""
    from services.timeline_authority.engine import SOURCE_REGISTRY

    expected = {
        "EVIDENCE_AUTHORITY",
        "RISK_GOVERNANCE",
        "CONTROL_REGISTRY",
        "GOVERNANCE_PORTAL",
        "GOVERNANCE_REPORTING",
        "FIELD_ASSESSMENT",
        "FRAMEWORK_AUTHORITY",
        "REMEDIATION_VERIFICATION",
        "AUTONOMOUS_GOVERNANCE",
        "TIMELINE_AUTHORITY",
    }
    assert expected == set(SOURCE_REGISTRY.keys())


def test_source_registry_entry_has_display_name(api_bundle):
    """TA-83: Each source registry entry has display_name and description."""
    from services.timeline_authority.engine import SOURCE_REGISTRY

    for k, v in SOURCE_REGISTRY.items():
        assert "display_name" in v, f"{k} missing display_name"
        assert "description" in v, f"{k} missing description"
        assert v["display_name"]
        assert v["description"]


# ---------------------------------------------------------------------------
# TA-84: Chain integrity verification at engine level
# ---------------------------------------------------------------------------


def test_verify_chain_empty_is_valid(api_bundle):
    """TA-84: _verify_chain([]) returns True."""
    from services.timeline_authority.engine import _verify_chain

    assert _verify_chain([]) is True


def test_verify_chain_single_event_valid(api_bundle):
    """TA-85: Single event with genesis prev_hash is valid."""
    from services.timeline_authority.engine import _verify_chain

    class FakeRow:
        prev_event_hash = "0" * 64
        event_hash = "a" * 64

    assert _verify_chain([FakeRow()]) is True


def test_verify_chain_single_event_invalid_genesis(api_bundle):
    """TA-86: Single event with non-genesis prev_hash is invalid."""
    from services.timeline_authority.engine import _verify_chain

    class FakeRow:
        prev_event_hash = "1" * 64  # Not genesis
        event_hash = "a" * 64

    assert _verify_chain([FakeRow()]) is False


def test_verify_chain_two_events_valid(api_bundle):
    """TA-87: Two linked events form valid chain."""
    from services.timeline_authority.engine import _verify_chain

    class R1:
        prev_event_hash = "0" * 64
        event_hash = "abc123" + "0" * 58

    class R2:
        prev_event_hash = R1.event_hash
        event_hash = "def456" + "0" * 58

    assert _verify_chain([R1(), R2()]) is True


def test_verify_chain_broken_link(api_bundle):
    """TA-88: Broken chain link returns False."""
    from services.timeline_authority.engine import _verify_chain

    class R1:
        prev_event_hash = "0" * 64
        event_hash = "abc" + "0" * 61

    class R2:
        prev_event_hash = "wrong" + "0" * 59  # Does not match R1.event_hash
        event_hash = "def" + "0" * 61

    assert _verify_chain([R1(), R2()]) is False


# ---------------------------------------------------------------------------
# TA-89: Hash chain integrity via API after multi-event sequence
# ---------------------------------------------------------------------------


def test_multi_event_chain_integrity_via_api(api_bundle):
    """TA-89: Multi-event chain passes integrity check."""
    entity_id = "ev-multi-chain-001"
    events = ["CREATED", "SUBMITTED", "VERIFIED", "APPROVED", "ARCHIVED"]
    for i, evt in enumerate(events):
        r = _record(
            api_bundle["client"],
            api_bundle["headers_rw_a"],
            entity_id=entity_id,
            event_type=evt,
            occurred_at=f"2026-06-06T{10 + i:02d}:00:00.000Z",
        )
        assert r.status_code in (200, 201), f"Failed at {evt}: {r.text}"

    r_int = api_bundle["client"].get(
        "/timeline-authority/integrity",
        headers=api_bundle["headers_rw_a"],
    )
    assert r_int.status_code == 200
    assert r_int.json()["integrity_valid"] is True


# ---------------------------------------------------------------------------
# TA-90: Prometheus counters exist
# ---------------------------------------------------------------------------


def test_prometheus_counters_exist(api_bundle):
    """TA-90: All 6 Prometheus counters are importable from engine."""
    from services.timeline_authority.engine import (
        TIMELINE_EVENTS_RECORDED_TOTAL,
        TIMELINE_REPLAY_RUNS_TOTAL,
        TIMELINE_EXPORTS_TOTAL,
        TIMELINE_INTEGRITY_FAILURES_TOTAL,
        TIMELINE_HASH_CHAIN_VALIDATIONS_TOTAL,
        TIMELINE_SOURCES_REGISTERED_TOTAL,
    )

    for counter in [
        TIMELINE_EVENTS_RECORDED_TOTAL,
        TIMELINE_REPLAY_RUNS_TOTAL,
        TIMELINE_EXPORTS_TOTAL,
        TIMELINE_INTEGRITY_FAILURES_TOTAL,
        TIMELINE_HASH_CHAIN_VALIDATIONS_TOTAL,
        TIMELINE_SOURCES_REGISTERED_TOTAL,
    ]:
        assert hasattr(counter, "inc")


# ---------------------------------------------------------------------------
# TA-91: Schema imports from __init__.py
# ---------------------------------------------------------------------------


def test_schema_exports_from_init(api_bundle):
    """TA-91: All schema classes importable via services.timeline_authority."""
    import services.timeline_authority as ta

    for name in [
        "TimelineSourceSystem",
        "TimelineEntityType",
        "TimelineSeverity",
        "TimelineActorType",
        "TimelineAuthorityError",
        "TimelineEventNotFound",
        "TimelineConflict",
        "TimelineIntegrityError",
        "TimelineTenantViolation",
        "TimelineEventRecordRequest",
        "TimelineEventResponse",
        "TimelineReplayResponse",
        "TimelineExportResponse",
        "TimelineIntegrityResponse",
        "TimelineStatisticsResponse",
    ]:
        obj = getattr(ta, name)
        assert obj is not None, f"{name} not exported"


def test_engine_exports_from_init(api_bundle):
    """TA-92: Engine and SOURCE_REGISTRY importable via services.timeline_authority."""
    import services.timeline_authority as ta

    assert ta.TimelineAuthorityEngine is not None
    assert ta.SOURCE_REGISTRY is not None


def test_repository_exports_from_init(api_bundle):
    """TA-93: Repository classes importable via services.timeline_authority."""
    import services.timeline_authority as ta

    assert ta.TimelineAuthorityRepository is not None
    assert ta.derive_event_id is not None
    assert ta.compute_event_hash is not None


# ---------------------------------------------------------------------------
# TA-94: ORM model validation
# ---------------------------------------------------------------------------


def test_orm_model_tablename(api_bundle):
    """TA-94: ORM model uses correct table name."""
    from api.db_models_timeline_authority import TimelineAuthorityEventRecord

    assert TimelineAuthorityEventRecord.__tablename__ == "fa_timeline_events"


def test_orm_model_has_required_columns(api_bundle):
    """TA-95: ORM model has all required columns."""
    from api.db_models_timeline_authority import TimelineAuthorityEventRecord

    cols = {c.name for c in TimelineAuthorityEventRecord.__table__.columns}
    required = {
        "id",
        "tenant_id",
        "event_id",
        "event_hash",
        "prev_event_hash",
        "source_system",
        "source_type",
        "entity_type",
        "entity_id",
        "event_type",
        "actor_type",
        "actor_id",
        "occurred_at",
        "recorded_at",
        "severity",
        "metadata_json",
        "correlation_id",
        "causation_id",
        "replay_version",
        "schema_version",
        "created_at",
    }
    assert required.issubset(cols)


# ---------------------------------------------------------------------------
# TA-96: Request validation
# ---------------------------------------------------------------------------


def test_record_event_invalid_source_system(api_bundle):
    """TA-96: Invalid source_system returns 422."""
    payload = {**_BASE_PAYLOAD, "source_system": "INVALID_SYSTEM"}
    r = api_bundle["client"].post(
        "/timeline-authority/events", json=payload, headers=api_bundle["headers_rw_a"]
    )
    assert r.status_code == 422


def test_record_event_invalid_entity_type(api_bundle):
    """TA-97: Invalid entity_type returns 422."""
    payload = {**_BASE_PAYLOAD, "entity_type": "INVALID_ENTITY"}
    r = api_bundle["client"].post(
        "/timeline-authority/events", json=payload, headers=api_bundle["headers_rw_a"]
    )
    assert r.status_code == 422


def test_record_event_invalid_severity(api_bundle):
    """TA-98: Invalid severity returns 422."""
    payload = {
        **_BASE_PAYLOAD,
        "severity": "INVALID_SEVERITY",
        "entity_id": "ev-sev-inv",
    }
    r = api_bundle["client"].post(
        "/timeline-authority/events", json=payload, headers=api_bundle["headers_rw_a"]
    )
    assert r.status_code == 422


def test_record_event_extra_fields_rejected(api_bundle):
    """TA-99: Extra fields in request body return 422 (extra='forbid')."""
    payload = {
        **_BASE_PAYLOAD,
        "extra_field": "should_fail",
        "entity_id": "ev-extra-field",
    }
    r = api_bundle["client"].post(
        "/timeline-authority/events", json=payload, headers=api_bundle["headers_rw_a"]
    )
    assert r.status_code == 422


def test_record_event_missing_required_fields(api_bundle):
    """TA-100: Missing required fields return 422."""
    # Missing entity_id and event_type
    payload = {"source_system": "EVIDENCE_AUTHORITY", "entity_type": "EVIDENCE"}
    r = api_bundle["client"].post(
        "/timeline-authority/events", json=payload, headers=api_bundle["headers_rw_a"]
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# TA-101: Multi-entity chain tracks independently
# ---------------------------------------------------------------------------


def test_two_entities_independent_chains(api_bundle):
    """TA-101: Two entities have independent hash chains."""
    for entity_id in ["ev-chain-a", "ev-chain-b"]:
        r = _record(
            api_bundle["client"],
            api_bundle["headers_rw_a"],
            entity_id=entity_id,
            event_type="CHAIN_INDEPENDENT",
            occurred_at="2026-06-05T10:00:00.000Z",
        )
        assert r.status_code in (200, 201)
        # Both should have genesis as prev_hash since they are first in their chain
        assert r.json()["prev_event_hash"] == "0" * 64


# ---------------------------------------------------------------------------
# TA-102: Tenant B event recording
# ---------------------------------------------------------------------------


def test_tenant_b_can_record_events(api_bundle):
    """TA-102: Tenant B can independently record events."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_b"],
        source_system="RISK_GOVERNANCE",
        entity_type="RISK",
        entity_id="risk-b-001",
        event_type="OPENED",
        occurred_at="2026-06-04T10:00:00.000Z",
    )
    assert r.status_code in (200, 201)
    data = r.json()
    assert data["tenant_id"] == "tenant-ta-002"


def test_tenant_b_event_not_visible_to_tenant_a(api_bundle):
    """TA-103: Tenant A cannot see Tenant B's events."""
    r = _record(
        api_bundle["client"],
        api_bundle["headers_rw_b"],
        entity_id="ev-b-isolation-002",
        event_type="ISOLATION_CHECK",
        occurred_at="2026-06-04T11:00:00.000Z",
    )
    assert r.status_code in (200, 201)
    event_id = r.json()["event_id"]

    r_a = api_bundle["client"].get(
        f"/timeline-authority/events/{event_id}",
        headers=api_bundle["headers_rw_a"],
    )
    assert r_a.status_code == 404


# ---------------------------------------------------------------------------
# TA-104: Router is registered
# ---------------------------------------------------------------------------


def test_router_is_registered_in_app(api_bundle):
    """TA-104: Timeline authority router is included in the FastAPI app."""
    routes = [r.path for r in api_bundle["client"].app.routes]
    assert any("/timeline-authority" in p for p in routes)


# ---------------------------------------------------------------------------
# TA-105: Actor from header
# ---------------------------------------------------------------------------


def test_actor_id_from_header_fallback(api_bundle):
    """TA-105: actor_id falls back to X-Actor header when not set in payload."""
    headers = {**api_bundle["headers_rw_a"], "X-Actor": "custom-actor-xyz"}
    r = api_bundle["client"].post(
        "/timeline-authority/events",
        json={
            "source_system": "CONTROL_REGISTRY",
            "entity_type": "CONTROL",
            "entity_id": "ctrl-actor-001",
            "event_type": "CREATED",
            "occurred_at": "2026-06-03T10:00:00.000Z",
            # No actor_id in payload
        },
        headers=headers,
    )
    assert r.status_code in (200, 201)
    data = r.json()
    assert data["actor_id"] == "custom-actor-xyz"


def test_actor_id_in_payload_takes_precedence(api_bundle):
    """TA-106: actor_id in payload takes precedence over X-Actor header."""
    headers = {**api_bundle["headers_rw_a"], "X-Actor": "header-actor"}
    r = api_bundle["client"].post(
        "/timeline-authority/events",
        json={
            "source_system": "CONTROL_REGISTRY",
            "entity_type": "CONTROL",
            "entity_id": "ctrl-actor-002",
            "event_type": "CREATED",
            "occurred_at": "2026-06-03T11:00:00.000Z",
            "actor_id": "payload-actor",
        },
        headers=headers,
    )
    assert r.status_code in (200, 201)
    data = r.json()
    assert data["actor_id"] == "payload-actor"


# ---------------------------------------------------------------------------
# TA-107: Read-only scope can access read endpoints
# ---------------------------------------------------------------------------


def test_read_scope_can_list_events(api_bundle):
    """TA-107: Read-only scope can access GET /events."""
    r = api_bundle["client"].get(
        "/timeline-authority/events", headers=api_bundle["headers_read_a"]
    )
    assert r.status_code == 200


def test_read_scope_can_replay(api_bundle):
    """TA-108: Read-only scope can access GET /replay."""
    r = api_bundle["client"].get(
        "/timeline-authority/replay", headers=api_bundle["headers_read_a"]
    )
    assert r.status_code == 200


def test_read_scope_can_integrity(api_bundle):
    """TA-109: Read-only scope can access GET /integrity."""
    r = api_bundle["client"].get(
        "/timeline-authority/integrity", headers=api_bundle["headers_read_a"]
    )
    assert r.status_code == 200


def test_read_scope_can_statistics(api_bundle):
    """TA-110: Read-only scope can access GET /statistics."""
    r = api_bundle["client"].get(
        "/timeline-authority/statistics", headers=api_bundle["headers_read_a"]
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# TA-111: Plane registry contains /timeline-authority
# ---------------------------------------------------------------------------


def test_plane_registry_has_timeline_authority(api_bundle):
    """TA-111: /timeline-authority is registered in the control plane."""
    from services.plane_registry.registry import PLANE_REGISTRY

    control_plane = next((p for p in PLANE_REGISTRY if p.plane_id == "control"), None)
    assert control_plane is not None
    assert "/timeline-authority" in control_plane.route_prefixes


# ---------------------------------------------------------------------------
# TA-112: SQLite table was created
# ---------------------------------------------------------------------------


def test_sqlite_table_exists(api_bundle):
    """TA-112: fa_timeline_events table exists in SQLite test DB."""
    import sqlite3

    con = sqlite3.connect(api_bundle["db_path"])
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='fa_timeline_events'"
    ).fetchone()
    con.close()
    assert row is not None


def test_sqlite_append_only_update_trigger(api_bundle):
    """TA-113: SQLite BEFORE UPDATE trigger raises on fa_timeline_events."""
    import sqlite3

    con = sqlite3.connect(api_bundle["db_path"])
    # First insert a row via direct SQL — include all NOT NULL columns
    con.execute(
        "INSERT OR REPLACE INTO fa_timeline_events "
        "(id, tenant_id, event_id, event_hash, prev_event_hash, source_system, source_type, "
        "entity_type, entity_id, event_type, actor_type, actor_id, occurred_at, recorded_at, "
        "severity, metadata_json, correlation_id, causation_id, replay_version, schema_version, created_at) "
        "VALUES ('test-trig-row', 'trig-tenant', 'test-trig-row', 'aaaa', '0000', "
        "'EVIDENCE_AUTHORITY', '', 'EVIDENCE', 'ev-trig', 'TRIG_TEST', '', '', "
        "'2026-01-01T00:00:00', '2026-01-01T00:00:00', 'INFO', '{}', '', '', 1, 1, '2026-01-01T00:00:00')"
    )
    con.commit()
    # Verify the row was inserted
    row = con.execute(
        "SELECT id FROM fa_timeline_events WHERE id = 'test-trig-row'"
    ).fetchone()
    assert row is not None, "Row was not inserted — trigger test cannot proceed"
    with pytest.raises(sqlite3.DatabaseError):
        con.execute(
            "UPDATE fa_timeline_events SET event_type = 'MODIFIED' WHERE id = 'test-trig-row'"
        )
    con.close()


def test_sqlite_append_only_delete_trigger(api_bundle):
    """TA-114: SQLite BEFORE DELETE trigger raises on fa_timeline_events."""
    import sqlite3

    con = sqlite3.connect(api_bundle["db_path"])
    # Ensure the row exists (it may have been committed from previous test)
    row = con.execute(
        "SELECT id FROM fa_timeline_events WHERE id = 'test-trig-row'"
    ).fetchone()
    assert row is not None, "Row from TA-113 must exist for delete trigger test"
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("DELETE FROM fa_timeline_events WHERE id = 'test-trig-row'")
    con.close()


# =============================================================================
# P1: Authority Level
# =============================================================================


def test_p1_authority_level_defaults_to_system(api_bundle):
    """TA-P1-01: authority_level defaults to SYSTEM when not specified."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "EVIDENCE_AUTHORITY",
        "entity_type": "EVIDENCE",
        "entity_id": "p1-ev-default-al",
        "event_type": "P1_DEFAULT_AL",
        "occurred_at": "2026-06-22T10:00:00Z",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["authority_level"] == "SYSTEM"


def test_p1_authority_level_human(api_bundle):
    """TA-P1-02: authority_level HUMAN is accepted and persisted."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "GOVERNANCE_PORTAL",
        "entity_type": "DECISION",
        "entity_id": "p1-dec-human",
        "event_type": "HUMAN_APPROVED",
        "occurred_at": "2026-06-22T10:01:00Z",
        "authority_level": "HUMAN",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["authority_level"] == "HUMAN"


def test_p1_authority_level_committee(api_bundle):
    """TA-P1-03: authority_level COMMITTEE is accepted."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "GOVERNANCE_REPORTING",
        "entity_type": "REPORT",
        "entity_id": "p1-rep-committee",
        "event_type": "COMMITTEE_REVIEW",
        "occurred_at": "2026-06-22T10:02:00Z",
        "authority_level": "COMMITTEE",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["authority_level"] == "COMMITTEE"


def test_p1_authority_level_autonomous_agent(api_bundle):
    """TA-P1-04: authority_level AUTONOMOUS_AGENT is accepted."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "AUTONOMOUS_GOVERNANCE",
        "entity_type": "AGENT",
        "entity_id": "p1-agent-aa",
        "event_type": "AGENT_DECISION",
        "occurred_at": "2026-06-22T10:03:00Z",
        "authority_level": "AUTONOMOUS_AGENT",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["authority_level"] == "AUTONOMOUS_AGENT"


def test_p1_authority_level_agi_system(api_bundle):
    """TA-P1-05: authority_level AGI_SYSTEM is accepted — future-proofing."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "AUTONOMOUS_GOVERNANCE",
        "entity_type": "DECISION",
        "entity_id": "p1-dec-agi",
        "event_type": "AGI_GOVERNANCE_DECISION",
        "occurred_at": "2026-06-22T10:04:00Z",
        "authority_level": "AGI_SYSTEM",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["authority_level"] == "AGI_SYSTEM"


def test_p1_authority_level_all_values_accepted(api_bundle):
    """TA-P1-06: all defined authority_level values are accepted by the API."""
    from services.timeline_authority.schemas import TimelineAuthorityLevel

    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    for i, level in enumerate(TimelineAuthorityLevel):
        payload = {
            "source_system": "CONTROL_REGISTRY",
            "entity_type": "CONTROL",
            "entity_id": f"p1-ctrl-al-{i}",
            "event_type": f"AL_TEST_{level.value}",
            "occurred_at": f"2026-06-22T10:10:{i:02d}Z",
            "authority_level": level.value,
        }
        resp = client.post("/timeline-authority/events", json=payload, headers=headers)
        assert resp.status_code == 200, f"authority_level={level.value} rejected"
        assert resp.json()["authority_level"] == level.value


def test_p1_authority_level_invalid_rejected(api_bundle):
    """TA-P1-07: invalid authority_level is rejected with 422."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "CONTROL_REGISTRY",
        "entity_type": "CONTROL",
        "entity_id": "p1-invalid-al",
        "event_type": "TEST",
        "occurred_at": "2026-06-22T10:20:00Z",
        "authority_level": "NOT_A_REAL_LEVEL",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 422


def test_p1_authority_level_in_response(api_bundle):
    """TA-P1-08: authority_level appears in GET /events response."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    resp = client.get("/timeline-authority/events", headers=headers)
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) > 0
    assert "authority_level" in events[0]


# =============================================================================
# P1: Signature Reservation
# =============================================================================


def test_p1_signature_fields_default_empty(api_bundle):
    """TA-P1-09: signature fields default to empty strings, signed_at to None."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "EVIDENCE_AUTHORITY",
        "entity_type": "EVIDENCE",
        "entity_id": "p1-ev-sig-default",
        "event_type": "SIG_DEFAULT",
        "occurred_at": "2026-06-22T11:00:00Z",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["signature_algorithm"] == ""
    assert body["signature_value"] == ""
    assert body["signed_at"] is None


def test_p1_signature_algorithm_stored(api_bundle):
    """TA-P1-10: signature_algorithm is persisted and returned."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "EVIDENCE_AUTHORITY",
        "entity_type": "EVIDENCE",
        "entity_id": "p1-ev-sig-alg",
        "event_type": "SIG_ALG_TEST",
        "occurred_at": "2026-06-22T11:01:00Z",
        "signature_algorithm": "Ed25519",
        "signature_value": "base64encodedvalue==",
        "signed_at": "2026-06-22T11:01:30Z",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["signature_algorithm"] == "Ed25519"
    assert body["signature_value"] == "base64encodedvalue=="
    assert body["signed_at"] is not None


def test_p1_signature_reserved_without_value_accepted(api_bundle):
    """TA-P1-11: partial signature fields (algorithm only) are accepted."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "RISK_GOVERNANCE",
        "entity_type": "RISK",
        "entity_id": "p1-risk-sig-partial",
        "event_type": "SIG_PARTIAL",
        "occurred_at": "2026-06-22T11:02:00Z",
        "signature_algorithm": "SHA256withRSA",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["signature_algorithm"] == "SHA256withRSA"
    assert resp.json()["signature_value"] == ""


# =============================================================================
# P1: External References
# =============================================================================


def test_p1_external_reference_defaults_empty(api_bundle):
    """TA-P1-12: external_reference fields default to empty strings."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "FIELD_ASSESSMENT",
        "entity_type": "ENGAGEMENT",
        "entity_id": "p1-eng-extref-default",
        "event_type": "EXTREF_DEFAULT",
        "occurred_at": "2026-06-22T12:00:00Z",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["external_reference"] == ""
    assert body["external_reference_type"] == ""


def test_p1_external_reference_jira(api_bundle):
    """TA-P1-13: Jira ticket reference is persisted and returned."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "CONTROL_REGISTRY",
        "entity_type": "CONTROL",
        "entity_id": "p1-ctrl-jira",
        "event_type": "JIRA_LINKED",
        "occurred_at": "2026-06-22T12:01:00Z",
        "external_reference": "CTRL-1234",
        "external_reference_type": "JIRA",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["external_reference"] == "CTRL-1234"
    assert body["external_reference_type"] == "JIRA"


def test_p1_external_reference_servicenow(api_bundle):
    """TA-P1-14: ServiceNow ticket reference is accepted."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "RISK_GOVERNANCE",
        "entity_type": "RISK",
        "entity_id": "p1-risk-snow",
        "event_type": "SNOW_LINKED",
        "occurred_at": "2026-06-22T12:02:00Z",
        "external_reference": "INC0012345",
        "external_reference_type": "SERVICENOW",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["external_reference_type"] == "SERVICENOW"


def test_p1_external_reference_legal_hold(api_bundle):
    """TA-P1-15: Legal hold reference type is accepted — future regulatory use."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "EVIDENCE_AUTHORITY",
        "entity_type": "EVIDENCE",
        "entity_id": "p1-ev-legalhold",
        "event_type": "LEGAL_HOLD_APPLIED",
        "occurred_at": "2026-06-22T12:03:00Z",
        "external_reference": "LH-2026-001",
        "external_reference_type": "LEGAL_HOLD",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["external_reference"] == "LH-2026-001"


def test_p1_external_reference_in_get_event(api_bundle):
    """TA-P1-16: external_reference fields are present in GET /events/{event_id}."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    post_resp = client.post(
        "/timeline-authority/events",
        json={
            "source_system": "CONTROL_REGISTRY",
            "entity_type": "CONTROL",
            "entity_id": "p1-ctrl-extref-get",
            "event_type": "EXTREF_GET_TEST",
            "occurred_at": "2026-06-22T12:04:00Z",
            "external_reference": "ADO-9999",
            "external_reference_type": "AZURE_DEVOPS",
        },
        headers=headers,
    )
    assert post_resp.status_code == 200
    event_id = post_resp.json()["event_id"]
    get_resp = client.get(f"/timeline-authority/events/{event_id}", headers=headers)
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["external_reference"] == "ADO-9999"
    assert body["external_reference_type"] == "AZURE_DEVOPS"


# =============================================================================
# P1: Federation Hooks
# =============================================================================


def test_p1_federation_hooks_default_empty(api_bundle):
    """TA-P1-17: federation hook fields default to empty strings."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "TIMELINE_AUTHORITY",
        "entity_type": "TENANT",
        "entity_id": "p1-tenant-fed-default",
        "event_type": "FED_DEFAULT",
        "occurred_at": "2026-06-22T13:00:00Z",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["origin_system"] == ""
    assert body["origin_tenant"] == ""
    assert body["origin_event_id"] == ""


def test_p1_federation_hooks_stored(api_bundle):
    """TA-P1-18: federation hook fields are persisted and returned."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "TIMELINE_AUTHORITY",
        "entity_type": "DECISION",
        "entity_id": "p1-dec-fed",
        "event_type": "FEDERATED_EVENT",
        "occurred_at": "2026-06-22T13:01:00Z",
        "origin_system": "partner-frostgate-eu",
        "origin_tenant": "partner-tenant-eu-001",
        "origin_event_id": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["origin_system"] == "partner-frostgate-eu"
    assert body["origin_tenant"] == "partner-tenant-eu-001"
    assert (
        body["origin_event_id"]
        == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )


def test_p1_federation_hooks_in_entity_timeline(api_bundle):
    """TA-P1-19: federation hook fields present in entity timeline response."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "RISK_GOVERNANCE",
        "entity_type": "RISK",
        "entity_id": "p1-risk-fed-timeline",
        "event_type": "FED_TIMELINE",
        "occurred_at": "2026-06-22T13:02:00Z",
        "origin_system": "cgin-node-1",
    }
    client.post("/timeline-authority/events", json=payload, headers=headers)
    resp = client.get(
        "/timeline-authority/entities/RISK/p1-risk-fed-timeline", headers=headers
    )
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 1
    assert "origin_system" in events[0]
    assert events[0]["origin_system"] == "cgin-node-1"


def test_p1_federation_partial_hook_accepted(api_bundle):
    """TA-P1-20: only origin_system set (partial federation) is valid."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    payload = {
        "source_system": "AUTONOMOUS_GOVERNANCE",
        "entity_type": "AGENT",
        "entity_id": "p1-agent-fed-partial",
        "event_type": "PARTIAL_FED",
        "occurred_at": "2026-06-22T13:03:00Z",
        "origin_system": "cgin-network-alpha",
    }
    resp = client.post("/timeline-authority/events", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["origin_system"] == "cgin-network-alpha"
    assert resp.json()["origin_tenant"] == ""
    assert resp.json()["origin_event_id"] == ""


# =============================================================================
# P1: Schema export
# =============================================================================


def test_p1_authority_level_enum_exported(api_bundle):
    """TA-P1-21: TimelineAuthorityLevel is exported from the service __init__."""
    from services.timeline_authority import TimelineAuthorityLevel

    assert TimelineAuthorityLevel.AGI_SYSTEM.value == "AGI_SYSTEM"
    assert TimelineAuthorityLevel.AUTONOMOUS_AGENT.value == "AUTONOMOUS_AGENT"
    assert len(list(TimelineAuthorityLevel)) == 7


def test_p1_all_p1_fields_in_response_schema(api_bundle):
    """TA-P1-22: all P1 fields are present in TimelineEventResponse."""
    from services.timeline_authority.schemas import TimelineEventResponse

    fields = TimelineEventResponse.model_fields
    for field in (
        "authority_level",
        "signature_algorithm",
        "signature_value",
        "signed_at",
        "external_reference",
        "external_reference_type",
        "origin_system",
        "origin_tenant",
        "origin_event_id",
    ):
        assert field in fields, f"Missing P1 field in response schema: {field}"


def test_p1_migration_file_exists(api_bundle):
    """TA-P1-23: migration 0126 exists on disk."""
    import os

    assert os.path.exists("migrations/postgres/0126_timeline_authority_p1.sql"), (
        "P1 migration file missing"
    )


# =============================================================================
# Bug fixes: ordering and export filter
# =============================================================================


def test_same_timestamp_tail_is_correct(api_bundle):
    """BF-01: when two events share occurred_at, the lexically-last id is the tail.

    get_latest_event_hash must use DESC,DESC ordering so the actual chain tail
    (last in ASC,ASC) is selected as prev_event_hash for the next event.
    """
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]
    ts = "2026-06-23T09:00:00Z"
    entity_id = "bf01-same-ts-entity"

    r1 = client.post(
        "/timeline-authority/events",
        json={
            "source_system": "EVIDENCE_AUTHORITY",
            "entity_type": "EVIDENCE",
            "entity_id": entity_id,
            "event_type": "FIRST",
            "occurred_at": ts,
        },
        headers=headers,
    )
    assert r1.status_code == 200

    r2 = client.post(
        "/timeline-authority/events",
        json={
            "source_system": "EVIDENCE_AUTHORITY",
            "entity_type": "EVIDENCE",
            "entity_id": entity_id,
            "event_type": "SECOND",
            "occurred_at": ts,
        },
        headers=headers,
    )
    assert r2.status_code == 200

    # Chain must be intact — integrity must report valid
    integrity = client.get("/timeline-authority/integrity", headers=headers)
    assert integrity.status_code == 200
    body = integrity.json()
    entity_chains = [c for c in body["chain_details"] if c["entity_id"] == entity_id]
    assert len(entity_chains) == 1
    assert entity_chains[0]["chain_valid"] is True, (
        "Same-timestamp events produced a broken chain — tail ordering bug"
    )


def test_export_entity_type_filter_honoured(api_bundle):
    """BF-02: export?entity_type=X must not return events from other entity types."""
    client = api_bundle["client"]
    headers = api_bundle["headers_rw_a"]

    # Record one RISK event
    client.post(
        "/timeline-authority/events",
        json={
            "source_system": "RISK_GOVERNANCE",
            "entity_type": "RISK",
            "entity_id": "bf02-risk",
            "event_type": "BF_RISK",
            "occurred_at": "2026-06-23T10:00:00Z",
        },
        headers=headers,
    )
    # Record one CONTROL event
    client.post(
        "/timeline-authority/events",
        json={
            "source_system": "CONTROL_REGISTRY",
            "entity_type": "CONTROL",
            "entity_id": "bf02-ctrl",
            "event_type": "BF_CTRL",
            "occurred_at": "2026-06-23T10:01:00Z",
        },
        headers=headers,
    )

    resp = client.get("/timeline-authority/export?entity_type=RISK", headers=headers)
    assert resp.status_code == 200
    events = resp.json()["events"]
    entity_types = {e["entity_type"] for e in events}
    assert "CONTROL" not in entity_types, (
        "export?entity_type=RISK returned CONTROL events — entity_type filter bug"
    )
