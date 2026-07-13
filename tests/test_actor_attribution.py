"""tests/test_actor_attribution.py — PR 535: Enterprise Actor Attribution & Non-Repudiation.

Tests: AA-1 through AA-27
"""

from __future__ import annotations

import sqlite3
from uuid import uuid4
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


# ── helpers ───────────────────────────────────────────────────────────────────

_NOW = "2026-01-01T00:00:00+00:00"
_NOW_2 = "2026-01-02T00:00:00+00:00"
_NOW_3 = "2026-01-03T00:00:00+00:00"


def _insert_actor(
    db_path: str,
    actor_id: str,
    tenant_id: str,
    actor_type: str = "human_user",
) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO actor_identities
            (id, tenant_id, actor_type, actor_subject, actor_display_name,
             authentication_method, identity_provider, trust_level, status,
             created_at, updated_at, is_service_account, is_robot, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, '1.0')
            """,
            (
                actor_id,
                tenant_id,
                actor_type,
                f"sub:{actor_id}",
                f"Actor {actor_id[:8]}",
                "api_key",
                "api_key",
                "high",
                "active",
                _NOW,
                _NOW,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_service_account_actor(
    db_path: str,
    actor_id: str,
    tenant_id: str,
) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO actor_identities
            (id, tenant_id, actor_type, actor_subject, actor_display_name,
             authentication_method, identity_provider, trust_level, status,
             created_at, updated_at, is_service_account, is_robot, schema_version)
            VALUES (?, ?, 'service_account', ?, ?, 'api_key', 'api_key',
                    'high', 'active', ?, ?, 1, 0, '1.0')
            """,
            (
                actor_id,
                tenant_id,
                f"sub:{actor_id}",
                f"SvcActor {actor_id[:8]}",
                _NOW,
                _NOW,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_actor_audit_event(
    db_path: str,
    event_id: str,
    actor_id: str,
    tenant_id: str,
    event_type: str,
    created_at: str = _NOW,
) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO actor_audit_events
            (id, tenant_id, actor_id, event_type, actor_type_snapshot,
             created_at, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, '1.0')
            """,
            (event_id, tenant_id, actor_id, event_type, "human_user", created_at),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_attribution_record(
    db_path: str,
    attr_id: str,
    actor_id: str,
    tenant_id: str,
    event_type: str,
    event_ref: str | None = None,
    event_ref_type: str | None = None,
    created_at: str = _NOW,
) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO actor_attribution_records
            (id, tenant_id, actor_id, snapshot_id, event_type,
             actor_type, actor_display_name, authentication_method,
             identity_provider, request_id, trust_level,
             actor_fingerprint, identity_fingerprint, request_fingerprint,
             attribution_hash, event_hash, created_at, schema_version,
             event_ref, event_ref_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '1.0', ?, ?)
            """,
            (
                attr_id,
                tenant_id,
                actor_id,
                "snap-1",
                event_type,
                "human_user",
                "Test Actor",
                "api_key",
                "api_key",
                f"req-{attr_id}",
                "high",
                "fp-actor",
                "fp-identity",
                "fp-request",
                "fp-attribution",
                "fp-event",
                created_at,
                event_ref,
                event_ref_type,
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ── Group 1: Auth & scope enforcement (AA-1 to AA-5) ─────────────────────────


def test_aa_1_missing_key_rejected(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    resp = client.get("/actor-attribution/actor/some-id")
    assert resp.status_code in (401, 403), "missing API key must be denied"


def test_aa_2_wrong_scope_rejected(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("governance:read", tenant_id="t-aa-2")
    resp = client.get("/actor-attribution/actor/some-id", headers={"X-API-Key": key})
    assert resp.status_code == 403, "wrong scope must be denied with 403"


def test_aa_3_valid_actor_read_key_accepted(build_app, fresh_db):
    actor_id = f"actor-aa-3-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, "t-aa-3")
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id="t-aa-3")
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}", headers={"X-API-Key": key}
    )
    assert resp.status_code == 200, f"actor:read key must succeed; got {resp.text}"


def test_aa_4_cross_tenant_key_denied(build_app, fresh_db):
    actor_id = f"actor-aa-4-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, "t-aa-4-a")
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key_b = mint_key("actor:read", tenant_id="t-aa-4-b")
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}", headers={"X-API-Key": key_b}
    )
    # Route returns 404 to avoid enumeration, not 403
    assert resp.status_code in (403, 404), "tenant-B key must not read tenant-A actor"


def test_aa_5_no_tenant_binding_returns_400(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    # Unscoped key without tenant binding
    key = mint_key("actor:read")
    resp = client.get("/actor-attribution/actor/any-id", headers={"X-API-Key": key})
    assert resp.status_code == 400, "unbound tenant must return 400"


# ── Group 2: Actor not found (AA-6 to AA-8) ──────────────────────────────────


def test_aa_6_actor_not_found_returns_404_with_code(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id="t-aa-6")
    resp = client.get(
        "/actor-attribution/actor/nonexistent-id", headers={"X-API-Key": key}
    )
    assert resp.status_code == 404, "nonexistent actor must return 404"
    assert resp.json()["detail"]["code"] == "ACTOR_NOT_FOUND"


def test_aa_7_actor_history_not_found_returns_404(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id="t-aa-7")
    resp = client.get(
        "/actor-attribution/actor/nonexistent-id/history", headers={"X-API-Key": key}
    )
    assert resp.status_code == 404, "history for nonexistent actor must return 404"


def test_aa_8_actor_attribution_not_found_returns_404(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id="t-aa-8")
    resp = client.get(
        "/actor-attribution/actor/nonexistent-id/attribution",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 404, "attribution for nonexistent actor must return 404"


# ── Group 3: Actor resolution via ActorIdentityEngine (AA-9 to AA-12) ────────


def test_aa_9_insert_actor_and_get_returns_200_with_correct_type(build_app, fresh_db):
    actor_id = f"actor-aa-9-{uuid4().hex[:8]}"
    tenant_id = "t-aa-9"
    _insert_actor(fresh_db, actor_id, tenant_id, actor_type="api_client")
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}", headers={"X-API-Key": key}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["actor_id"] == actor_id, "actor_id must match"
    assert body["actor_type"] == "api_client", "actor_type must match inserted value"


def test_aa_10_cross_tenant_actor_read_returns_404(build_app, fresh_db):
    actor_id = f"actor-aa-10-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, "t-aa-10-a")
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key_b = mint_key("actor:read", tenant_id="t-aa-10-b")
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}", headers={"X-API-Key": key_b}
    )
    # Must return 404 (not 200, not 403) to avoid enumeration
    assert resp.status_code == 404, (
        f"cross-tenant read must return 404 to avoid enumeration; got {resp.status_code}"
    )


def test_aa_11_actor_status_returned_correctly(build_app, fresh_db):
    actor_id = f"actor-aa-11-{uuid4().hex[:8]}"
    tenant_id = "t-aa-11"
    _insert_actor(fresh_db, actor_id, tenant_id)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}", headers={"X-API-Key": key}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "active", "status field must be 'active'"


def test_aa_12_is_service_account_and_is_robot_returned_as_booleans(
    build_app, fresh_db
):
    actor_id = f"actor-aa-12-{uuid4().hex[:8]}"
    tenant_id = "t-aa-12"
    _insert_actor(fresh_db, actor_id, tenant_id)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}", headers={"X-API-Key": key}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body["is_service_account"], bool), (
        "is_service_account must be a Python bool, not int"
    )
    assert isinstance(body["is_robot"], bool), "is_robot must be a Python bool, not int"
    assert body["is_service_account"] is False
    assert body["is_robot"] is False


# ── Group 4: Actor history (AA-13 to AA-15) ───────────────────────────────────


def test_aa_13_actor_with_two_audit_events_returns_both(build_app, fresh_db):
    actor_id = f"actor-aa-13-{uuid4().hex[:8]}"
    tenant_id = "t-aa-13"
    _insert_actor(fresh_db, actor_id, tenant_id)
    _insert_actor_audit_event(
        fresh_db, f"ev-aa-13-1-{uuid4().hex[:6]}", actor_id, tenant_id, "actor_created"
    )
    _insert_actor_audit_event(
        fresh_db, f"ev-aa-13-2-{uuid4().hex[:6]}", actor_id, tenant_id, "actor_updated"
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}/history", headers={"X-API-Key": key}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2, f"expected 2 events, got {body['total']}"
    assert len(body["events"]) == 2


def test_aa_14_history_respects_limit_param(build_app, fresh_db):
    actor_id = f"actor-aa-14-{uuid4().hex[:8]}"
    tenant_id = "t-aa-14"
    _insert_actor(fresh_db, actor_id, tenant_id)
    for i in range(5):
        _insert_actor_audit_event(
            fresh_db,
            f"ev-aa-14-{i}-{uuid4().hex[:6]}",
            actor_id,
            tenant_id,
            "actor_updated",
        )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}/history?limit=2",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 5, f"total must reflect all 5 events; got {body['total']}"
    assert len(body["events"]) == 2, "limit=2 must return only 2 events"


def test_aa_15_actor_with_no_history_returns_empty_events(build_app, fresh_db):
    actor_id = f"actor-aa-15-{uuid4().hex[:8]}"
    tenant_id = "t-aa-15"
    _insert_actor(fresh_db, actor_id, tenant_id)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}/history", headers={"X-API-Key": key}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["events"] == [], "actor with no history must return events: []"
    assert body["total"] == 0


# ── Group 5: Actor attribution records (AA-16 to AA-18) ───────────────────────


def test_aa_16_actor_with_three_attribution_records_returns_all(build_app, fresh_db):
    actor_id = f"actor-aa-16-{uuid4().hex[:8]}"
    tenant_id = "t-aa-16"
    _insert_actor(fresh_db, actor_id, tenant_id)
    for i in range(3):
        _insert_attribution_record(
            fresh_db,
            f"attr-aa-16-{i}-{uuid4().hex[:6]}",
            actor_id,
            tenant_id,
            "report_generation",
        )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}/attribution",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 3, f"expected 3 attribution records, got {body['total']}"
    assert len(body["attribution_records"]) == 3


def test_aa_17_attribution_filter_by_event_type(build_app, fresh_db):
    actor_id = f"actor-aa-17-{uuid4().hex[:8]}"
    tenant_id = "t-aa-17"
    _insert_actor(fresh_db, actor_id, tenant_id)
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-17-a-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "report_generation",
    )
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-17-b-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "governance_decision",
    )
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-17-c-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "governance_decision",
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}/attribution?event_type=governance_decision",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2, "filter by event_type=governance_decision must return 2"
    assert all(
        r["event_type"] == "governance_decision" for r in body["attribution_records"]
    )


def test_aa_18_actor_with_no_attribution_returns_empty(build_app, fresh_db):
    actor_id = f"actor-aa-18-{uuid4().hex[:8]}"
    tenant_id = "t-aa-18"
    _insert_actor(fresh_db, actor_id, tenant_id)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}/attribution",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["attribution_records"] == [], (
        "actor with no attribution must return attribution_records: []"
    )
    assert body["total"] == 0


# ── Group 6: Report actor chain (AA-19 to AA-21) ─────────────────────────────


def test_aa_19_report_with_two_records_returns_chain_length_2(build_app, fresh_db):
    actor_id = f"actor-aa-19-{uuid4().hex[:8]}"
    tenant_id = "t-aa-19"
    report_id = f"report-aa-19-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, tenant_id)
    for i in range(2):
        _insert_attribution_record(
            fresh_db,
            f"attr-aa-19-{i}-{uuid4().hex[:6]}",
            actor_id,
            tenant_id,
            "report_generation",
            event_ref=report_id,
            event_ref_type="report",
        )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/report/{report_id}/actor-chain",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["chain_length"] == 2, (
        f"expected chain_length 2, got {body['chain_length']}"
    )
    assert len(body["chain"]) == 2


def test_aa_20_report_with_no_records_returns_empty_chain(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id="t-aa-20")
    report_id = f"report-aa-20-{uuid4().hex[:8]}"
    resp = client.get(
        f"/actor-attribution/report/{report_id}/actor-chain",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["chain_length"] == 0, "report with no records must have chain_length 0"
    assert body["chain"] == []


def test_aa_21_cross_tenant_report_chain_returns_empty_not_403(build_app, fresh_db):
    actor_id = f"actor-aa-21-{uuid4().hex[:8]}"
    report_id = f"report-aa-21-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, "t-aa-21-a")
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-21-{uuid4().hex[:6]}",
        actor_id,
        "t-aa-21-a",
        "report_generation",
        event_ref=report_id,
        event_ref_type="report",
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key_b = mint_key("actor:read", tenant_id="t-aa-21-b")
    resp = client.get(
        f"/actor-attribution/report/{report_id}/actor-chain",
        headers={"X-API-Key": key_b},
    )
    # Cross-tenant: no 403, just empty chain (tenant isolation without enumeration)
    assert resp.status_code == 200, (
        f"cross-tenant report chain must return 200 empty chain; got {resp.status_code}"
    )
    assert resp.json()["chain_length"] == 0, "cross-tenant must see empty chain"


# ── Group 7: Evidence actor chain (AA-22 to AA-24) ───────────────────────────


def test_aa_22_evidence_records_with_type_evidence_returned(build_app, fresh_db):
    actor_id = f"actor-aa-22-{uuid4().hex[:8]}"
    tenant_id = "t-aa-22"
    evidence_id = f"evid-aa-22-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, tenant_id)
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-22-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "evidence_provenance",
        event_ref=evidence_id,
        event_ref_type="evidence",
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/evidence/{evidence_id}/actor-chain",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["chain_length"] == 1, (
        f"evidence with 1 record must return chain_length 1; got {body['chain_length']}"
    )


def test_aa_23_evidence_records_with_type_evidence_link_returned(build_app, fresh_db):
    actor_id = f"actor-aa-23-{uuid4().hex[:8]}"
    tenant_id = "t-aa-23"
    evidence_id = f"evid-aa-23-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, tenant_id)
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-23-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "evidence_provenance",
        event_ref=evidence_id,
        event_ref_type="evidence_link",
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/evidence/{evidence_id}/actor-chain",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["chain_length"] == 1, (
        "event_ref_type='evidence_link' must be included in evidence chain"
    )


def test_aa_24_evidence_id_with_no_records_returns_chain_length_0(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id="t-aa-24")
    evidence_id = f"evid-aa-24-{uuid4().hex[:8]}"
    resp = client.get(
        f"/actor-attribution/evidence/{evidence_id}/actor-chain",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["chain_length"] == 0, (
        "evidence with no records must return chain_length 0"
    )
    assert body["chain"] == []


# ── Group 8: Immutability / non-repudiation fields (AA-25 to AA-27) ──────────


def test_aa_25_attribution_record_has_non_null_fingerprint_fields(build_app, fresh_db):
    actor_id = f"actor-aa-25-{uuid4().hex[:8]}"
    tenant_id = "t-aa-25"
    _insert_actor(fresh_db, actor_id, tenant_id)
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-25-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "report_generation",
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/actor/{actor_id}/attribution",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    record = resp.json()["attribution_records"][0]
    assert record["actor_fingerprint"] is not None, "actor_fingerprint must be non-null"
    assert record["attribution_hash"] is not None, "attribution_hash must be non-null"
    assert record["event_hash"] is not None, "event_hash must be non-null"


def test_aa_26_attribution_record_fields_are_deterministic(build_app, fresh_db):
    actor_id = f"actor-aa-26-{uuid4().hex[:8]}"
    tenant_id = "t-aa-26"
    attr_id = f"attr-aa-26-{uuid4().hex[:6]}"
    _insert_actor(fresh_db, actor_id, tenant_id)
    _insert_attribution_record(
        fresh_db,
        attr_id,
        actor_id,
        tenant_id,
        "report_generation",
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    url = f"/actor-attribution/actor/{actor_id}/attribution"
    headers = {"X-API-Key": key}
    r1 = client.get(url, headers=headers)
    r2 = client.get(url, headers=headers)
    assert r1.status_code == 200 and r2.status_code == 200
    rec1 = r1.json()["attribution_records"][0]
    rec2 = r2.json()["attribution_records"][0]
    assert rec1["actor_fingerprint"] == rec2["actor_fingerprint"], (
        "actor_fingerprint must be deterministic across identical reads"
    )
    assert rec1["attribution_hash"] == rec2["attribution_hash"], (
        "attribution_hash must be deterministic"
    )
    assert rec1["event_hash"] == rec2["event_hash"], "event_hash must be deterministic"


def test_aa_27_attribution_chain_for_report_ordered_by_created_at_ascending(
    build_app, fresh_db
):
    actor_id = f"actor-aa-27-{uuid4().hex[:8]}"
    tenant_id = "t-aa-27"
    report_id = f"report-aa-27-{uuid4().hex[:8]}"
    _insert_actor(fresh_db, actor_id, tenant_id)
    # Insert in reverse chronological order to confirm DB ordering
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-27-c-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "report_approval",
        event_ref=report_id,
        event_ref_type="report",
        created_at=_NOW_3,
    )
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-27-a-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "report_generation",
        event_ref=report_id,
        event_ref_type="report",
        created_at=_NOW,
    )
    _insert_attribution_record(
        fresh_db,
        f"attr-aa-27-b-{uuid4().hex[:6]}",
        actor_id,
        tenant_id,
        "report_delivery",
        event_ref=report_id,
        event_ref_type="report",
        created_at=_NOW_2,
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("actor:read", tenant_id=tenant_id)
    resp = client.get(
        f"/actor-attribution/report/{report_id}/actor-chain",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    chain = resp.json()["chain"]
    assert len(chain) == 3, f"expected 3 records in chain, got {len(chain)}"
    timestamps = [r["created_at"] for r in chain]
    assert timestamps == sorted(timestamps), (
        f"chain must be ordered by created_at ascending; got {timestamps}"
    )
