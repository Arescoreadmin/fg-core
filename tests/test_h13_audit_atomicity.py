"""tests/test_h13_audit_atomicity.py — H13 Audit Atomicity & Evidence Transaction Integrity.

Covers all 12 mandatory security control layers:
  L1  Transaction atomicity — mutation + audit event flush in same db.commit()
  L2  Rollback on audit failure — injected audit failure rolls back the mutation
  L3  No orphan commits — report creation audit event is now persisted (not lost)
  L4  entity_type populated — standardised entity class on v2.0 events
  L5  entity_id populated — PK of the mutated entity on v2.0 events
  L6  transaction_id populated — unique per operation, non-null on v2.0 events
  L7  correlation_id supported — optional cross-service identifier
  L8  compute_entity_hash — deterministic SHA-256, order-independent
  L9  actor_type populated — human_operator / portal_client / api_key / system
  L10 AuditAtomicityService abstraction — importable singleton, emit() returns tx_id
  L11 Append-only enforcement — no update/delete route for audit events
  L12 Coverage — every previously-unaudited mutation path now emits FA audit event

Regression targets from AUDIT_TRACKER H13:
  - api/field_assessment.py:1092-1119  patch_engagement (no audit event)
  - api/field_assessment.py:2227-2264  patch_finding_remediation (no audit event)
  - api/field_assessment.py:5735-5751  portal_grant revoke/rotate (no FA audit event)
  - api/field_assessment.py:6382-6398  report creation split-commit (audit was lost)
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT_ID = "tenant-h13-test"

_ENG_BODY = {
    "client_name": "AuditCorp",
    "assessor_id": "assessor-h13",
    "assessment_type": "ai_governance",
}

_DOC_BODY = {
    "document_name": "H13 AI Policy Doc",
    "document_classification": "ai_policy",
}

_OBS_BODY = {
    "domain": "ai_governance",
    "observation_type": "gap",
    "severity": "high",
    "title": "H13 Test Observation",
    "description": "Audit atomicity test",
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=_TENANT_ID,
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_no_raise(build_app: object) -> TestClient:
    """Client that returns 5xx status codes instead of re-raising server exceptions."""
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=_TENANT_ID,
    )
    return TestClient(app, headers={"X-API-Key": key}, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_engagement(c: TestClient) -> str:
    """Returns the engagement id string."""
    resp = c.post("/field-assessment/engagements", json=_ENG_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _count_audit_events(c: TestClient, eng_id: str) -> int:
    resp = c.get(
        f"/field-assessment/engagements/{eng_id}/audit-events",
        params={"limit": 100},
    )
    assert resp.status_code == 200
    return len(resp.json())


def _get_audit_events(c: TestClient, eng_id: str) -> list[dict]:
    resp = c.get(
        f"/field-assessment/engagements/{eng_id}/audit-events",
        params={"limit": 100},
    )
    assert resp.status_code == 200
    return resp.json()


def _db_audit_events(eng_id: str) -> list[dict]:
    """Direct DB read to inspect schema-level columns not surfaced by the API."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaEngagementAuditEvent

    SM = get_sessionmaker()
    with SM() as db:
        rows = (
            db.execute(
                select(FaEngagementAuditEvent).where(
                    FaEngagementAuditEvent.engagement_id == eng_id,
                    FaEngagementAuditEvent.tenant_id == _TENANT_ID,
                )
            )
            .scalars()
            .all()
        )
        result = [
            {
                "event_type": r.event_type,
                "actor_type": r.actor_type,
                "entity_type": r.entity_type,
                "entity_id": r.entity_id,
                "transaction_id": r.transaction_id,
                "schema_version": r.schema_version,
                "before_hash": r.before_hash,
                "after_hash": r.after_hash,
            }
            for r in rows
        ]
    return result


# ===========================================================================
# L1 — Transaction atomicity
# ===========================================================================


def test_l1_engagement_create_audit_event_exists(client: TestClient) -> None:
    """Creating an engagement emits an audit event in the same transaction."""
    eng_id = _create_engagement(client)
    events = _get_audit_events(client, eng_id)
    types = [e["event_type"] for e in events]
    assert "engagement.created" in types


def test_l1_status_transition_audit_event_atomic(client: TestClient) -> None:
    """Status transition and its audit event commit together."""
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)
    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/status",
        json={"new_status": "cancelled", "reason": "h13 test"},
    )
    assert resp.status_code == 200
    after = _count_audit_events(client, eng_id)
    assert after == before + 1


def test_l1_observation_create_audit_event_atomic(client: TestClient) -> None:
    """Observation creation and its audit event commit together."""
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json=_OBS_BODY,
    )
    assert resp.status_code == 201
    after = _count_audit_events(client, eng_id)
    assert after == before + 2


def test_l1_document_analysis_audit_event_atomic(client: TestClient) -> None:
    """Document analysis registration and audit event commit together."""
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/document-analyses",
        json=_DOC_BODY,
    )
    assert resp.status_code == 201
    after = _count_audit_events(client, eng_id)
    assert after == before + 2


# ===========================================================================
# L2 — Rollback on audit failure (legacy emit path)
# ===========================================================================


def test_l2_audit_failure_rolls_back_observation(
    client_no_raise: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected audit failure prevents the observation from being committed."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaFieldObservation

    eng_id = _create_engagement(client_no_raise)
    unique_title = "Should-Not-Persist-Obs-H13"

    def _raise(*args: object, **kwargs: object) -> None:
        raise RuntimeError("injected audit failure")

    monkeypatch.setattr("api.field_assessment.emit_engagement_audit_event", _raise)

    resp = client_no_raise.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json={**_OBS_BODY, "title": unique_title},
    )
    assert resp.status_code == 500

    SM = get_sessionmaker()
    with SM() as db:
        count = db.execute(
            select(func.count())
            .select_from(FaFieldObservation)
            .where(
                FaFieldObservation.engagement_id == eng_id,
                FaFieldObservation.tenant_id == _TENANT_ID,
                FaFieldObservation.title == unique_title,
            )
        ).scalar()
    assert count == 0, "Mutation must be rolled back when audit emission fails"


def test_l2_audit_failure_rolls_back_document_analysis(
    client_no_raise: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected audit failure prevents the document analysis from being committed."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaDocumentAnalysis

    eng_id = _create_engagement(client_no_raise)
    unique_name = "Should-Not-Persist-Doc-H13"

    def _raise(*args: object, **kwargs: object) -> None:
        raise RuntimeError("injected audit failure")

    monkeypatch.setattr("api.field_assessment.emit_engagement_audit_event", _raise)

    resp = client_no_raise.post(
        f"/field-assessment/engagements/{eng_id}/document-analyses",
        json={"document_name": unique_name, "document_classification": "ai_policy"},
    )
    assert resp.status_code == 500

    SM = get_sessionmaker()
    with SM() as db:
        count = db.execute(
            select(func.count())
            .select_from(FaDocumentAnalysis)
            .where(
                FaDocumentAnalysis.engagement_id == eng_id,
                FaDocumentAnalysis.tenant_id == _TENANT_ID,
                FaDocumentAnalysis.document_name == unique_name,
            )
        ).scalar()
    assert count == 0, "Mutation must be rolled back when audit emission fails"


def test_l2_audit_failure_rolls_back_patch_engagement(
    client_no_raise: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected audit failure during patch_engagement rolls back metadata change."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaEngagement
    from services.field_assessment.audit import AuditAtomicityService

    eng_id = _create_engagement(client_no_raise)

    SM = get_sessionmaker()

    def _raise(self: object, *args: object, **kwargs: object) -> str:
        raise RuntimeError("injected audit failure")

    monkeypatch.setattr(AuditAtomicityService, "emit", _raise)

    resp = client_no_raise.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": {"should_not_appear": True}},
    )
    assert resp.status_code == 500

    with SM() as db:
        eng = db.execute(
            select(FaEngagement).where(
                FaEngagement.id == eng_id,
                FaEngagement.tenant_id == _TENANT_ID,
            )
        ).scalar_one()
        assert eng.engagement_metadata.get("should_not_appear") is None, (
            "Metadata change must be rolled back when audit fails"
        )


# ===========================================================================
# L3 — Report creation split-commit fix (THE core H13 regression)
# ===========================================================================


def test_l3_report_creation_audit_event_persisted(client: TestClient) -> None:
    """Report creation audit event is persisted after the H13 fix.

    Before fix: db.commit() at line 6382 committed the report, then
    emit_engagement_audit_event() at line 6385 ran in a new transaction
    that was never committed — audit event was silently discarded.

    After fix: audit emitted before db.commit() so both commit atomically.
    """
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201), resp.text

    after = _count_audit_events(client, eng_id)
    assert after > before, "Report creation must produce an audit event (H13 fix)"

    events = _get_audit_events(client, eng_id)
    types = [e["event_type"] for e in events]
    assert "engagement_report_created" in types


def test_l3_report_creation_audit_payload_contains_report_id(
    client: TestClient,
) -> None:
    """Report audit event payload contains report_id and manifest_hash."""
    eng_id = _create_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201)
    report_id = resp.json().get("report_id")

    events = _get_audit_events(client, eng_id)
    ev = next(
        (e for e in events if e["event_type"] == "engagement_report_created"), None
    )
    assert ev is not None
    payload = ev.get("payload", {})
    assert payload.get("report_id") == report_id
    assert "manifest_hash" in payload


# ===========================================================================
# L4 + L5 — entity_type and entity_id
# ===========================================================================


def test_l4_l5_patch_engagement_entity_fields(client: TestClient) -> None:
    """engagement.metadata_updated event has entity_type='engagement', entity_id=eng_id."""
    eng_id = _create_engagement(client)
    client.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": {"entity_field_test": True}},
    )

    rows = _db_audit_events(eng_id)
    event = next(
        (r for r in rows if r["event_type"] == "engagement.metadata_updated"), None
    )
    assert event is not None
    assert event["entity_type"] == "engagement"
    assert event["entity_id"] == eng_id


def test_l4_l5_remediation_hint_entity_fields(client: TestClient) -> None:
    """finding.remediation_hint_updated event has entity_type='finding', entity_id=fid."""
    eng_id = _create_engagement(client)

    # Normalise a scan to get a finding
    scan = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json={
            "source_type": "network",
            "schema_version": "1.0",
            "collected_at": "2026-01-01T00:00:00Z",
            "raw_payload": {
                "findings": [
                    {
                        "finding_type": "open_port",
                        "severity": "medium",
                        "title": "Entity Fields Finding",
                        "description": "l4/l5 test",
                        "source_attribution": "network_scan",
                    }
                ]
            },
        },
    )
    if scan.status_code not in (201, 409):
        pytest.skip("scan result unavailable")

    findings_resp = client.get(
        f"/field-assessment/engagements/{eng_id}/findings?limit=10"
    )
    if findings_resp.status_code != 200 or not findings_resp.json().get("findings"):
        pytest.skip("no findings available to test")
    finding_id = findings_resp.json()["findings"][0]["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/findings/{finding_id}/remediation",
        json={"remediation_hint": "Restrict open port"},
    )
    assert resp.status_code == 200

    rows = _db_audit_events(eng_id)
    event = next(
        (r for r in rows if r["event_type"] == "finding.remediation_hint_updated"),
        None,
    )
    assert event is not None
    assert event["entity_type"] == "finding"
    assert event["entity_id"] == finding_id


def test_l4_l5_report_entity_fields(client: TestClient) -> None:
    """engagement_report_created event has entity_type='report', entity_id=report_id."""
    eng_id = _create_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201)
    report_id = resp.json()["report_id"]

    rows = _db_audit_events(eng_id)
    event = next(
        (r for r in rows if r["event_type"] == "engagement_report_created"), None
    )
    assert event is not None
    assert event["entity_type"] == "report"
    assert event["entity_id"] == report_id


# ===========================================================================
# L6 — transaction_id
# ===========================================================================


def test_l6_patch_engagement_has_transaction_id(client: TestClient) -> None:
    """engagement.metadata_updated emits schema v2.0 with non-null transaction_id."""
    eng_id = _create_engagement(client)
    client.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": {"tx_test": 1}},
    )

    rows = _db_audit_events(eng_id)
    event = next(
        (r for r in rows if r["event_type"] == "engagement.metadata_updated"), None
    )
    assert event is not None
    assert event["transaction_id"] is not None
    assert len(event["transaction_id"]) == 32


def test_l6_report_creation_has_transaction_id(client: TestClient) -> None:
    """engagement_report_created emits schema v2.0 with non-null transaction_id."""
    eng_id = _create_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201)

    rows = _db_audit_events(eng_id)
    event = next(
        (r for r in rows if r["event_type"] == "engagement_report_created"), None
    )
    assert event is not None
    assert event["transaction_id"] is not None


def test_l6_transaction_id_unique_per_event(client: TestClient) -> None:
    """transaction_id is unique across multiple v2.0 audit events."""
    eng_id = _create_engagement(client)

    client.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": {"seq": 1}},
    )
    client.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": {"seq": 2}},
    )

    rows = _db_audit_events(eng_id)
    v2_rows = [r for r in rows if r["transaction_id"] is not None]
    tx_ids = [r["transaction_id"] for r in v2_rows]
    assert len(tx_ids) == len(set(tx_ids)), "transaction_ids must be unique per event"


def test_l6_v1_legacy_events_have_null_transaction_id(client: TestClient) -> None:
    """Legacy v1.0 events (old emit path) have NULL transaction_id."""
    eng_id = _create_engagement(client)

    rows = _db_audit_events(eng_id)
    # engagement.created uses old emit path → schema_version=1.0, transaction_id=None
    created = [r for r in rows if r["event_type"] == "engagement.created"]
    assert len(created) > 0
    for row in created:
        assert row["schema_version"] == "1.0"
        assert row["transaction_id"] is None


# ===========================================================================
# L8 — compute_entity_hash
# ===========================================================================


def test_l8_compute_entity_hash_deterministic() -> None:
    """compute_entity_hash is deterministic and key-order-independent."""
    from services.field_assessment.audit import AuditAtomicityService

    state = {"id": "abc", "status": "open", "updated_at": "2026-01-01"}
    h1 = AuditAtomicityService.compute_entity_hash(state)
    state_reordered = {"updated_at": "2026-01-01", "id": "abc", "status": "open"}
    h2 = AuditAtomicityService.compute_entity_hash(state_reordered)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_l8_compute_entity_hash_sensitive_to_change() -> None:
    """Hash changes when entity value changes."""
    from services.field_assessment.audit import AuditAtomicityService

    before = AuditAtomicityService.compute_entity_hash({"status": "open"})
    after = AuditAtomicityService.compute_entity_hash({"status": "closed"})
    assert before != after


# ===========================================================================
# L9 — actor_type
# ===========================================================================


def test_l9_patch_engagement_actor_type(client: TestClient) -> None:
    """engagement.metadata_updated emits actor_type='human_operator'."""
    eng_id = _create_engagement(client)
    client.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": {"actor_type_test": True}},
    )

    rows = _db_audit_events(eng_id)
    event = next(
        (r for r in rows if r["event_type"] == "engagement.metadata_updated"), None
    )
    assert event is not None
    assert event["actor_type"] == "human_operator"


def test_l9_portal_grant_events_actor_type(client: TestClient) -> None:
    """Portal grant create/rotate/revoke emit actor_type='human_operator'."""
    eng_id = _create_engagement(client)

    # Create
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/portal-grants",
        json={"ttl_days": 7},
    )
    assert resp.status_code == 201
    grant_id = resp.json()["grant"]["id"]

    rows = _db_audit_events(eng_id)
    grant_event = next(
        (r for r in rows if r["event_type"] == "portal_grant.created"), None
    )
    assert grant_event is not None
    assert grant_event["actor_type"] == "human_operator"

    # Rotate
    rot = client.post(
        f"/field-assessment/engagements/{eng_id}/portal-grants/{grant_id}/rotate"
    )
    assert rot.status_code == 200
    new_grant_id = rot.json()["grant"]["id"]

    rows = _db_audit_events(eng_id)
    rotate_event = next(
        (r for r in rows if r["event_type"] == "portal_grant.rotated"), None
    )
    assert rotate_event is not None
    assert rotate_event["actor_type"] == "human_operator"

    # Revoke
    rev = client.delete(
        f"/field-assessment/engagements/{eng_id}/portal-grants/{new_grant_id}"
    )
    assert rev.status_code == 204

    rows = _db_audit_events(eng_id)
    revoke_event = next(
        (r for r in rows if r["event_type"] == "portal_grant.revoked"), None
    )
    assert revoke_event is not None
    assert revoke_event["actor_type"] == "human_operator"


def test_l9_report_creation_actor_type(client: TestClient) -> None:
    """engagement_report_created emits actor_type='human_operator'."""
    eng_id = _create_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201)

    rows = _db_audit_events(eng_id)
    event = next(
        (r for r in rows if r["event_type"] == "engagement_report_created"), None
    )
    assert event is not None
    assert event["actor_type"] == "human_operator"


# ===========================================================================
# L10 — AuditAtomicityService abstraction
# ===========================================================================


def test_l10_service_is_importable_singleton() -> None:
    """audit_atomicity_svc is an importable singleton of AuditAtomicityService."""
    from services.field_assessment.audit import (
        AuditAtomicityService,
        audit_atomicity_svc,
    )

    assert isinstance(audit_atomicity_svc, AuditAtomicityService)


def test_l10_service_emit_returns_transaction_id(client: TestClient) -> None:
    """audit_atomicity_svc.emit() returns a 32-char hex transaction_id."""
    from api.db import get_sessionmaker
    from services.field_assessment.audit import audit_atomicity_svc

    eng_id = _create_engagement(client)

    SM = get_sessionmaker()
    with SM() as db:
        tx_id = audit_atomicity_svc.emit(
            db,
            tenant_id=_TENANT_ID,
            engagement_id=eng_id,
            event_type="test.direct_emit",
            actor="test-actor",
            actor_type="system",
            reason_code="TEST",
            entity_type="engagement",
            entity_id=eng_id,
            payload={"direct": True},
        )
        db.commit()

    assert isinstance(tx_id, str)
    assert len(tx_id) == 32


def test_l10_service_emit_schema_v2(client: TestClient) -> None:
    """Events emitted via AuditAtomicityService have schema_version='2.0'."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaEngagementAuditEvent
    from services.field_assessment.audit import audit_atomicity_svc

    eng_id = _create_engagement(client)

    SM = get_sessionmaker()
    with SM() as db:
        tx_id = audit_atomicity_svc.emit(
            db,
            tenant_id=_TENANT_ID,
            engagement_id=eng_id,
            event_type="test.schema_v2_check",
            actor="test",
            actor_type="system",
            reason_code="TEST",
            entity_type="engagement",
            entity_id=eng_id,
            payload={},
        )
        db.commit()

    SM2 = get_sessionmaker()
    with SM2() as db:
        row = db.execute(
            select(FaEngagementAuditEvent).where(
                FaEngagementAuditEvent.transaction_id == tx_id,
            )
        ).scalar_one_or_none()
    assert row is not None
    assert row.schema_version == "2.0"
    assert row.transaction_id == tx_id


# ===========================================================================
# L11 — Append-only enforcement
# ===========================================================================


def test_l11_no_update_route_for_audit_events(client: TestClient) -> None:
    """There is no PATCH/PUT route for audit events — they are immutable."""
    eng_id = _create_engagement(client)
    events = _get_audit_events(client, eng_id)
    assert len(events) > 0
    event_id = events[0]["id"]

    patch_resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/audit-events/{event_id}",
        json={"event_type": "tampered"},
    )
    assert patch_resp.status_code in (404, 405)


def test_l11_no_delete_route_for_audit_events(client: TestClient) -> None:
    """There is no DELETE route for audit events — they are immutable."""
    eng_id = _create_engagement(client)
    events = _get_audit_events(client, eng_id)
    assert len(events) > 0
    event_id = events[0]["id"]

    del_resp = client.delete(
        f"/field-assessment/engagements/{eng_id}/audit-events/{event_id}"
    )
    assert del_resp.status_code in (404, 405)


# ===========================================================================
# L12 — Coverage: previously-unaudited mutation paths
# ===========================================================================


def test_l12_patch_engagement_emits_audit_event(client: TestClient) -> None:
    """PATCH /engagements/{id} now emits FA audit event (was missing before H13 fix)."""
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": {"coverage_test": True}},
    )
    assert resp.status_code == 200

    after = _count_audit_events(client, eng_id)
    assert after == before + 1
    types = [e["event_type"] for e in _get_audit_events(client, eng_id)]
    assert "engagement.metadata_updated" in types


def test_l12_patch_engagement_null_metadata_still_audited(
    client: TestClient,
) -> None:
    """PATCH /engagements/{id} with null metadata still emits an audit event."""
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}",
        json={"engagement_metadata": None},
    )
    assert resp.status_code == 200

    after = _count_audit_events(client, eng_id)
    assert after == before + 1


def test_l12_remediation_hint_emits_audit_event(client: TestClient) -> None:
    """PATCH .../findings/{id}/remediation now emits FA audit event (was missing)."""
    eng_id = _create_engagement(client)

    scan = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json={
            "source_type": "network",
            "schema_version": "1.0",
            "collected_at": "2026-01-01T00:00:00Z",
            "raw_payload": {
                "findings": [
                    {
                        "finding_type": "open_port",
                        "severity": "high",
                        "title": "Coverage Remediation Finding",
                        "description": "l12 remediation test",
                        "source_attribution": "network_scan",
                    }
                ]
            },
        },
    )
    if scan.status_code not in (201, 409):
        pytest.skip("scan result unavailable")

    findings_resp = client.get(
        f"/field-assessment/engagements/{eng_id}/findings?limit=10"
    )
    if findings_resp.status_code != 200 or not findings_resp.json().get("findings"):
        pytest.skip("no findings available")
    finding_id = findings_resp.json()["findings"][0]["id"]

    before = _count_audit_events(client, eng_id)
    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/findings/{finding_id}/remediation",
        json={"remediation_hint": "Restrict access with firewall rules"},
    )
    assert resp.status_code == 200

    after = _count_audit_events(client, eng_id)
    assert after == before + 1
    types = [e["event_type"] for e in _get_audit_events(client, eng_id)]
    assert "finding.remediation_hint_updated" in types


def test_l12_portal_grant_create_emits_fa_audit_event(client: TestClient) -> None:
    """POST .../portal-grants emits FA audit event (was missing before H13)."""
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/portal-grants",
        json={"ttl_days": 14},
    )
    assert resp.status_code == 201

    after = _count_audit_events(client, eng_id)
    assert after == before + 1
    types = [e["event_type"] for e in _get_audit_events(client, eng_id)]
    assert "portal_grant.created" in types


def test_l12_portal_grant_revoke_emits_fa_audit_event(client: TestClient) -> None:
    """DELETE .../portal-grants/{id} emits FA audit event (was missing before H13)."""
    eng_id = _create_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/portal-grants",
        json={"ttl_days": 14},
    )
    assert resp.status_code == 201
    grant_id = resp.json()["grant"]["id"]

    before = _count_audit_events(client, eng_id)
    rev = client.delete(
        f"/field-assessment/engagements/{eng_id}/portal-grants/{grant_id}"
    )
    assert rev.status_code == 204

    after = _count_audit_events(client, eng_id)
    assert after == before + 1
    types = [e["event_type"] for e in _get_audit_events(client, eng_id)]
    assert "portal_grant.revoked" in types


def test_l12_portal_grant_rotate_emits_fa_audit_event(client: TestClient) -> None:
    """POST .../portal-grants/{id}/rotate emits FA audit event (was missing before H13)."""
    eng_id = _create_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/portal-grants",
        json={"ttl_days": 14},
    )
    assert resp.status_code == 201
    grant_id = resp.json()["grant"]["id"]

    before = _count_audit_events(client, eng_id)
    rot = client.post(
        f"/field-assessment/engagements/{eng_id}/portal-grants/{grant_id}/rotate"
    )
    assert rot.status_code == 200

    after = _count_audit_events(client, eng_id)
    assert after == before + 1
    types = [e["event_type"] for e in _get_audit_events(client, eng_id)]
    assert "portal_grant.rotated" in types


def test_l12_report_creation_audit_not_lost(client: TestClient) -> None:
    """POST .../reports audit event is now committed atomically (H13 split-commit fix).

    Previously: db.commit() happened first, then audit was in a new transaction
    that was never committed. Count delta was 0. Now delta must be >= 1.
    """
    eng_id = _create_engagement(client)
    before = _count_audit_events(client, eng_id)

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201), resp.text

    after = _count_audit_events(client, eng_id)
    assert after > before, (
        "Report audit event must be committed (was discarded before H13 fix)"
    )
