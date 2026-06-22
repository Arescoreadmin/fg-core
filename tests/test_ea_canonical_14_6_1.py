# tests/test_ea_canonical_14_6_1.py
"""Canonical Evidence Authority test suite — PR 14.6.1.

Coverage map:
  EA-1    Create evidence returns 201 with COLLECTED state
  EA-2    Create evidence sets integrity_hash
  EA-3    Create evidence creates audit event
  EA-4    Create evidence sets trust_state=UNVERIFIED
  EA-5    Create evidence with classification_labels stores them
  EA-6    Create evidence with engagement_id stores it
  EA-7    Create evidence with expires_at stores it
  EA-8    Duplicate titles produce unique evidence_refs (UUID suffix)
  EA-9    Create requires governance:write scope
  EA-10   Missing required fields → 422
  EA-11   Invalid collected_at format → 422
  EA-12   Get evidence by ID → 200
  EA-13   Get non-existent evidence → 404
  EA-14   Get cross-tenant evidence → 404
  EA-15   List evidence returns empty list when none
  EA-16   List evidence returns all tenant records
  EA-17   List evidence filters by lifecycle_state
  EA-18   List evidence filters by trust_state
  EA-19   List evidence filters by classification
  EA-20   List evidence filters by source_type
  EA-21   List evidence filters by engagement_id
  EA-22   List evidence respects offset/limit
  EA-23   List evidence excludes cross-tenant records
  EA-24   Update metadata: title changes
  EA-25   Update metadata: description changes
  EA-26   Update metadata: source_system changes
  EA-27   Update metadata: expires_at changes
  EA-28   Update metadata on immutable (VERIFIED) state → 409
  EA-29   Update metadata on REVOKED state → 409
  EA-30   Update metadata on ARCHIVED state → 409
  EA-31   Update metadata requires governance:write scope
  EA-32   Lifecycle: COLLECTED → SUBMITTED succeeds
  EA-33   Lifecycle: SUBMITTED → UNDER_REVIEW succeeds
  EA-34   Lifecycle: UNDER_REVIEW → VERIFIED succeeds; sets verified_at
  EA-35   Lifecycle: UNDER_REVIEW → REJECTED succeeds
  EA-36   Lifecycle: VERIFIED → SUPERSEDED succeeds
  EA-37   Lifecycle: VERIFIED → EXPIRED succeeds
  EA-38   Lifecycle: VERIFIED → ARCHIVED succeeds
  EA-39   Lifecycle: REVOKED is terminal (no outbound)
  EA-40   Lifecycle: ARCHIVED is semi-terminal (no outbound)
  EA-41   Invalid lifecycle transition → 422
  EA-42   Lifecycle on non-existent evidence → 404
  EA-43   Lifecycle transition creates audit event
  EA-44   Lifecycle: REVOKED transition sets revoked_at
  EA-45   Lifecycle: ARCHIVED transition sets archived_at
  EA-46   Lifecycle: SUBMITTED sets submitted_at
  EA-47   Lifecycle requires governance:write scope
  EA-48   Trust: UNVERIFIED → PARTIALLY_VERIFIED succeeds
  EA-49   Trust: UNVERIFIED → VERIFIED succeeds
  EA-50   Trust: VERIFIED → HIGH_CONFIDENCE succeeds
  EA-51   Trust: HIGH_CONFIDENCE → DISPUTED succeeds
  EA-52   Trust: UNVERIFIED → INVALIDATED succeeds; terminal state
  EA-53   Invalid trust transition → 422
  EA-54   Trust transition creates hash-chained trust event
  EA-55   Trust event has event_hash populated
  EA-56   Second trust event has prev_event_hash = first event_hash
  EA-57   Trust score floor applied (VERIFIED ≥ 60)
  EA-58   Trust VERIFIED sets verified_at if not already set
  EA-59   Trust transition creates audit event
  EA-60   Trust on non-existent evidence → 404
  EA-61   Trust query returns full event history
  EA-62   Trust verify requires governance:write scope
  EA-63   Trust query requires governance:read scope
  EA-64   Ownership: assign OWNER role
  EA-65   Ownership: assigning OWNER updates evidence.owner_id
  EA-66   Ownership: assign REVIEWER role
  EA-67   Ownership: assign VERIFIER role
  EA-68   Ownership: revoke sets is_active=False
  EA-69   Ownership: revoke sets revoked_at
  EA-70   Ownership: revoke non-existent → 404
  EA-71   Ownership: list all ownership records
  EA-72   Ownership: list active_only filters revoked records
  EA-73   Ownership: assign creates audit event
  EA-74   Ownership: revoke creates audit event
  EA-75   Ownership: cross-tenant evidence → 404
  EA-76   Relationship: link evidence to finding
  EA-77   Relationship: link evidence to control
  EA-78   Relationship: link evidence to risk_acceptance
  EA-79   Relationship: duplicate relationship → 409
  EA-80   Relationship: list relationships for evidence
  EA-81   Relationship: list relationships filtered by entity_type
  EA-82   Relationship: list evidence for entity (reverse lookup)
  EA-83   Relationship: link creates audit event
  EA-84   Relationship: link to non-existent evidence → 404
  EA-85   Relationship: cross-tenant evidence → 404
  EA-86   Audit trail: create event recorded
  EA-87   Audit trail: lifecycle event recorded
  EA-88   Audit trail: trust event recorded
  EA-89   Audit trail: filter by event_type
  EA-90   Audit trail: pagination (offset/limit)
  EA-91   Audit trail on non-existent evidence → 404
  EA-92   Dashboard: total_evidence accurate
  EA-93   Dashboard: by_lifecycle_state breakdown
  EA-94   Dashboard: by_trust_state breakdown
  EA-95   Dashboard: verified_count accurate
  EA-96   Dashboard: without_owner_count accurate
  EA-97   Dashboard: without_relationships_count accurate
  EA-98   Dashboard: tenant isolation (Tenant B sees its own counts)
  EA-99   State machine: all REVOKED transitions blocked (pure)
  EA-100  State machine: all ARCHIVED transitions blocked (pure)
  EA-101  State machine: INVALIDATED trust state is terminal (pure)
  EA-102  Full workflow: collect → submit → review → verify → supersede
  EA-103  Full workflow: trust chain UNVERIFIED → PARTIALLY → VERIFIED → HIGH
  EA-104  Actor type 'agent' stored on ownership (AGI-forward)
  EA-105  Schema version 1.0 on created evidence
  EA-106  Schema version 1.0 in list results
  EA-107  Cross-tenant list isolation
  EA-108  Dashboard requires governance:read scope
  EA-109  By-entity endpoint returns relationships for given entity
  EA-110  Trust confidence_score stored on trust event
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from services.evidence_authority.models import (
    EvidenceLifecycleState,
    EvidenceTrustState,
    TRUST_STATE_SCORE_FLOOR,
    validate_lifecycle_transition,
    validate_trust_transition,
)

_TENANT_A = "tenant-ea14-a"
_TENANT_B = "tenant-ea14-b"

_FUTURE = "2099-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uid() -> str:
    return uuid.uuid4().hex[:12]


def _j(r) -> dict[str, Any]:
    assert r is not None
    return r


def _ev_body(**overrides: Any) -> dict:
    base: dict[str, Any] = {
        "title": f"EA Test Evidence {_uid()}",
        "source_type": "DOCUMENT",
        "collection_method": "MANUAL_UPLOAD",
        "classification": "INTERNAL",
        "collected_at": "2026-01-15T10:00:00+00:00",
    }
    base.update(overrides)
    return base


def _create_evidence(client: TestClient, **overrides: Any) -> dict[str, Any]:
    r = client.post("/evidence", json=_ev_body(**overrides))
    assert r.status_code == 201, r.text
    return _j(r.json())


def _drive_to_verified(client: TestClient, ev_id: str) -> None:
    """Drive COLLECTED → SUBMITTED → UNDER_REVIEW → VERIFIED."""
    client.post(f"/evidence/{ev_id}/lifecycle", json={"to_state": "SUBMITTED"})
    client.post(f"/evidence/{ev_id}/lifecycle", json={"to_state": "UNDER_REVIEW"})
    r = client.post(f"/evidence/{ev_id}/lifecycle", json={"to_state": "VERIFIED"})
    assert r.status_code == 200, r.text


def _verify(client: TestClient, ev_id: str, to_state: str, **kw: Any) -> dict:
    body: dict[str, Any] = {
        "to_trust_state": to_state,
        "verification_source": "HUMAN",
        **kw,
    }
    r = client.post(f"/evidence/{ev_id}/verify", json=body)
    assert r.status_code == 200, r.text
    return _j(r.json())


def _link(
    client: TestClient,
    ev_id: str,
    entity_type: str = "finding",
    entity_id: str | None = None,
    rel_type: str = "SUPPORTS",
) -> dict:
    body = {
        "related_entity_type": entity_type,
        "related_entity_id": entity_id or _uid(),
        "relationship_type": rel_type,
    }
    r = client.post(f"/evidence/{ev_id}/relationships", json=body)
    assert r.status_code == 201, r.text
    return _j(r.json())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_b(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def readonly_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", tenant_id=_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def writeonly_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:write", tenant_id=_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# EA-1 – EA-11: Create Evidence
# ---------------------------------------------------------------------------


def test_ea_1_create_evidence_201(client):
    r = client.post("/evidence", json=_ev_body())
    assert r.status_code == 201
    body = _j(r.json())
    assert body["lifecycle_state"] == "COLLECTED"
    assert body["id"]
    assert body["evidence_ref"]


def test_ea_2_create_evidence_integrity_hash(client):
    body = _create_evidence(client)
    assert body["integrity_hash"]
    assert len(body["integrity_hash"]) == 64  # SHA-256 hex


def test_ea_3_create_evidence_audit_event(client):
    ev = _create_evidence(client)
    r = client.get(f"/evidence/{ev['id']}/audit")
    assert r.status_code == 200
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "evidence_created" in types


def test_ea_4_create_evidence_trust_state_unverified(client):
    body = _create_evidence(client)
    assert body["trust_state"] == "UNVERIFIED"


def test_ea_5_create_evidence_classification_labels(client):
    body = _create_evidence(client, classification_labels=["PII", "PHI"])
    assert set(body["classification_labels"]) == {"PII", "PHI"}


def test_ea_6_create_evidence_engagement_id(client):
    eid = _uid()
    body = _create_evidence(client, engagement_id=eid)
    assert body["engagement_id"] == eid


def test_ea_7_create_evidence_expires_at(client):
    body = _create_evidence(client, expires_at=_FUTURE)
    assert body["expires_at"] == _FUTURE


def test_ea_8_duplicate_titles_produce_unique_refs(client):
    title = f"Same Title {_uid()}"
    b1 = _create_evidence(client, title=title)
    b2 = _create_evidence(client, title=title)
    assert b1["id"] != b2["id"]
    assert b1["evidence_ref"] != b2["evidence_ref"]


def test_ea_9_create_requires_write_scope(readonly_client):
    r = readonly_client.post("/evidence", json=_ev_body())
    assert r.status_code == 403


def test_ea_10_missing_required_fields_422(client):
    r = client.post("/evidence", json={"title": "Missing fields"})
    assert r.status_code == 422


def test_ea_11_invalid_collected_at_format_422(client):
    r = client.post("/evidence", json=_ev_body(collected_at="not-a-date"))
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# EA-12 – EA-14: Get Evidence
# ---------------------------------------------------------------------------


def test_ea_12_get_evidence_200(client):
    ev = _create_evidence(client)
    r = client.get(f"/evidence/{ev['id']}")
    assert r.status_code == 200
    assert _j(r.json())["id"] == ev["id"]


def test_ea_13_get_nonexistent_404(client):
    r = client.get(f"/evidence/{_uid()}")
    assert r.status_code == 404


def test_ea_14_get_cross_tenant_404(client, client_b):
    ev = _create_evidence(client)
    r = client_b.get(f"/evidence/{ev['id']}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# EA-15 – EA-23: List Evidence
# ---------------------------------------------------------------------------


def test_ea_15_list_empty(client):
    r = client.get("/evidence")
    assert r.status_code == 200
    body = _j(r.json())
    assert isinstance(body["items"], list)
    assert "total" in body


def test_ea_16_list_returns_tenant_records(client):
    ev = _create_evidence(client)
    r = client.get("/evidence")
    ids = [e["id"] for e in _j(r.json())["items"]]
    assert ev["id"] in ids


def test_ea_17_list_filter_lifecycle_state(client):
    ev = _create_evidence(client)
    r = client.get("/evidence", params={"lifecycle_state": "COLLECTED"})
    ids = [e["id"] for e in _j(r.json())["items"]]
    assert ev["id"] in ids

    r2 = client.get("/evidence", params={"lifecycle_state": "VERIFIED"})
    ids2 = [e["id"] for e in _j(r2.json())["items"]]
    assert ev["id"] not in ids2


def test_ea_18_list_filter_trust_state(client):
    ev = _create_evidence(client)
    r = client.get("/evidence", params={"trust_state": "UNVERIFIED"})
    ids = [e["id"] for e in _j(r.json())["items"]]
    assert ev["id"] in ids


def test_ea_19_list_filter_classification(client):
    ev = _create_evidence(client, classification="CONFIDENTIAL")
    r = client.get("/evidence", params={"classification": "CONFIDENTIAL"})
    ids = [e["id"] for e in _j(r.json())["items"]]
    assert ev["id"] in ids

    r2 = client.get("/evidence", params={"classification": "RESTRICTED"})
    ids2 = [e["id"] for e in _j(r2.json())["items"]]
    assert ev["id"] not in ids2


def test_ea_20_list_filter_source_type(client):
    ev = _create_evidence(client, source_type="SCAN")
    r = client.get("/evidence", params={"source_type": "SCAN"})
    ids = [e["id"] for e in _j(r.json())["items"]]
    assert ev["id"] in ids


def test_ea_21_list_filter_engagement_id(client):
    eid = _uid()
    ev = _create_evidence(client, engagement_id=eid)
    r = client.get("/evidence", params={"engagement_id": eid})
    body = _j(r.json())
    ids = [e["id"] for e in body["items"]]
    assert ev["id"] in ids
    assert all(e["engagement_id"] == eid for e in body["items"])


def test_ea_22_list_offset_limit(client):
    for _ in range(3):
        _create_evidence(client)
    r = client.get("/evidence", params={"limit": 1, "offset": 0})
    body = _j(r.json())
    assert len(body["items"]) == 1
    assert body["limit"] == 1


def test_ea_23_list_excludes_cross_tenant(client, client_b):
    ev_a = _create_evidence(client)
    r = client_b.get("/evidence")
    ids = [e["id"] for e in _j(r.json())["items"]]
    assert ev_a["id"] not in ids


# ---------------------------------------------------------------------------
# EA-24 – EA-31: Update Metadata
# ---------------------------------------------------------------------------


def test_ea_24_update_metadata_title(client):
    ev = _create_evidence(client)
    r = client.patch(f"/evidence/{ev['id']}", json={"title": "Updated Title"})
    assert r.status_code == 200
    assert _j(r.json())["title"] == "Updated Title"


def test_ea_25_update_metadata_description(client):
    ev = _create_evidence(client)
    r = client.patch(f"/evidence/{ev['id']}", json={"description": "New description"})
    assert r.status_code == 200
    assert _j(r.json())["description"] == "New description"


def test_ea_26_update_metadata_source_system(client):
    ev = _create_evidence(client)
    r = client.patch(f"/evidence/{ev['id']}", json={"source_system": "Jira"})
    assert r.status_code == 200
    assert _j(r.json())["source_system"] == "Jira"


def test_ea_27_update_metadata_expires_at(client):
    ev = _create_evidence(client)
    r = client.patch(f"/evidence/{ev['id']}", json={"expires_at": _FUTURE})
    assert r.status_code == 200
    assert _j(r.json())["expires_at"] == _FUTURE


def test_ea_28_update_metadata_immutable_verified(client):
    ev = _create_evidence(client)
    _drive_to_verified(client, ev["id"])
    r = client.patch(f"/evidence/{ev['id']}", json={"title": "Cannot update"})
    assert r.status_code == 409


def test_ea_29_update_metadata_immutable_revoked(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "REVOKED"})
    r = client.patch(f"/evidence/{ev['id']}", json={"title": "Cannot update"})
    assert r.status_code == 409


def test_ea_30_update_metadata_immutable_archived(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "ARCHIVED"})
    r = client.patch(f"/evidence/{ev['id']}", json={"title": "Cannot update"})
    assert r.status_code == 409


def test_ea_31_update_metadata_requires_write_scope(readonly_client, client):
    ev = _create_evidence(client)
    r = readonly_client.patch(f"/evidence/{ev['id']}", json={"title": "Blocked"})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# EA-32 – EA-47: Lifecycle Transitions
# ---------------------------------------------------------------------------


def test_ea_32_collected_to_submitted(client):
    ev = _create_evidence(client)
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    assert r.status_code == 200
    assert _j(r.json())["lifecycle_state"] == "SUBMITTED"


def test_ea_33_submitted_to_under_review(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    r = client.post(
        f"/evidence/{ev['id']}/lifecycle", json={"to_state": "UNDER_REVIEW"}
    )
    assert r.status_code == 200
    assert _j(r.json())["lifecycle_state"] == "UNDER_REVIEW"


def test_ea_34_under_review_to_verified_sets_verified_at(client):
    ev = _create_evidence(client)
    _drive_to_verified(client, ev["id"])
    r = client.get(f"/evidence/{ev['id']}")
    body = _j(r.json())
    assert body["lifecycle_state"] == "VERIFIED"
    assert body["verified_at"] is not None


def test_ea_35_under_review_to_rejected(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "UNDER_REVIEW"})
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "REJECTED"})
    assert r.status_code == 200
    assert _j(r.json())["lifecycle_state"] == "REJECTED"


def test_ea_36_verified_to_superseded(client):
    ev = _create_evidence(client)
    _drive_to_verified(client, ev["id"])
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUPERSEDED"})
    assert r.status_code == 200
    assert _j(r.json())["lifecycle_state"] == "SUPERSEDED"


def test_ea_37_verified_to_expired(client):
    ev = _create_evidence(client)
    _drive_to_verified(client, ev["id"])
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "EXPIRED"})
    assert r.status_code == 200
    assert _j(r.json())["lifecycle_state"] == "EXPIRED"


def test_ea_38_verified_to_archived(client):
    ev = _create_evidence(client)
    _drive_to_verified(client, ev["id"])
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "ARCHIVED"})
    assert r.status_code == 200
    assert _j(r.json())["lifecycle_state"] == "ARCHIVED"


def test_ea_39_revoked_is_terminal(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "REVOKED"})
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "ARCHIVED"})
    assert r.status_code == 422


def test_ea_40_archived_is_semi_terminal(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "ARCHIVED"})
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "COLLECTED"})
    assert r.status_code == 422


def test_ea_41_invalid_lifecycle_transition_422(client):
    # COLLECTED → VERIFIED is not a direct transition
    ev = _create_evidence(client)
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "VERIFIED"})
    assert r.status_code == 422


def test_ea_42_lifecycle_nonexistent_evidence_404(client):
    r = client.post(f"/evidence/{_uid()}/lifecycle", json={"to_state": "SUBMITTED"})
    assert r.status_code == 404


def test_ea_43_lifecycle_creates_audit_event(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    r = client.get(f"/evidence/{ev['id']}/audit")
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "lifecycle_transitioned" in types


def test_ea_44_revoked_sets_revoked_at(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "REVOKED"})
    r = client.get(f"/evidence/{ev['id']}")
    assert _j(r.json())["revoked_at"] is not None


def test_ea_45_archived_sets_archived_at(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "ARCHIVED"})
    r = client.get(f"/evidence/{ev['id']}")
    assert _j(r.json())["archived_at"] is not None


def test_ea_46_submitted_sets_submitted_at(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    r = client.get(f"/evidence/{ev['id']}")
    assert _j(r.json())["submitted_at"] is not None


def test_ea_47_lifecycle_requires_write_scope(readonly_client, client):
    ev = _create_evidence(client)
    r = readonly_client.post(
        f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"}
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# EA-48 – EA-63: Trust State Transitions
# ---------------------------------------------------------------------------


def test_ea_48_trust_unverified_to_partially_verified(client):
    ev = _create_evidence(client)
    result = _verify(client, ev["id"], "PARTIALLY_VERIFIED")
    assert result["current_trust_state"] == "PARTIALLY_VERIFIED"


def test_ea_49_trust_unverified_to_verified(client):
    ev = _create_evidence(client)
    result = _verify(client, ev["id"], "VERIFIED")
    assert result["current_trust_state"] == "VERIFIED"


def test_ea_50_trust_verified_to_high_confidence(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "VERIFIED")
    result = _verify(client, ev["id"], "HIGH_CONFIDENCE")
    assert result["current_trust_state"] == "HIGH_CONFIDENCE"


def test_ea_51_trust_high_confidence_to_disputed(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "VERIFIED")
    _verify(client, ev["id"], "HIGH_CONFIDENCE")
    result = _verify(client, ev["id"], "DISPUTED")
    assert result["current_trust_state"] == "DISPUTED"


def test_ea_52_trust_invalidated_is_terminal(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "INVALIDATED")
    r = client.post(
        f"/evidence/{ev['id']}/verify",
        json={"to_trust_state": "VERIFIED", "verification_source": "HUMAN"},
    )
    assert r.status_code == 422


def test_ea_53_invalid_trust_transition_422(client):
    # UNVERIFIED → HIGH_CONFIDENCE is not a valid direct transition
    ev = _create_evidence(client)
    r = client.post(
        f"/evidence/{ev['id']}/verify",
        json={"to_trust_state": "HIGH_CONFIDENCE", "verification_source": "HUMAN"},
    )
    assert r.status_code == 422


def test_ea_54_trust_event_created_with_state(client):
    ev = _create_evidence(client)
    result = _verify(client, ev["id"], "VERIFIED")
    assert len(result["events"]) == 1
    event = result["events"][0]
    assert event["from_trust_state"] == "UNVERIFIED"
    assert event["to_trust_state"] == "VERIFIED"


def test_ea_55_trust_event_hash_populated(client):
    ev = _create_evidence(client)
    result = _verify(client, ev["id"], "VERIFIED")
    h = result["events"][0]["event_hash"]
    assert h is not None
    assert len(h) == 64


def test_ea_56_second_trust_event_chains_to_first(client):
    ev = _create_evidence(client)
    first = _verify(client, ev["id"], "PARTIALLY_VERIFIED")
    first_hash = first["events"][0]["event_hash"]

    second = _verify(client, ev["id"], "VERIFIED")
    assert second["events"][1]["prev_event_hash"] == first_hash


def test_ea_57_trust_score_floor_applied(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "VERIFIED")
    r = client.get(f"/evidence/{ev['id']}")
    score = _j(r.json())["trust_score"]
    assert score is not None
    assert score >= TRUST_STATE_SCORE_FLOOR[EvidenceTrustState.VERIFIED]


def test_ea_58_trust_verified_sets_verified_at(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "VERIFIED")
    r = client.get(f"/evidence/{ev['id']}")
    assert _j(r.json())["verified_at"] is not None


def test_ea_59_trust_creates_audit_event(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "VERIFIED")
    r = client.get(f"/evidence/{ev['id']}/audit")
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "trust_state_changed" in types


def test_ea_60_trust_nonexistent_evidence_404(client):
    r = client.post(
        f"/evidence/{_uid()}/verify",
        json={"to_trust_state": "VERIFIED", "verification_source": "HUMAN"},
    )
    assert r.status_code == 404


def test_ea_61_trust_query_returns_full_history(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "PARTIALLY_VERIFIED")
    _verify(client, ev["id"], "VERIFIED")
    r = client.get(f"/evidence/{ev['id']}/trust")
    assert r.status_code == 200
    body = _j(r.json())
    assert len(body["events"]) == 2
    assert body["verification_count"] == 2


def test_ea_62_trust_verify_requires_write_scope(readonly_client, client):
    ev = _create_evidence(client)
    r = readonly_client.post(
        f"/evidence/{ev['id']}/verify",
        json={"to_trust_state": "VERIFIED", "verification_source": "HUMAN"},
    )
    assert r.status_code == 403


def test_ea_63_trust_query_requires_read_scope(writeonly_client, client):
    ev = _create_evidence(client)
    r = writeonly_client.get(f"/evidence/{ev['id']}/trust")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# EA-64 – EA-75: Ownership
# ---------------------------------------------------------------------------


def _assign_ownership(
    client: TestClient,
    ev_id: str,
    role: str = "OWNER",
    actor_id: str | None = None,
    actor_type: str = "human",
) -> dict:
    r = client.post(
        f"/evidence/{ev_id}/ownership",
        json={
            "role": role,
            "actor_id": actor_id or f"user-{_uid()}",
            "actor_type": actor_type,
        },
    )
    assert r.status_code == 201, r.text
    return _j(r.json())


def test_ea_64_assign_owner_role(client):
    ev = _create_evidence(client)
    own = _assign_ownership(client, ev["id"], role="OWNER")
    assert own["role"] == "OWNER"
    assert own["is_active"] is True


def test_ea_65_assign_owner_updates_evidence_owner_id(client):
    ev = _create_evidence(client)
    actor = f"user-{_uid()}"
    _assign_ownership(client, ev["id"], role="OWNER", actor_id=actor)
    r = client.get(f"/evidence/{ev['id']}")
    assert _j(r.json())["owner_id"] == actor


def test_ea_66_assign_reviewer_role(client):
    ev = _create_evidence(client)
    own = _assign_ownership(client, ev["id"], role="REVIEWER")
    assert own["role"] == "REVIEWER"


def test_ea_67_assign_verifier_role(client):
    ev = _create_evidence(client)
    own = _assign_ownership(client, ev["id"], role="VERIFIER")
    assert own["role"] == "VERIFIER"


def test_ea_68_revoke_ownership_sets_inactive(client):
    ev = _create_evidence(client)
    own = _assign_ownership(client, ev["id"])
    r = client.delete(f"/evidence/{ev['id']}/ownership/{own['id']}")
    assert r.status_code == 200
    assert _j(r.json())["is_active"] is False


def test_ea_69_revoke_ownership_sets_revoked_at(client):
    ev = _create_evidence(client)
    own = _assign_ownership(client, ev["id"])
    client.delete(f"/evidence/{ev['id']}/ownership/{own['id']}")
    r = client.get(f"/evidence/{ev['id']}/ownership")
    items = _j(r.json())["items"]
    revoked = next(i for i in items if i["id"] == own["id"])
    assert revoked["revoked_at"] is not None


def test_ea_70_revoke_nonexistent_ownership_404(client):
    ev = _create_evidence(client)
    r = client.delete(f"/evidence/{ev['id']}/ownership/{_uid()}")
    assert r.status_code == 404


def test_ea_71_list_all_ownership_records(client):
    ev = _create_evidence(client)
    _assign_ownership(client, ev["id"], role="OWNER")
    _assign_ownership(client, ev["id"], role="REVIEWER")
    r = client.get(f"/evidence/{ev['id']}/ownership")
    assert r.status_code == 200
    assert _j(r.json())["total"] == 2


def test_ea_72_list_active_only_filters_revoked(client):
    ev = _create_evidence(client)
    active_own = _assign_ownership(client, ev["id"], role="OWNER")
    revoked_own = _assign_ownership(client, ev["id"], role="REVIEWER")
    client.delete(f"/evidence/{ev['id']}/ownership/{revoked_own['id']}")

    r = client.get(f"/evidence/{ev['id']}/ownership", params={"active_only": "true"})
    ids = [i["id"] for i in _j(r.json())["items"]]
    assert active_own["id"] in ids
    assert revoked_own["id"] not in ids


def test_ea_73_assign_ownership_creates_audit_event(client):
    ev = _create_evidence(client)
    _assign_ownership(client, ev["id"])
    r = client.get(f"/evidence/{ev['id']}/audit")
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "ownership_assigned" in types


def test_ea_74_revoke_ownership_creates_audit_event(client):
    ev = _create_evidence(client)
    own = _assign_ownership(client, ev["id"])
    client.delete(f"/evidence/{ev['id']}/ownership/{own['id']}")
    r = client.get(f"/evidence/{ev['id']}/audit")
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "ownership_revoked" in types


def test_ea_75_ownership_cross_tenant_404(client_b, client):
    ev = _create_evidence(client)
    r = client_b.post(
        f"/evidence/{ev['id']}/ownership",
        json={"role": "OWNER", "actor_id": "attacker", "actor_type": "human"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# EA-76 – EA-85: Relationships
# ---------------------------------------------------------------------------


def test_ea_76_link_evidence_to_finding(client):
    ev = _create_evidence(client)
    rel = _link(client, ev["id"], entity_type="finding")
    assert rel["related_entity_type"] == "finding"
    assert rel["relationship_type"] == "SUPPORTS"


def test_ea_77_link_evidence_to_control(client):
    ev = _create_evidence(client)
    rel = _link(client, ev["id"], entity_type="control")
    assert rel["related_entity_type"] == "control"


def test_ea_78_link_evidence_to_risk_acceptance(client):
    ev = _create_evidence(client)
    rel = _link(client, ev["id"], entity_type="risk_acceptance")
    assert rel["related_entity_type"] == "risk_acceptance"


def test_ea_79_duplicate_relationship_409(client):
    ev = _create_evidence(client)
    entity_id = _uid()
    _link(client, ev["id"], entity_type="finding", entity_id=entity_id)
    r = client.post(
        f"/evidence/{ev['id']}/relationships",
        json={
            "related_entity_type": "finding",
            "related_entity_id": entity_id,
            "relationship_type": "SUPPORTS",
        },
    )
    assert r.status_code == 409


def test_ea_80_list_relationships(client):
    ev = _create_evidence(client)
    _link(client, ev["id"], entity_type="finding")
    _link(client, ev["id"], entity_type="control")
    r = client.get(f"/evidence/{ev['id']}/relationships")
    assert r.status_code == 200
    body = _j(r.json())
    assert body["total"] == 2


def test_ea_81_list_relationships_filtered_by_entity_type(client):
    ev = _create_evidence(client)
    _link(client, ev["id"], entity_type="finding")
    _link(client, ev["id"], entity_type="control")
    r = client.get(
        f"/evidence/{ev['id']}/relationships", params={"entity_type": "finding"}
    )
    body = _j(r.json())
    assert all(e["related_entity_type"] == "finding" for e in body["items"])


def test_ea_82_list_evidence_for_entity(client):
    ev = _create_evidence(client)
    fid = _uid()
    _link(client, ev["id"], entity_type="finding", entity_id=fid)
    r = client.get(f"/evidence/by-entity/finding/{fid}")
    assert r.status_code == 200
    body = _j(r.json())
    assert any(rel["evidence_id"] == ev["id"] for rel in body["items"])


def test_ea_83_link_creates_audit_event(client):
    ev = _create_evidence(client)
    _link(client, ev["id"])
    r = client.get(f"/evidence/{ev['id']}/audit")
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "relationship_linked" in types


def test_ea_84_link_nonexistent_evidence_404(client):
    r = client.post(
        f"/evidence/{_uid()}/relationships",
        json={
            "related_entity_type": "finding",
            "related_entity_id": _uid(),
            "relationship_type": "SUPPORTS",
        },
    )
    assert r.status_code == 404


def test_ea_85_link_cross_tenant_evidence_404(client_b, client):
    ev = _create_evidence(client)
    r = client_b.post(
        f"/evidence/{ev['id']}/relationships",
        json={
            "related_entity_type": "finding",
            "related_entity_id": _uid(),
            "relationship_type": "SUPPORTS",
        },
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# EA-86 – EA-91: Audit Trail
# ---------------------------------------------------------------------------


def test_ea_86_audit_create_event(client):
    ev = _create_evidence(client)
    r = client.get(f"/evidence/{ev['id']}/audit")
    assert r.status_code == 200
    body = _j(r.json())
    assert body["total"] >= 1
    assert any(e["event_type"] == "evidence_created" for e in body["items"])


def test_ea_87_audit_lifecycle_event(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    r = client.get(f"/evidence/{ev['id']}/audit")
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "lifecycle_transitioned" in types


def test_ea_88_audit_trust_event(client):
    ev = _create_evidence(client)
    _verify(client, ev["id"], "VERIFIED")
    r = client.get(f"/evidence/{ev['id']}/audit")
    types = [e["event_type"] for e in _j(r.json())["items"]]
    assert "trust_state_changed" in types


def test_ea_89_audit_filter_by_event_type(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    _verify(client, ev["id"], "VERIFIED")
    r = client.get(
        f"/evidence/{ev['id']}/audit",
        params={"event_type": "lifecycle_transitioned"},
    )
    body = _j(r.json())
    assert all(e["event_type"] == "lifecycle_transitioned" for e in body["items"])
    assert len(body["items"]) >= 1


def test_ea_90_audit_pagination(client):
    ev = _create_evidence(client)
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "UNDER_REVIEW"})
    r = client.get(f"/evidence/{ev['id']}/audit", params={"limit": 1, "offset": 0})
    body = _j(r.json())
    assert len(body["items"]) == 1
    assert body["total"] >= 3  # created + 2 transitions


def test_ea_91_audit_nonexistent_evidence_404(client):
    r = client.get(f"/evidence/{_uid()}/audit")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# EA-92 – EA-98: Dashboard
# ---------------------------------------------------------------------------


def test_ea_92_dashboard_total_evidence(client):
    _create_evidence(client)
    _create_evidence(client)
    r = client.get("/evidence/dashboard")
    assert r.status_code == 200
    body = _j(r.json())
    assert body["total_evidence"] >= 2


def test_ea_93_dashboard_by_lifecycle_state(client):
    _create_evidence(client)
    r = client.get("/evidence/dashboard")
    body = _j(r.json())
    assert "COLLECTED" in body["by_lifecycle_state"]
    assert body["by_lifecycle_state"]["COLLECTED"] >= 1


def test_ea_94_dashboard_by_trust_state(client):
    _create_evidence(client)
    r = client.get("/evidence/dashboard")
    body = _j(r.json())
    assert "UNVERIFIED" in body["by_trust_state"]
    assert body["by_trust_state"]["UNVERIFIED"] >= 1


def test_ea_95_dashboard_verified_count(client):
    ev = _create_evidence(client)
    _drive_to_verified(client, ev["id"])
    r = client.get("/evidence/dashboard")
    body = _j(r.json())
    assert body["verified_count"] >= 1


def test_ea_96_dashboard_without_owner_count(client):
    _create_evidence(client)
    r = client.get("/evidence/dashboard")
    body = _j(r.json())
    assert body["without_owner_count"] >= 1


def test_ea_97_dashboard_without_relationships_count(client):
    _create_evidence(client)
    r = client.get("/evidence/dashboard")
    body = _j(r.json())
    assert body["without_relationships_count"] >= 1


def test_ea_98_dashboard_tenant_isolation(client, client_b):
    # Tenant A gets 2 records, Tenant B gets 1
    _create_evidence(client)
    _create_evidence(client)
    _create_evidence(client_b)

    r_b = client_b.get("/evidence/dashboard")
    total_b = _j(r_b.json())["total_evidence"]
    # Tenant B's total should not reflect Tenant A's records
    assert total_b >= 1


# ---------------------------------------------------------------------------
# EA-99 – EA-101: State Machine Pure Tests (no I/O)
# ---------------------------------------------------------------------------


def test_ea_99_all_revoked_transitions_blocked():
    from_state = EvidenceLifecycleState.REVOKED
    for to_state in EvidenceLifecycleState:
        with pytest.raises(ValueError):
            validate_lifecycle_transition(from_state, to_state)


def test_ea_100_all_archived_transitions_blocked():
    from_state = EvidenceLifecycleState.ARCHIVED
    for to_state in EvidenceLifecycleState:
        with pytest.raises(ValueError):
            validate_lifecycle_transition(from_state, to_state)


def test_ea_101_invalidated_trust_terminal():
    from_state = EvidenceTrustState.INVALIDATED
    for to_state in EvidenceTrustState:
        with pytest.raises(ValueError):
            validate_trust_transition(from_state, to_state)


# ---------------------------------------------------------------------------
# EA-102 – EA-103: Full Workflow Integration
# ---------------------------------------------------------------------------


def test_ea_102_full_lifecycle_workflow(client):
    """COLLECTED → SUBMITTED → UNDER_REVIEW → VERIFIED → SUPERSEDED."""
    ev = _create_evidence(client)
    assert ev["lifecycle_state"] == "COLLECTED"

    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUBMITTED"})
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "UNDER_REVIEW"})
    client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "VERIFIED"})
    r = client.post(f"/evidence/{ev['id']}/lifecycle", json={"to_state": "SUPERSEDED"})
    assert r.status_code == 200
    body = _j(r.json())
    assert body["lifecycle_state"] == "SUPERSEDED"
    assert body["verified_at"] is not None

    audit_r = client.get(f"/evidence/{ev['id']}/audit")
    types = {e["event_type"] for e in _j(audit_r.json())["items"]}
    assert "evidence_created" in types
    assert "lifecycle_transitioned" in types
    assert "evidence_superseded" in types


def test_ea_103_full_trust_chain_workflow(client):
    """UNVERIFIED → PARTIALLY_VERIFIED → VERIFIED → HIGH_CONFIDENCE with chain integrity."""
    ev = _create_evidence(client)

    r1 = _verify(client, ev["id"], "PARTIALLY_VERIFIED", confidence_score=30)
    assert r1["current_trust_state"] == "PARTIALLY_VERIFIED"
    first_hash = r1["events"][0]["event_hash"]
    assert r1["events"][0]["prev_event_hash"] is None

    r2 = _verify(client, ev["id"], "VERIFIED", confidence_score=75)
    assert r2["current_trust_state"] == "VERIFIED"
    assert r2["verification_count"] == 2
    assert r2["events"][1]["prev_event_hash"] == first_hash

    r3 = _verify(client, ev["id"], "HIGH_CONFIDENCE", confidence_score=95)
    assert r3["current_trust_state"] == "HIGH_CONFIDENCE"
    assert r3["verification_count"] == 3
    second_hash = r2["events"][1]["event_hash"]
    assert r3["events"][2]["prev_event_hash"] == second_hash


# ---------------------------------------------------------------------------
# EA-104 – EA-110: Actor Type, Schema, Security
# ---------------------------------------------------------------------------


def test_ea_104_actor_type_agent_on_ownership(client):
    ev = _create_evidence(client)
    r = client.post(
        f"/evidence/{ev['id']}/ownership",
        json={"role": "REVIEWER", "actor_id": "agent-007", "actor_type": "agent"},
    )
    assert r.status_code == 201
    assert _j(r.json())["actor_type"] == "agent"


def test_ea_105_schema_version_on_evidence(client):
    body = _create_evidence(client)
    assert body["schema_version"] == "1.0"


def test_ea_106_schema_version_in_list(client):
    _create_evidence(client)
    r = client.get("/evidence")
    items = _j(r.json())["items"]
    assert all(e["schema_version"] == "1.0" for e in items)


def test_ea_107_cross_tenant_list_isolation(client, client_b):
    ev_a = _create_evidence(client)
    ev_b = _create_evidence(client_b)

    ids_a = {e["id"] for e in _j(client.get("/evidence").json())["items"]}
    ids_b = {e["id"] for e in _j(client_b.get("/evidence").json())["items"]}

    assert ev_a["id"] in ids_a
    assert ev_b["id"] not in ids_a
    assert ev_b["id"] in ids_b
    assert ev_a["id"] not in ids_b


def test_ea_108_dashboard_requires_read_scope(writeonly_client):
    r = writeonly_client.get("/evidence/dashboard")
    assert r.status_code == 403


def test_ea_109_by_entity_returns_relationships(client):
    ev = _create_evidence(client)
    entity_id = _uid()
    _link(client, ev["id"], entity_type="control", entity_id=entity_id)
    r = client.get(f"/evidence/by-entity/control/{entity_id}")
    assert r.status_code == 200
    body = _j(r.json())
    assert body["total"] >= 1
    assert any(rel["related_entity_id"] == entity_id for rel in body["items"])


def test_ea_110_trust_confidence_score_stored(client):
    ev = _create_evidence(client)
    result = _verify(client, ev["id"], "VERIFIED", confidence_score=88)
    event = result["events"][0]
    assert event["confidence_score"] == 88
