# tests/test_control_registry.py
"""Compensating Control Registry test suite — PR 14.3.

Coverage:
  CCR-1   Create control (DRAFT status, UNVERIFIED verification)
  CCR-2   Get control
  CCR-3   List controls (empty and populated)
  CCR-4   Update control title
  CCR-5   Update control type
  CCR-6   Update effectiveness rating
  CCR-7   Status: DRAFT → ACTIVE
  CCR-8   Status: ACTIVE → RETIRED
  CCR-9   Status: ACTIVE → SUSPENDED
  CCR-10  Status: SUSPENDED → ACTIVE (reactivation)
  CCR-11  Invalid status transition → 422
  CCR-12  HIGHLY_EFFECTIVE when UNVERIFIED → 409
  CCR-13  control_id is stored and returned at creation
  CCR-14  Verify control sets VERIFIED + last_verified_at
  CCR-15  Verify without evidence → 422
  CCR-16  Link evidence to control
  CCR-17  List evidence for control
  CCR-18  Link evidence then verify succeeds
  CCR-19  Link risk acceptance to control
  CCR-20  List risk links for control
  CCR-21  Cannot link RETIRED control to risk → 409
  CCR-22  Create review for control
  CCR-23  List reviews for control
  CCR-24  Complete review with outcome
  CCR-25  Complete already-completed review → 409
  CCR-26  Get control audit trail
  CCR-27  Audit event on control creation
  CCR-28  Audit event on status change
  CCR-29  Audit event on verification
  CCR-30  Freshness sweep marks VERIFIED controls EXPIRED when stale
  CCR-31  Freshness sweep ignores DRAFT controls
  CCR-32  Freshness sweep ignores recently verified controls
  CCR-33  Review sweep marks overdue reviews
  CCR-34  Dashboard: total_controls count
  CCR-35  Dashboard: active_controls count
  CCR-36  Dashboard: verified_controls count
  CCR-37  Dashboard: unverified_controls count
  CCR-38  Dashboard: controls_without_evidence count
  CCR-39  Dashboard: controls_without_owner count
  CCR-40  Dashboard: high_criticality_unverified count
  CCR-41  Timeline event emitted on control creation
  CCR-42  Timeline event emitted on control verification
  CCR-43  Metrics: CONTROLS_TOTAL increments on create
  CCR-44  Metrics: CONTROLS_VERIFIED_TOTAL increments on verify
  CCR-45  Tenant B cannot get Tenant A control → 404
  CCR-46  Tenant B list returns empty (not Tenant A controls)
  CCR-47  Tenant B cannot verify Tenant A control → 404
  CCR-48  Tenant B cannot link evidence to Tenant A control → 404
  CCR-49  Tenant B cannot link risk to Tenant A control → 404
  CCR-50  Read scope required for GET /controls
  CCR-51  Write scope required for POST /controls
  CCR-52  Schema version 1.0 on control records
  CCR-53  Schema version 1.0 on review records
  CCR-54  Freshness: FRESH when verified recently
  CCR-55  Freshness: EXPIRED when no last_verified_at
  CCR-56  List controls with status filter
  CCR-57  List controls with control_type filter
  CCR-58  Dashboard: governance_debt score (non-negative int)
  CCR-59  Multiple evidence links per control
  CCR-60  Multiple risk links per control
  CCR-61  Update sets updated_at
  CCR-62  Verify sets last_verified_at
  CCR-63  Risk link with rationale stored
  CCR-64  Evidence link with evidence_type stored
  CCR-65  RETIRED control still readable
  CCR-66  Maintenance endpoints require write scope
  CCR-67  Dashboard requires read scope
  CCR-68  List reviews with pagination
  CCR-69  Audit entries: old_state and new_state stored
  CCR-70  Audit count increases with each operation
  CCR-71  Tenant B cannot complete Tenant A review → 404
  CCR-72  Tenant B cannot create review for Tenant A control → 404
  CCR-73  All control types stored correctly
  CCR-74  All criticality levels stored correctly
  CCR-75  Full governance workflow: create → link → verify → review → dashboard
  CCR-76  Review sweep ignores already-completed reviews
  CCR-77  Update owner email
  CCR-78  Non-existent control GET → 404
  CCR-79  Non-existent control PATCH → 404
  CCR-80  Verify non-existent control → 404
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_engine

_TENANT_A = "tenant-cr-a"
_TENANT_B = "tenant-cr-b"

_FUTURE_DUE = "2099-06-01T00:00:00+00:00"
_PAST_DUE = "2020-06-01T00:00:00+00:00"
# Verified 200 days ago with 90-day cycle = expired
_OLD_VERIFIED = "2025-12-04T00:00:00+00:00"
# Verified 10 days ago with 90-day cycle = fresh
_RECENT_VERIFIED = "2026-06-11T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json(value: dict[Any, Any] | None) -> dict[Any, Any]:
    assert value is not None
    return value


def _control_body(**overrides: Any) -> dict:
    base: dict[str, Any] = {
        "title": "Firewall Patch Management",
        "description": "Ensures firewall firmware is updated monthly.",
        "control_type": "technical",
        "criticality": "high",
        "owner": "security-team@example.com",
        "owner_email": "security-team@example.com",
        "business_unit": "Infrastructure",
        "effectiveness_rating": "effective",
        "review_frequency_days": 90,
    }
    base.update(overrides)
    return base


def _review_body(**overrides: Any) -> dict:
    base: dict[str, Any] = {
        "reviewer": "auditor@example.com",
        "review_date": _FUTURE_DUE,
        "notes": "Scheduled quarterly review.",
    }
    base.update(overrides)
    return base


def _evidence_body(**overrides: Any) -> dict:
    base: dict[str, Any] = {
        "evidence_id": f"ev-{uuid.uuid4().hex[:8]}",
        "evidence_type": "scan_report",
        "linked_by": "ops-team@example.com",
    }
    base.update(overrides)
    return base


def _risk_link_body(**overrides: Any) -> dict:
    base: dict[str, Any] = {
        "risk_acceptance_id": f"ra-{uuid.uuid4().hex[:8]}",
        "rationale": "Control directly mitigates the accepted risk.",
    }
    base.update(overrides)
    return base


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


@pytest.fixture()
def db_session(build_app):
    build_app(auth_enabled=True)
    engine = get_engine()
    with Session(engine) as session:
        yield session


# ---------------------------------------------------------------------------
# CCR-1: Create control
# ---------------------------------------------------------------------------


def test_ccr_1_create_control(client):
    r = client.post("/controls", json=_control_body())
    assert r.status_code == 201
    body = _json(r.json())
    assert body["control_status"] == "draft"
    assert body["verification_status"] == "unverified"
    assert body["title"] == "Firewall Patch Management"


# ---------------------------------------------------------------------------
# CCR-2: Get control
# ---------------------------------------------------------------------------


def test_ccr_2_get_control(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.get(f"/controls/{ctl_id}")
    assert r.status_code == 200
    assert _json(r.json())["id"] == ctl_id


# ---------------------------------------------------------------------------
# CCR-3: List controls
# ---------------------------------------------------------------------------


def test_ccr_3_list_controls(client):
    client.post("/controls", json=_control_body(title="Control A"))
    client.post("/controls", json=_control_body(title="Control B"))
    r = client.get("/controls")
    body = _json(r.json())
    assert body["total"] >= 2
    assert len(body["items"]) >= 2


# ---------------------------------------------------------------------------
# CCR-4: Update control title
# ---------------------------------------------------------------------------


def test_ccr_4_update_title(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.patch(f"/controls/{ctl_id}", json={"title": "Updated Title"})
    assert r.status_code == 200
    assert _json(r.json())["title"] == "Updated Title"


# ---------------------------------------------------------------------------
# CCR-5: Update control type
# ---------------------------------------------------------------------------


def test_ccr_5_update_type(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.patch(f"/controls/{ctl_id}", json={"control_type": "administrative"})
    assert r.status_code == 200
    assert _json(r.json())["control_type"] == "administrative"


# ---------------------------------------------------------------------------
# CCR-6: Update effectiveness rating
# ---------------------------------------------------------------------------


def test_ccr_6_update_effectiveness(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.patch(
        f"/controls/{ctl_id}", json={"effectiveness_rating": "partially_effective"}
    )
    assert r.status_code == 200
    assert _json(r.json())["effectiveness_rating"] == "partially_effective"


# ---------------------------------------------------------------------------
# CCR-7: Status DRAFT → ACTIVE
# ---------------------------------------------------------------------------


def test_ccr_7_draft_to_active(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    assert r.status_code == 200
    assert _json(r.json())["control_status"] == "active"


# ---------------------------------------------------------------------------
# CCR-8: Status ACTIVE → RETIRED
# ---------------------------------------------------------------------------


def test_ccr_8_active_to_retired(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    r = client.patch(f"/controls/{ctl_id}", json={"control_status": "retired"})
    assert r.status_code == 200
    assert _json(r.json())["control_status"] == "retired"


# ---------------------------------------------------------------------------
# CCR-9: Status ACTIVE → SUSPENDED
# ---------------------------------------------------------------------------


def test_ccr_9_active_to_suspended(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    r = client.patch(f"/controls/{ctl_id}", json={"control_status": "suspended"})
    assert r.status_code == 200
    assert _json(r.json())["control_status"] == "suspended"


# ---------------------------------------------------------------------------
# CCR-10: Status SUSPENDED → ACTIVE (reactivation)
# ---------------------------------------------------------------------------


def test_ccr_10_suspended_to_active(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    client.patch(f"/controls/{ctl_id}", json={"control_status": "suspended"})
    r = client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    assert r.status_code == 200
    assert _json(r.json())["control_status"] == "active"


# ---------------------------------------------------------------------------
# CCR-11: Invalid status transition → 422
# ---------------------------------------------------------------------------


def test_ccr_11_invalid_transition(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    # DRAFT → RETIRED is not allowed
    r = client.patch(f"/controls/{ctl_id}", json={"control_status": "retired"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# CCR-12: HIGHLY_EFFECTIVE when UNVERIFIED → 409
# ---------------------------------------------------------------------------


def test_ccr_12_highly_effective_when_unverified(client):
    ctl_id = _json(
        client.post(
            "/controls", json=_control_body(effectiveness_rating="unknown")
        ).json()
    )["id"]
    r = client.patch(
        f"/controls/{ctl_id}", json={"effectiveness_rating": "highly_effective"}
    )
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# CCR-13: control_id stored at creation
# ---------------------------------------------------------------------------


def test_ccr_13_control_id_stored(client):
    r = client.post("/controls", json=_control_body(control_id="CC-FIREWALL-001"))
    assert r.status_code == 201
    assert _json(r.json())["control_id"] == "CC-FIREWALL-001"


# ---------------------------------------------------------------------------
# CCR-14: Verify control
# ---------------------------------------------------------------------------


def test_ccr_14_verify_control(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    r = client.post(f"/controls/{ctl_id}/verify", json={})
    assert r.status_code == 200
    body = _json(r.json())
    assert body["verification_status"] == "verified"
    assert body["last_verified_at"] is not None


# ---------------------------------------------------------------------------
# CCR-15: Verify without evidence → 422
# ---------------------------------------------------------------------------


def test_ccr_15_verify_without_evidence(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.post(f"/controls/{ctl_id}/verify", json={})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# CCR-16: Link evidence
# ---------------------------------------------------------------------------


def test_ccr_16_link_evidence(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.post(
        f"/controls/{ctl_id}/evidence",
        json={"evidence_id": "ev-abc123", "evidence_type": "scan_report"},
    )
    assert r.status_code == 201
    body = _json(r.json())
    assert body["evidence_id"] == "ev-abc123"
    assert body["evidence_type"] == "scan_report"


# ---------------------------------------------------------------------------
# CCR-17: List evidence
# ---------------------------------------------------------------------------


def test_ccr_17_list_evidence(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    r = client.get(f"/controls/{ctl_id}/evidence")
    body = _json(r.json())
    assert body["total"] == 2
    assert len(body["items"]) == 2


# ---------------------------------------------------------------------------
# CCR-18: Link evidence then verify succeeds
# ---------------------------------------------------------------------------


def test_ccr_18_verify_after_evidence(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    r = client.post(f"/controls/{ctl_id}/verify", json={})
    assert r.status_code == 200
    assert _json(r.json())["verification_status"] == "verified"


# ---------------------------------------------------------------------------
# CCR-19: Link risk acceptance
# ---------------------------------------------------------------------------


def test_ccr_19_link_risk(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.post(
        f"/controls/{ctl_id}/risk-links",
        json={"risk_acceptance_id": "ra-123", "rationale": "Direct mitigation."},
    )
    assert r.status_code == 201
    body = _json(r.json())
    assert body["risk_acceptance_id"] == "ra-123"
    assert body["control_id"] == ctl_id


# ---------------------------------------------------------------------------
# CCR-20: List risk links
# ---------------------------------------------------------------------------


def test_ccr_20_list_risk_links(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/risk-links", json=_risk_link_body())
    client.post(f"/controls/{ctl_id}/risk-links", json=_risk_link_body())
    r = client.get(f"/controls/{ctl_id}/risk-links")
    body = _json(r.json())
    assert body["total"] == 2


# ---------------------------------------------------------------------------
# CCR-21: Cannot link RETIRED control → 409
# ---------------------------------------------------------------------------


def test_ccr_21_link_retired_control(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    client.patch(f"/controls/{ctl_id}", json={"control_status": "retired"})
    r = client.post(f"/controls/{ctl_id}/risk-links", json=_risk_link_body())
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# CCR-22: Create review
# ---------------------------------------------------------------------------


def test_ccr_22_create_review(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.post(f"/controls/{ctl_id}/reviews", json=_review_body())
    assert r.status_code == 201
    body = _json(r.json())
    assert body["status"] == "pending"
    assert body["control_id"] == ctl_id


# ---------------------------------------------------------------------------
# CCR-23: List reviews
# ---------------------------------------------------------------------------


def test_ccr_23_list_reviews(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/reviews", json=_review_body())
    client.post(
        f"/controls/{ctl_id}/reviews",
        json=_review_body(review_date="2099-07-01T00:00:00+00:00"),
    )
    r = client.get(f"/controls/{ctl_id}/reviews")
    body = _json(r.json())
    assert body["total"] == 2


# ---------------------------------------------------------------------------
# CCR-24: Complete review
# ---------------------------------------------------------------------------


def test_ccr_24_complete_review(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    review_id = _json(
        client.post(f"/controls/{ctl_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client.post(
        f"/controls/{ctl_id}/reviews/{review_id}/complete",
        json={"outcome": "effective", "notes": "Control is operating effectively."},
    )
    assert r.status_code == 200
    body = _json(r.json())
    assert body["status"] == "completed"
    assert body["outcome"] == "effective"


# ---------------------------------------------------------------------------
# CCR-25: Complete already-completed review → 409
# ---------------------------------------------------------------------------


def test_ccr_25_complete_twice(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    review_id = _json(
        client.post(f"/controls/{ctl_id}/reviews", json=_review_body()).json()
    )["id"]
    client.post(
        f"/controls/{ctl_id}/reviews/{review_id}/complete",
        json={"outcome": "effective"},
    )
    r = client.post(
        f"/controls/{ctl_id}/reviews/{review_id}/complete",
        json={"outcome": "ineffective"},
    )
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# CCR-26: Get audit trail
# ---------------------------------------------------------------------------


def test_ccr_26_get_audit(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.get(f"/controls/{ctl_id}/audit")
    assert r.status_code == 200
    body = _json(r.json())
    assert body["total"] >= 1


# ---------------------------------------------------------------------------
# CCR-27: Audit event on creation
# ---------------------------------------------------------------------------


def test_ccr_27_audit_on_create(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.get(f"/controls/{ctl_id}/audit")
    body = _json(r.json())
    event_types = [e["event_type"] for e in body["items"]]
    assert "control_created" in event_types


# ---------------------------------------------------------------------------
# CCR-28: Audit event on status change
# ---------------------------------------------------------------------------


def test_ccr_28_audit_on_status_change(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    r = client.get(f"/controls/{ctl_id}/audit")
    body = _json(r.json())
    event_types = [e["event_type"] for e in body["items"]]
    assert "control_activated" in event_types


# ---------------------------------------------------------------------------
# CCR-29: Audit event on verification
# ---------------------------------------------------------------------------


def test_ccr_29_audit_on_verify(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    client.post(f"/controls/{ctl_id}/verify", json={})
    r = client.get(f"/controls/{ctl_id}/audit")
    body = _json(r.json())
    event_types = [e["event_type"] for e in body["items"]]
    assert "control_verified" in event_types


# ---------------------------------------------------------------------------
# CCR-30: Freshness sweep marks stale VERIFIED controls EXPIRED
# ---------------------------------------------------------------------------


def test_ccr_30_freshness_sweep_expires_stale(client, db_session):
    from api.db_models_control_registry import ControlRegistry

    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    # Activate and manually backdate last_verified_at to make it stale
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    engine = get_engine()
    with Session(engine) as db:
        ctrl = db.query(ControlRegistry).filter(ControlRegistry.id == ctl_id).first()
        ctrl.verification_status = "verified"
        ctrl.last_verified_at = _OLD_VERIFIED
        db.commit()

    r = client.post("/controls/maintenance/freshness")
    assert r.status_code == 200
    assert _json(r.json())["expired"] >= 1

    updated = _json(client.get(f"/controls/{ctl_id}").json())
    assert updated["verification_status"] == "expired"


# ---------------------------------------------------------------------------
# CCR-31: Freshness sweep ignores DRAFT controls
# ---------------------------------------------------------------------------


def test_ccr_31_freshness_sweep_ignores_draft(client, db_session):
    from api.db_models_control_registry import ControlRegistry

    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    engine = get_engine()
    with Session(engine) as db:
        ctrl = db.query(ControlRegistry).filter(ControlRegistry.id == ctl_id).first()
        ctrl.verification_status = "verified"
        ctrl.last_verified_at = _OLD_VERIFIED
        # Keep control_status as "draft"
        db.commit()

    client.post("/controls/maintenance/freshness")
    updated = _json(client.get(f"/controls/{ctl_id}").json())
    # DRAFT controls should not be swept
    assert updated["verification_status"] == "verified"


# ---------------------------------------------------------------------------
# CCR-32: Freshness sweep ignores recently verified controls
# ---------------------------------------------------------------------------


def test_ccr_32_freshness_sweep_ignores_fresh(client, db_session):
    from api.db_models_control_registry import ControlRegistry

    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    engine = get_engine()
    with Session(engine) as db:
        ctrl = db.query(ControlRegistry).filter(ControlRegistry.id == ctl_id).first()
        ctrl.verification_status = "verified"
        ctrl.last_verified_at = _RECENT_VERIFIED
        db.commit()

    client.post("/controls/maintenance/freshness")
    updated = _json(client.get(f"/controls/{ctl_id}").json())
    assert updated["verification_status"] == "verified"


# ---------------------------------------------------------------------------
# CCR-33: Review sweep marks overdue reviews
# ---------------------------------------------------------------------------


def test_ccr_33_review_sweep_marks_overdue(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(
        f"/controls/{ctl_id}/reviews",
        json=_review_body(review_date=_PAST_DUE),
    )
    r = client.post("/controls/maintenance/review-sweep")
    assert r.status_code == 200
    assert _json(r.json())["marked_overdue"] >= 1


# ---------------------------------------------------------------------------
# CCR-34: Dashboard total_controls
# ---------------------------------------------------------------------------


def test_ccr_34_dashboard_total(client):
    before = _json(client.get("/controls/dashboard").json())["total_controls"]
    client.post("/controls", json=_control_body())
    after = _json(client.get("/controls/dashboard").json())["total_controls"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# CCR-35: Dashboard active_controls
# ---------------------------------------------------------------------------


def test_ccr_35_dashboard_active(client):
    before = _json(client.get("/controls/dashboard").json())["active_controls"]
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    after = _json(client.get("/controls/dashboard").json())["active_controls"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# CCR-36: Dashboard verified_controls
# ---------------------------------------------------------------------------


def test_ccr_36_dashboard_verified(client):
    before = _json(client.get("/controls/dashboard").json())["verified_controls"]
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    client.post(f"/controls/{ctl_id}/verify", json={})
    after = _json(client.get("/controls/dashboard").json())["verified_controls"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# CCR-37: Dashboard unverified_controls
# ---------------------------------------------------------------------------


def test_ccr_37_dashboard_unverified(client):
    before = _json(client.get("/controls/dashboard").json())["unverified_controls"]
    client.post("/controls", json=_control_body())
    after = _json(client.get("/controls/dashboard").json())["unverified_controls"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# CCR-38: Dashboard controls_without_evidence
# ---------------------------------------------------------------------------


def test_ccr_38_dashboard_without_evidence(client):
    before = _json(client.get("/controls/dashboard").json())[
        "controls_without_evidence"
    ]
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    after = _json(client.get("/controls/dashboard").json())["controls_without_evidence"]
    assert after == before + 1
    # Link evidence — should remove from count
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    after2 = _json(client.get("/controls/dashboard").json())[
        "controls_without_evidence"
    ]
    assert after2 == before


# ---------------------------------------------------------------------------
# CCR-39: Dashboard controls_without_owner
# ---------------------------------------------------------------------------


def test_ccr_39_dashboard_without_owner(client):
    before = _json(client.get("/controls/dashboard").json())["controls_without_owner"]
    client.post("/controls", json=_control_body(owner=None, owner_email=None))
    after = _json(client.get("/controls/dashboard").json())["controls_without_owner"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# CCR-40: Dashboard high_criticality_unverified
# ---------------------------------------------------------------------------


def test_ccr_40_dashboard_high_crit_unverified(client):
    before = _json(client.get("/controls/dashboard").json())[
        "high_criticality_unverified"
    ]
    client.post("/controls", json=_control_body(criticality="critical"))
    after = _json(client.get("/controls/dashboard").json())[
        "high_criticality_unverified"
    ]
    assert after == before + 1


# ---------------------------------------------------------------------------
# CCR-41: Timeline event on create
# ---------------------------------------------------------------------------


def test_ccr_41_timeline_on_create(client, db_session):
    from api.db_models_timeline import TimelineEventRecord

    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(TimelineEventRecord)
            .filter(
                TimelineEventRecord.tenant_id == _TENANT_A,
                TimelineEventRecord.source_id == ctl_id,
                TimelineEventRecord.source_type == "CONTROL_REGISTRY",
                TimelineEventRecord.event_type == "control_created",
            )
            .all()
        )
    assert len(events) >= 1


# ---------------------------------------------------------------------------
# CCR-42: Timeline event on verify
# ---------------------------------------------------------------------------


def test_ccr_42_timeline_on_verify(client, db_session):
    from api.db_models_timeline import TimelineEventRecord

    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    client.post(f"/controls/{ctl_id}/verify", json={})
    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(TimelineEventRecord)
            .filter(
                TimelineEventRecord.tenant_id == _TENANT_A,
                TimelineEventRecord.source_id == ctl_id,
                TimelineEventRecord.source_type == "CONTROL_REGISTRY",
                TimelineEventRecord.event_type == "control_verified",
            )
            .all()
        )
    assert len(events) >= 1


# ---------------------------------------------------------------------------
# CCR-43: Metrics CONTROLS_TOTAL
# ---------------------------------------------------------------------------


def test_ccr_43_metrics_controls_total(client):
    from api.observability.metrics import CONTROLS_TOTAL

    before = CONTROLS_TOTAL._value.get()
    client.post("/controls", json=_control_body())
    assert CONTROLS_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# CCR-44: Metrics CONTROLS_VERIFIED_TOTAL
# ---------------------------------------------------------------------------


def test_ccr_44_metrics_verified_total(client):
    from api.observability.metrics import CONTROLS_VERIFIED_TOTAL

    before = CONTROLS_VERIFIED_TOTAL._value.get()
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    client.post(f"/controls/{ctl_id}/verify", json={})
    assert CONTROLS_VERIFIED_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# CCR-45: Tenant B cannot get Tenant A control
# ---------------------------------------------------------------------------


def test_ccr_45_cross_tenant_get(client, client_b):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client_b.get(f"/controls/{ctl_id}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-46: Tenant B list returns empty
# ---------------------------------------------------------------------------


def test_ccr_46_cross_tenant_list(client, client_b):
    client.post("/controls", json=_control_body())
    r = client_b.get("/controls")
    body = _json(r.json())
    # Tenant B should see zero of Tenant A's controls
    assert body["total"] == 0


# ---------------------------------------------------------------------------
# CCR-47: Tenant B cannot verify Tenant A control
# ---------------------------------------------------------------------------


def test_ccr_47_cross_tenant_verify(client, client_b):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client_b.post(f"/controls/{ctl_id}/verify", json={})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-48: Tenant B cannot link evidence to Tenant A control
# ---------------------------------------------------------------------------


def test_ccr_48_cross_tenant_evidence(client, client_b):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client_b.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-49: Tenant B cannot link risk to Tenant A control
# ---------------------------------------------------------------------------


def test_ccr_49_cross_tenant_risk_link(client, client_b):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client_b.post(f"/controls/{ctl_id}/risk-links", json=_risk_link_body())
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-50: Read scope required for GET /controls
# ---------------------------------------------------------------------------


def test_ccr_50_read_scope_required(writeonly_client):
    r = writeonly_client.get("/controls")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# CCR-51: Write scope required for POST /controls
# ---------------------------------------------------------------------------


def test_ccr_51_write_scope_required(readonly_client):
    r = readonly_client.post("/controls", json=_control_body())
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# CCR-52: Schema version 1.0 on control records
# ---------------------------------------------------------------------------


def test_ccr_52_schema_version_control(client):
    r = client.post("/controls", json=_control_body())
    assert _json(r.json())["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# CCR-53: Schema version 1.0 on review records
# ---------------------------------------------------------------------------


def test_ccr_53_schema_version_review(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.post(f"/controls/{ctl_id}/reviews", json=_review_body())
    assert _json(r.json())["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# CCR-54: Freshness FRESH when recently verified
# ---------------------------------------------------------------------------


def test_ccr_54_freshness_fresh(client, db_session):

    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    client.post(f"/controls/{ctl_id}/verify", json={})
    # Verify sets last_verified_at to now → freshness should be FRESH
    r = client.get(f"/controls/{ctl_id}")
    assert _json(r.json())["freshness"] == "fresh"


# ---------------------------------------------------------------------------
# CCR-55: Freshness EXPIRED when no last_verified_at
# ---------------------------------------------------------------------------


def test_ccr_55_freshness_expired_no_verification(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.get(f"/controls/{ctl_id}")
    assert _json(r.json())["freshness"] == "expired"


# ---------------------------------------------------------------------------
# CCR-56: List controls with status filter
# ---------------------------------------------------------------------------


def test_ccr_56_status_filter(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    client.post("/controls", json=_control_body(title="Draft Control"))
    r = client.get("/controls?status=active")
    body = _json(r.json())
    assert all(c["control_status"] == "active" for c in body["items"])


# ---------------------------------------------------------------------------
# CCR-57: List controls with control_type filter
# ---------------------------------------------------------------------------


def test_ccr_57_type_filter(client):
    client.post("/controls", json=_control_body(control_type="administrative"))
    r = client.get("/controls?control_type=administrative")
    body = _json(r.json())
    assert all(c["control_type"] == "administrative" for c in body["items"])
    assert body["total"] >= 1


# ---------------------------------------------------------------------------
# CCR-58: Dashboard is bounded (non-negative integers)
# ---------------------------------------------------------------------------


def test_ccr_58_dashboard_bounded(client):
    dash = _json(client.get("/controls/dashboard").json())
    for key, val in dash.items():
        if key != "tenant_id":
            assert isinstance(val, int), f"{key} should be int"
            assert val >= 0, f"{key} should be non-negative"


# ---------------------------------------------------------------------------
# CCR-59: Multiple evidence links
# ---------------------------------------------------------------------------


def test_ccr_59_multiple_evidence_links(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    for _ in range(3):
        client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    r = client.get(f"/controls/{ctl_id}/evidence")
    assert _json(r.json())["total"] == 3


# ---------------------------------------------------------------------------
# CCR-60: Multiple risk links
# ---------------------------------------------------------------------------


def test_ccr_60_multiple_risk_links(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    for _ in range(3):
        client.post(f"/controls/{ctl_id}/risk-links", json=_risk_link_body())
    r = client.get(f"/controls/{ctl_id}/risk-links")
    assert _json(r.json())["total"] == 3


# ---------------------------------------------------------------------------
# CCR-61: Update sets updated_at
# ---------------------------------------------------------------------------


def test_ccr_61_update_sets_updated_at(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    before = _json(client.get(f"/controls/{ctl_id}").json())["updated_at"]
    client.patch(f"/controls/{ctl_id}", json={"title": "Changed Title"})
    after = _json(client.get(f"/controls/{ctl_id}").json())["updated_at"]
    assert after >= before


# ---------------------------------------------------------------------------
# CCR-62: Verify sets last_verified_at
# ---------------------------------------------------------------------------


def test_ccr_62_verify_sets_last_verified(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    assert _json(client.get(f"/controls/{ctl_id}").json())["last_verified_at"] is None
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    client.post(f"/controls/{ctl_id}/verify", json={})
    assert (
        _json(client.get(f"/controls/{ctl_id}").json())["last_verified_at"] is not None
    )


# ---------------------------------------------------------------------------
# CCR-63: Risk link with rationale stored
# ---------------------------------------------------------------------------


def test_ccr_63_risk_link_rationale(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.post(
        f"/controls/{ctl_id}/risk-links",
        json={
            "risk_acceptance_id": "ra-xyz",
            "rationale": "Specific mitigation rationale.",
        },
    )
    assert r.status_code == 201
    assert _json(r.json())["rationale"] == "Specific mitigation rationale."


# ---------------------------------------------------------------------------
# CCR-64: Evidence link with evidence_type stored
# ---------------------------------------------------------------------------


def test_ccr_64_evidence_type_stored(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.post(
        f"/controls/{ctl_id}/evidence",
        json={"evidence_id": "ev-001", "evidence_type": "pen_test_report"},
    )
    assert r.status_code == 201
    assert _json(r.json())["evidence_type"] == "pen_test_report"


# ---------------------------------------------------------------------------
# CCR-65: RETIRED control is still readable
# ---------------------------------------------------------------------------


def test_ccr_65_retired_readable(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    client.patch(f"/controls/{ctl_id}", json={"control_status": "retired"})
    r = client.get(f"/controls/{ctl_id}")
    assert r.status_code == 200
    assert _json(r.json())["control_status"] == "retired"


# ---------------------------------------------------------------------------
# CCR-66: Maintenance endpoints require write scope
# ---------------------------------------------------------------------------


def test_ccr_66_maintenance_requires_write(readonly_client):
    r = readonly_client.post("/controls/maintenance/freshness")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# CCR-67: Dashboard requires read scope
# ---------------------------------------------------------------------------


def test_ccr_67_dashboard_requires_read(writeonly_client):
    r = writeonly_client.get("/controls/dashboard")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# CCR-68: List reviews with pagination
# ---------------------------------------------------------------------------


def test_ccr_68_review_pagination(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    for _ in range(3):
        client.post(f"/controls/{ctl_id}/reviews", json=_review_body())
    r = client.get(f"/controls/{ctl_id}/reviews?limit=2&offset=0")
    body = _json(r.json())
    assert len(body["items"]) == 2
    assert body["total"] == 3


# ---------------------------------------------------------------------------
# CCR-69: Audit old_state and new_state stored
# ---------------------------------------------------------------------------


def test_ccr_69_audit_states(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    r = client.get(f"/controls/{ctl_id}/audit")
    body = _json(r.json())
    status_events = [e for e in body["items"] if e["event_type"] == "control_activated"]
    assert len(status_events) >= 1
    evt = status_events[0]
    assert evt["old_state"] is not None
    assert evt["new_state"] is not None


# ---------------------------------------------------------------------------
# CCR-70: Audit count increases with each operation
# ---------------------------------------------------------------------------


def test_ccr_70_audit_count_grows(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    count1 = _json(client.get(f"/controls/{ctl_id}/audit").json())["total"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    count2 = _json(client.get(f"/controls/{ctl_id}/audit").json())["total"]
    assert count2 > count1


# ---------------------------------------------------------------------------
# CCR-71: Tenant B cannot complete Tenant A review
# ---------------------------------------------------------------------------


def test_ccr_71_cross_tenant_complete_review(client, client_b):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    review_id = _json(
        client.post(f"/controls/{ctl_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client_b.post(
        f"/controls/{ctl_id}/reviews/{review_id}/complete",
        json={"outcome": "effective"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-72: Tenant B cannot create review for Tenant A control
# ---------------------------------------------------------------------------


def test_ccr_72_cross_tenant_create_review(client, client_b):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client_b.post(f"/controls/{ctl_id}/reviews", json=_review_body())
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-73: All control types stored correctly
# ---------------------------------------------------------------------------


def test_ccr_73_all_control_types(client):
    for ctype in [
        "technical",
        "administrative",
        "physical",
        "process",
        "human",
        "detective",
        "preventive",
        "corrective",
        "compensating",
    ]:
        r = client.post(
            "/controls", json=_control_body(control_type=ctype, title=f"Ctrl {ctype}")
        )
        assert r.status_code == 201
        assert _json(r.json())["control_type"] == ctype


# ---------------------------------------------------------------------------
# CCR-74: All criticality levels stored correctly
# ---------------------------------------------------------------------------


def test_ccr_74_all_criticality_levels(client):
    for level in ["low", "medium", "high", "critical"]:
        r = client.post(
            "/controls", json=_control_body(criticality=level, title=f"Ctrl {level}")
        )
        assert r.status_code == 201
        assert _json(r.json())["criticality"] == level


# ---------------------------------------------------------------------------
# CCR-75: Full governance workflow
# ---------------------------------------------------------------------------


def test_ccr_75_full_governance_workflow(client):
    # Create control
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    assert _json(client.get(f"/controls/{ctl_id}").json())["control_status"] == "draft"

    # Activate
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})
    assert _json(client.get(f"/controls/{ctl_id}").json())["control_status"] == "active"

    # Link evidence
    client.post(f"/controls/{ctl_id}/evidence", json=_evidence_body())
    assert _json(client.get(f"/controls/{ctl_id}/evidence").json())["total"] == 1

    # Verify
    r = client.post(f"/controls/{ctl_id}/verify", json={})
    assert r.status_code == 200
    assert _json(r.json())["verification_status"] == "verified"

    # Create review
    review_id = _json(
        client.post(f"/controls/{ctl_id}/reviews", json=_review_body()).json()
    )["id"]

    # Complete review
    r2 = client.post(
        f"/controls/{ctl_id}/reviews/{review_id}/complete",
        json={"outcome": "effective"},
    )
    assert r2.status_code == 200

    # Link to risk acceptance
    r3 = client.post(f"/controls/{ctl_id}/risk-links", json=_risk_link_body())
    assert r3.status_code == 201

    # Check audit trail
    audit = _json(client.get(f"/controls/{ctl_id}/audit").json())
    assert audit["total"] >= 4

    # Dashboard reflects state
    dash = _json(client.get("/controls/dashboard").json())
    assert dash["active_controls"] >= 1
    assert dash["verified_controls"] >= 1


# ---------------------------------------------------------------------------
# CCR-76: Review sweep ignores completed reviews
# ---------------------------------------------------------------------------


def test_ccr_76_review_sweep_ignores_completed(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    review_id = _json(
        client.post(
            f"/controls/{ctl_id}/reviews",
            json=_review_body(review_date=_PAST_DUE),
        ).json()
    )["id"]
    client.post(
        f"/controls/{ctl_id}/reviews/{review_id}/complete",
        json={"outcome": "effective"},
    )
    r = client.post("/controls/maintenance/review-sweep")
    assert r.status_code == 200
    # The completed review should NOT be marked overdue
    review = _json(client.get(f"/controls/{ctl_id}/reviews").json())["items"][0]
    assert review["status"] == "completed"


# ---------------------------------------------------------------------------
# CCR-77: Update owner email
# ---------------------------------------------------------------------------


def test_ccr_77_update_owner_email(client):
    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    r = client.patch(
        f"/controls/{ctl_id}", json={"owner_email": "new-owner@example.com"}
    )
    assert r.status_code == 200
    assert _json(r.json())["owner_email"] == "new-owner@example.com"


# ---------------------------------------------------------------------------
# CCR-78: Non-existent control GET → 404
# ---------------------------------------------------------------------------


def test_ccr_78_get_nonexistent(client):
    r = client.get("/controls/nonexistent-id-xyz")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-79: Non-existent control PATCH → 404
# ---------------------------------------------------------------------------


def test_ccr_79_patch_nonexistent(client):
    r = client.patch("/controls/nonexistent-id-xyz", json={"title": "Ghost"})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-80: Verify non-existent control → 404
# ---------------------------------------------------------------------------


def test_ccr_80_verify_nonexistent(client):
    r = client.post("/controls/nonexistent-id-xyz/verify", json={})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# CCR-81: Create with HIGHLY_EFFECTIVE rejected (P2 fix — bot review)
# Controls start UNVERIFIED so HIGHLY_EFFECTIVE on creation violates the
# HIGHLY_EFFECTIVE-requires-VERIFIED invariant before any evidence exists.
# ---------------------------------------------------------------------------


def test_ccr_81_create_highly_effective_rejected(client):
    body = _control_body()
    body["effectiveness_rating"] = "highly_effective"
    r = client.post("/controls", json=body)
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# CCR-82: Complete an OVERDUE review (P2 fix — bot review)
# After run_review_sweep marks a review overdue, the /complete route must
# still accept it. Only COMPLETED is truly terminal.
# ---------------------------------------------------------------------------


def test_ccr_82_complete_overdue_review(client, db_session):
    from api.db_models_control_registry import ControlReview

    ctl_id = _json(client.post("/controls", json=_control_body()).json())["id"]
    rev_id = _json(
        client.post(
            f"/controls/{ctl_id}/reviews",
            json={
                "reviewer": "auditor@example.com",
                "review_date": _FUTURE_DUE,
            },
        ).json()
    )["id"]

    db_session.query(ControlReview).filter(ControlReview.id == rev_id).update(
        {"status": "overdue", "review_date": _PAST_DUE}
    )
    db_session.commit()

    r = client.post(
        f"/controls/{ctl_id}/reviews/{rev_id}/complete",
        json={"outcome": "effective"},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "completed"


# ---------------------------------------------------------------------------
# CCR-83: Freshness sweep downgrades HIGHLY_EFFECTIVE to EFFECTIVE (P2 fix)
# When verification expires, the HIGHLY_EFFECTIVE rating must be cleared
# so dashboards don't treat expired controls as highly effective.
# ---------------------------------------------------------------------------


def test_ccr_83_freshness_sweep_downgrades_highly_effective(client, db_session):
    from api.db_models_control_registry import ControlRegistry as ControlModel

    # Create with EFFECTIVE (highest allowed at creation), activate, then
    # manually push to VERIFIED + HIGHLY_EFFECTIVE + stale last_verified_at.
    body = _control_body()
    body["effectiveness_rating"] = "effective"
    ctl_id = _json(client.post("/controls", json=body).json())["id"]
    client.patch(f"/controls/{ctl_id}", json={"control_status": "active"})

    db_session.query(ControlModel).filter(ControlModel.id == ctl_id).update(
        {
            "verification_status": "verified",
            "effectiveness_rating": "highly_effective",
            "last_verified_at": _OLD_VERIFIED,
        }
    )
    db_session.commit()

    r = client.post("/controls/maintenance/freshness", json={})
    assert r.status_code == 200
    assert _json(r.json())["expired"] >= 1

    updated = _json(client.get(f"/controls/{ctl_id}").json())
    assert updated["verification_status"] == "expired"
    assert updated["effectiveness_rating"] == "effective"


def test_framework_authority_and_enterprise_controls_routes_coexist() -> None:
    import warnings
    from api.main import build_app
    from pydantic.warnings import PydanticDeprecatedSince20
    app = build_app(auth_enabled=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", PydanticDeprecatedSince20)
        paths = app.openapi()["paths"]
    assert "/enterprise-controls/frameworks" in paths
    assert "/frameworks" in paths
    assert "/controls/{control_id}/framework-mappings" in paths
