# tests/test_risk_governance.py
"""Risk Governance Engine test suite — PR 14.2.

Coverage:
  RAA-1   Create approval (PENDING)
  RAA-2   Get approval
  RAA-3   List approvals for a risk acceptance
  RAA-4   Approve (PENDING → APPROVED)
  RAA-5   Reject (PENDING → REJECTED)
  RAA-6   Approve sets approved_at timestamp
  RAA-7   Approval on non-existent risk acceptance → 404
  RAA-8   Approval on cross-tenant risk acceptance → 404
  RAA-9   Get non-existent approval → 404
  RAA-10  Decide on non-existent approval → 404
  RAA-11  Decide on terminal approval (REJECTED) → 422
  RAA-12  Decide with invalid decision value → 422
  RAA-13  Audit event on approval creation
  RAA-14  Audit event on approval granted
  RAA-15  Audit event on approval rejected
  RAA-16  Approval audit list is chronological
  RAA-17  Multi-approver: multiple approvals for same risk acceptance
  RAA-18  Quorum fields stored and returned
  RAA-19  COMMITTEE approval type stored
  RAA-20  DELEGATED approval type stored
  RAA-21  EMERGENCY approval type stored
  RAA-22  Approval expiry stored
  RAA-23  Expire overdue approvals endpoint sweeps PENDING past expires_at
  RAA-24  Expire overdue ignores future expires_at
  RAA-25  Expire overdue ignores non-PENDING approvals
  RAA-26  Approval status filter (list)
  RAA-27  Write scope required for approval create
  RAA-28  Read scope required for approval list
  RAA-29  Tenant B cannot list tenant A approvals
  RAA-30  Tenant B cannot decide on tenant A approval
  RAA-31  Create review (PENDING)
  RAA-32  Get review
  RAA-33  List reviews for a risk acceptance
  RAA-34  Complete review (PENDING → COMPLETED)
  RAA-35  Waive review (PENDING → WAIVED)
  RAA-36  Complete sets review_completed_at
  RAA-37  Complete with outcome stored
  RAA-38  Complete already-completed review → 409
  RAA-39  Complete with invalid status → 409
  RAA-40  Review on non-existent risk acceptance → 404
  RAA-41  Get non-existent review → 404
  RAA-42  Mark overdue reviews endpoint marks PENDING past due_at as OVERDUE
  RAA-43  Mark overdue ignores future due reviews
  RAA-44  Mark overdue ignores already-completed reviews
  RAA-45  Review status filter (list)
  RAA-46  Write scope required for review create
  RAA-47  Tenant B cannot complete tenant A review
  RAA-48  Create escalation (INFO level)
  RAA-49  Create escalation (CRITICAL level)
  RAA-50  List escalations for risk acceptance
  RAA-51  Escalation trigger stored correctly
  RAA-52  Escalation details stored
  RAA-53  Escalation resolved=False by default
  RAA-54  List escalations with resolved filter
  RAA-55  Escalation on cross-tenant risk acceptance → 404
  RAA-56  Create governance policy (SINGLE threshold)
  RAA-57  Get governance policy
  RAA-58  List governance policies
  RAA-59  Policy with QUORUM threshold stored
  RAA-60  Policy with sequential=True stored
  RAA-61  Policy with required_roles stored
  RAA-62  List active-only policies filter
  RAA-63  Get non-existent policy → 404
  RAA-64  Dashboard: pending_approvals count accurate
  RAA-65  Dashboard: overdue_reviews count accurate
  RAA-66  Dashboard: unresolved_escalations count accurate
  RAA-67  Dashboard: expired_risks count accurate
  RAA-68  Dashboard: governance_debt_score is non-negative integer
  RAA-69  Schema version 1.0 on all approval records
  RAA-70  Schema version 1.0 on all review records
  RAA-71  Timeline event emitted on approval creation
  RAA-72  Timeline event emitted on review creation
  RAA-73  Metrics increment: RISK_APPROVALS_TOTAL on create
  RAA-74  Metrics increment: RISK_REVIEWS_TOTAL on create
  RAA-75  Full governance workflow: create → approve → review → escalate
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding

_TENANT_A = "tenant-rg-a"
_TENANT_B = "tenant-rg-b"

_FUTURE_EXPIRY = "2099-01-01T00:00:00+00:00"
_PAST_EXPIRY = "2020-01-01T00:00:00+00:00"
_PAST_DUE = "2020-06-01T00:00:00+00:00"
_FUTURE_DUE = "2099-06-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json(value: dict[Any, Any] | None) -> dict[Any, Any]:
    assert value is not None
    return value


def _new_engagement(db: Session, tenant_id: str) -> str:
    eid = uuid.uuid4().hex
    now = "2026-01-01T00:00:00+00:00"
    eng = FaEngagement(
        id=eid,
        tenant_id=tenant_id,
        client_name="RG Test Client",
        assessor_id="assessor-rg",
        assessment_type="security",
        status="in_progress",
        engagement_metadata={},
        created_at=now,
        updated_at=now,
    )
    db.add(eng)
    db.commit()
    return eid


def _new_finding(db: Session, tenant_id: str, engagement_id: str) -> str:
    fid = uuid.uuid4().hex
    now = "2026-01-01T00:00:00+00:00"
    finding = FaNormalizedFinding(
        id=fid,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        finding_type="vulnerability",
        findings_hash=uuid.uuid4().hex,
        severity="high",
        status="open",
        title="RG Test Finding",
        description="A test finding for risk governance.",
        source_attribution="scanner",
        created_at=now,
        updated_at=now,
    )
    db.add(finding)
    db.commit()
    return fid


def _make_refs(db: Session, tenant_id: str) -> tuple[str, str]:
    """Return (assessment_id, finding_id)."""
    assessment_id = _new_engagement(db, tenant_id)
    finding_id = _new_finding(db, tenant_id, assessment_id)
    return assessment_id, finding_id


def _create_ra(client: TestClient, db: Session, tenant_id: str) -> str:
    """Create a risk acceptance in ACTIVE state. Returns ra_id."""
    assessment_id, finding_id = _make_refs(db, tenant_id)
    r = client.post(
        "/risk-acceptances",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "RG Test RA",
            "business_justification": "Test justification.",
            "risk_rationale": "Network segmentation limits exposure.",
            "accepted_by": "ciso@example.com",
            "compensating_controls": [],
            "review_required": False,
            "expires_at": _FUTURE_EXPIRY,
        },
    )
    assert r.status_code == 201, r.text
    ra_id = _json(r.json())["id"]
    # Drive DRAFT → PENDING_APPROVAL → APPROVED → ACTIVE
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "approved"}
    )
    r2 = client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "active"}
    )
    assert r2.status_code == 200, r2.text
    return ra_id


def _create_draft_ra(client: TestClient, db: Session, tenant_id: str) -> str:
    """Create a risk acceptance in DRAFT state. Returns ra_id."""
    assessment_id, finding_id = _make_refs(db, tenant_id)
    r = client.post(
        "/risk-acceptances",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "RG Draft RA",
            "business_justification": "Test justification.",
            "risk_rationale": "Segmentation.",
            "accepted_by": "ciso@example.com",
            "compensating_controls": [],
            "review_required": False,
        },
    )
    assert r.status_code == 201, r.text
    return _json(r.json())["id"]


def _approval_body(**overrides: Any) -> dict:
    base: dict[str, Any] = {
        "approver_name": "Jane CISO",
        "approver_email": "jane@example.com",
        "approver_role": "CISO",
        "approval_authority": "executive",
        "approval_type": "single",
        "is_required": True,
    }
    base.update(overrides)
    return base


def _review_body(**overrides: Any) -> dict:
    base: dict[str, Any] = {
        "review_type": "periodic",
        "reviewer": "risk-team@example.com",
        "review_due_at": _FUTURE_DUE,
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
# RAA-1: Create approval
# ---------------------------------------------------------------------------


def test_raa_1_create_approval(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    assert r.status_code == 201
    body = _json(r.json())
    assert body["status"] == "pending"
    assert body["risk_acceptance_id"] == ra_id
    assert body["approver_name"] == "Jane CISO"


# ---------------------------------------------------------------------------
# RAA-2: Get approval
# ---------------------------------------------------------------------------


def test_raa_2_get_approval(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    created = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )
    r = client.get(f"/risk-acceptances/{ra_id}/approvals/{created['id']}")
    assert r.status_code == 200
    assert _json(r.json())["id"] == created["id"]


# ---------------------------------------------------------------------------
# RAA-3: List approvals
# ---------------------------------------------------------------------------


def test_raa_3_list_approvals(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    client.post(
        f"/risk-acceptances/{ra_id}/approvals",
        json=_approval_body(approver_name="Bob CFO"),
    )
    r = client.get(f"/risk-acceptances/{ra_id}/approvals")
    assert r.status_code == 200
    body = _json(r.json())
    assert body["total"] == 2
    assert len(body["items"]) == 2


# ---------------------------------------------------------------------------
# RAA-4: Approve (PENDING → APPROVED)
# ---------------------------------------------------------------------------


def test_raa_4_approve(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved", "comments": "Looks good."},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "approved"


# ---------------------------------------------------------------------------
# RAA-5: Reject (PENDING → REJECTED)
# ---------------------------------------------------------------------------


def test_raa_5_reject(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "rejected", "reason": "Risk too high."},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "rejected"


# ---------------------------------------------------------------------------
# RAA-6: Approve sets approved_at
# ---------------------------------------------------------------------------


def test_raa_6_approve_sets_approved_at(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved"},
    )
    body = _json(r.json())
    assert body["approved_at"] is not None
    assert "2026" in body["approved_at"] or "202" in body["approved_at"]


# ---------------------------------------------------------------------------
# RAA-7: Approval on non-existent RA → 404
# ---------------------------------------------------------------------------


def test_raa_7_approval_nonexistent_ra(client):
    r = client.post(
        f"/risk-acceptances/{uuid.uuid4().hex}/approvals", json=_approval_body()
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-8: Cross-tenant RA → 404
# ---------------------------------------------------------------------------


def test_raa_8_cross_tenant_ra(client, client_b, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client_b.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-9: Get non-existent approval → 404
# ---------------------------------------------------------------------------


def test_raa_9_get_nonexistent_approval(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.get(f"/risk-acceptances/{ra_id}/approvals/{uuid.uuid4().hex}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-10: Decide on non-existent approval → 404
# ---------------------------------------------------------------------------


def test_raa_10_decide_nonexistent_approval(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals/{uuid.uuid4().hex}/decision",
        json={"decision": "approved"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-11: Decide on terminal approval → 422
# ---------------------------------------------------------------------------


def test_raa_11_decide_terminal_approval(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "rejected"},
    )
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RAA-12: Decide with invalid decision → 422
# ---------------------------------------------------------------------------


def test_raa_12_decide_invalid_decision(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "revoked"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RAA-13: Audit event on approval creation
# ---------------------------------------------------------------------------


def test_raa_13_audit_on_create(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    r = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}/audit")
    assert r.status_code == 200
    body = _json(r.json())
    assert body["total"] >= 1
    event_types = [a["event_type"] for a in body["items"]]
    assert "approval_requested" in event_types


# ---------------------------------------------------------------------------
# RAA-14: Audit event on approval granted
# ---------------------------------------------------------------------------


def test_raa_14_audit_on_granted(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved"},
    )
    r = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}/audit")
    body = _json(r.json())
    event_types = [a["event_type"] for a in body["items"]]
    assert "approval_granted" in event_types


# ---------------------------------------------------------------------------
# RAA-15: Audit event on approval rejected
# ---------------------------------------------------------------------------


def test_raa_15_audit_on_rejected(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "rejected"},
    )
    r = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}/audit")
    body = _json(r.json())
    event_types = [a["event_type"] for a in body["items"]]
    assert "approval_rejected" in event_types


# ---------------------------------------------------------------------------
# RAA-16: Audit list is chronological
# ---------------------------------------------------------------------------


def test_raa_16_audit_chronological(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved"},
    )
    r = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}/audit")
    items = _json(r.json())["items"]
    timestamps = [a["event_at"] for a in items]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# RAA-17: Multi-approver — multiple approvals for same RA
# ---------------------------------------------------------------------------


def test_raa_17_multi_approver(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    for name in ["CISO", "CRO", "Legal"]:
        r = client.post(
            f"/risk-acceptances/{ra_id}/approvals",
            json=_approval_body(approver_name=name, approval_type="multi_approver"),
        )
        assert r.status_code == 201
    r = client.get(f"/risk-acceptances/{ra_id}/approvals")
    assert _json(r.json())["total"] == 3


# ---------------------------------------------------------------------------
# RAA-18: Quorum fields stored
# ---------------------------------------------------------------------------


def test_raa_18_quorum_fields(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals",
        json=_approval_body(
            approval_type="committee", quorum_required=3, quorum_position=1
        ),
    )
    body = _json(r.json())
    assert body["quorum_required"] == 3
    assert body["quorum_position"] == 1


# ---------------------------------------------------------------------------
# RAA-19: COMMITTEE approval type
# ---------------------------------------------------------------------------


def test_raa_19_committee_type(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals",
        json=_approval_body(approval_type="committee"),
    )
    assert _json(r.json())["approval_type"] == "committee"


# ---------------------------------------------------------------------------
# RAA-20: DELEGATED approval type
# ---------------------------------------------------------------------------


def test_raa_20_delegated_type(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals",
        json=_approval_body(approval_type="delegated"),
    )
    assert _json(r.json())["approval_type"] == "delegated"


# ---------------------------------------------------------------------------
# RAA-21: EMERGENCY approval type
# ---------------------------------------------------------------------------


def test_raa_21_emergency_type(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals",
        json=_approval_body(approval_type="emergency"),
    )
    assert _json(r.json())["approval_type"] == "emergency"


# ---------------------------------------------------------------------------
# RAA-22: Approval expiry stored
# ---------------------------------------------------------------------------


def test_raa_22_approval_expiry(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals",
        json=_approval_body(expires_at=_FUTURE_EXPIRY),
    )
    assert _json(r.json())["expires_at"] == _FUTURE_EXPIRY


# ---------------------------------------------------------------------------
# RAA-23: Expire overdue approvals sweeps past expires_at
# ---------------------------------------------------------------------------


def test_raa_23_expire_overdue_approvals(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals",
            json=_approval_body(expires_at=_PAST_EXPIRY),
        ).json()
    )["id"]
    r = client.post("/risk-governance/maintenance/expire-approvals")
    assert r.status_code == 200
    assert _json(r.json())["expired"] >= 1
    r2 = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}")
    assert _json(r2.json())["status"] == "expired"


# ---------------------------------------------------------------------------
# RAA-24: Expire overdue ignores future expires_at
# ---------------------------------------------------------------------------


def test_raa_24_expire_ignores_future(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals",
            json=_approval_body(expires_at=_FUTURE_EXPIRY),
        ).json()
    )["id"]
    client.post("/risk-governance/maintenance/expire-approvals")
    r = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}")
    assert _json(r.json())["status"] == "pending"


# ---------------------------------------------------------------------------
# RAA-25: Expire overdue ignores non-PENDING approvals
# ---------------------------------------------------------------------------


def test_raa_25_expire_ignores_non_pending(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals",
            json=_approval_body(expires_at=_PAST_EXPIRY),
        ).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved"},
    )
    r_before = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}")
    status_before = _json(r_before.json())["status"]
    client.post("/risk-governance/maintenance/expire-approvals")
    r_after = client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}")
    assert _json(r_after.json())["status"] == status_before


# ---------------------------------------------------------------------------
# RAA-26: Approval status filter
# ---------------------------------------------------------------------------


def test_raa_26_approval_status_filter(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved"},
    )
    client.post(
        f"/risk-acceptances/{ra_id}/approvals",
        json=_approval_body(approver_name="Pending"),
    )
    r = client.get(f"/risk-acceptances/{ra_id}/approvals?status=approved")
    body = _json(r.json())
    assert body["total"] == 1
    assert all(a["status"] == "approved" for a in body["items"])


# ---------------------------------------------------------------------------
# RAA-27: Write scope required for approval create
# ---------------------------------------------------------------------------


def test_raa_27_write_scope_required(readonly_client, db_session):
    ra_id = _create_draft_ra(
        TestClient(
            readonly_client.app,
            headers={
                "X-API-Key": mint_key(
                    "governance:read", "governance:write", tenant_id=_TENANT_A
                )
            },
        ),
        db_session,
        _TENANT_A,
    )
    r = readonly_client.post(
        f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# RAA-28: Read scope required for approval list
# ---------------------------------------------------------------------------


def test_raa_28_read_scope_required(writeonly_client, db_session):
    ra_id = _create_ra(
        TestClient(
            writeonly_client.app,
            headers={
                "X-API-Key": mint_key(
                    "governance:read", "governance:write", tenant_id=_TENANT_A
                )
            },
        ),
        db_session,
        _TENANT_A,
    )
    r = writeonly_client.get(f"/risk-acceptances/{ra_id}/approvals")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# RAA-29: Tenant B cannot list tenant A approvals
# ---------------------------------------------------------------------------


def test_raa_29_tenant_isolation_list(client, client_b, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    r = client_b.get(f"/risk-acceptances/{ra_id}/approvals")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-30: Tenant B cannot decide on tenant A approval
# ---------------------------------------------------------------------------


def test_raa_30_tenant_isolation_decide(client, client_b, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    r = client_b.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-31: Create review
# ---------------------------------------------------------------------------


def test_raa_31_create_review(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body())
    assert r.status_code == 201
    body = _json(r.json())
    assert body["status"] == "pending"
    assert body["risk_acceptance_id"] == ra_id


# ---------------------------------------------------------------------------
# RAA-32: Get review
# ---------------------------------------------------------------------------


def test_raa_32_get_review(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client.get(f"/risk-acceptances/{ra_id}/reviews/{review_id}")
    assert r.status_code == 200
    assert _json(r.json())["id"] == review_id


# ---------------------------------------------------------------------------
# RAA-33: List reviews
# ---------------------------------------------------------------------------


def test_raa_33_list_reviews(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body())
    client.post(
        f"/risk-acceptances/{ra_id}/reviews",
        json=_review_body(review_type="compliance"),
    )
    r = client.get(f"/risk-acceptances/{ra_id}/reviews")
    body = _json(r.json())
    assert body["total"] == 2
    assert len(body["items"]) == 2


# ---------------------------------------------------------------------------
# RAA-34: Complete review (PENDING → COMPLETED)
# ---------------------------------------------------------------------------


def test_raa_34_complete_review(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed", "outcome": "continue"},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "completed"


# ---------------------------------------------------------------------------
# RAA-35: Waive review (PENDING → WAIVED)
# ---------------------------------------------------------------------------


def test_raa_35_waive_review(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "waived", "review_notes": "Annual review waived by CISO."},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "waived"


# ---------------------------------------------------------------------------
# RAA-36: Complete sets review_completed_at
# ---------------------------------------------------------------------------


def test_raa_36_completed_at_set(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed"},
    )
    assert _json(r.json())["review_completed_at"] is not None


# ---------------------------------------------------------------------------
# RAA-37: Complete with outcome stored
# ---------------------------------------------------------------------------


def test_raa_37_outcome_stored(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed", "outcome": "revoke"},
    )
    assert _json(r.json())["outcome"] == "revoke"


# ---------------------------------------------------------------------------
# RAA-38: Complete already-completed review → 409
# ---------------------------------------------------------------------------


def test_raa_38_complete_twice_conflict(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed"},
    )
    r = client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed"},
    )
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# RAA-39: Complete with invalid status → 409
# ---------------------------------------------------------------------------


def test_raa_39_complete_invalid_status(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "pending"},
    )
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# RAA-40: Review on non-existent RA → 404
# ---------------------------------------------------------------------------


def test_raa_40_review_nonexistent_ra(client):
    r = client.post(
        f"/risk-acceptances/{uuid.uuid4().hex}/reviews", json=_review_body()
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-41: Get non-existent review → 404
# ---------------------------------------------------------------------------


def test_raa_41_get_nonexistent_review(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.get(f"/risk-acceptances/{ra_id}/reviews/{uuid.uuid4().hex}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-42: Mark overdue reviews
# ---------------------------------------------------------------------------


def test_raa_42_mark_overdue_reviews(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/reviews",
            json=_review_body(review_due_at=_PAST_DUE),
        ).json()
    )["id"]
    r = client.post("/risk-governance/maintenance/mark-overdue-reviews")
    assert r.status_code == 200
    assert _json(r.json())["marked_overdue"] >= 1
    r2 = client.get(f"/risk-acceptances/{ra_id}/reviews/{review_id}")
    assert _json(r2.json())["status"] == "overdue"


# ---------------------------------------------------------------------------
# RAA-43: Mark overdue ignores future reviews
# ---------------------------------------------------------------------------


def test_raa_43_overdue_ignores_future(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/reviews",
            json=_review_body(review_due_at=_FUTURE_DUE),
        ).json()
    )["id"]
    client.post("/risk-governance/maintenance/mark-overdue-reviews")
    r = client.get(f"/risk-acceptances/{ra_id}/reviews/{review_id}")
    assert _json(r.json())["status"] == "pending"


# ---------------------------------------------------------------------------
# RAA-44: Mark overdue ignores completed reviews
# ---------------------------------------------------------------------------


def test_raa_44_overdue_ignores_completed(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/reviews",
            json=_review_body(review_due_at=_PAST_DUE),
        ).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed"},
    )
    client.post("/risk-governance/maintenance/mark-overdue-reviews")
    r_after = client.get(f"/risk-acceptances/{ra_id}/reviews/{review_id}")
    assert _json(r_after.json())["status"] == "completed"


# ---------------------------------------------------------------------------
# RAA-45: Review status filter
# ---------------------------------------------------------------------------


def test_raa_45_review_status_filter(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed"},
    )
    client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body())
    r = client.get(f"/risk-acceptances/{ra_id}/reviews?status=completed")
    body = _json(r.json())
    assert body["total"] == 1
    assert all(rv["status"] == "completed" for rv in body["items"])


# ---------------------------------------------------------------------------
# RAA-46: Write scope required for review create
# ---------------------------------------------------------------------------


def test_raa_46_write_scope_required_review(readonly_client, db_session):
    ra_id = _create_draft_ra(
        TestClient(
            readonly_client.app,
            headers={
                "X-API-Key": mint_key(
                    "governance:read", "governance:write", tenant_id=_TENANT_A
                )
            },
        ),
        db_session,
        _TENANT_A,
    )
    r = readonly_client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body())
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# RAA-47: Tenant B cannot complete tenant A review
# ---------------------------------------------------------------------------


def test_raa_47_tenant_isolation_review(client, client_b, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    r = client_b.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-48: Create escalation (INFO level)
# ---------------------------------------------------------------------------


def test_raa_48_escalation_info(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=info",
    )
    assert r.status_code == 201
    body = _json(r.json())
    assert body["level"] == "info"
    assert body["trigger"] == "missed_review"


# ---------------------------------------------------------------------------
# RAA-49: Create escalation (CRITICAL level)
# ---------------------------------------------------------------------------


def test_raa_49_escalation_critical(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=critical_residual_risk&level=critical",
    )
    assert r.status_code == 201
    assert _json(r.json())["level"] == "critical"


# ---------------------------------------------------------------------------
# RAA-50: List escalations
# ---------------------------------------------------------------------------


def test_raa_50_list_escalations(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=warning"
    )
    client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=expired_approval&level=high"
    )
    r = client.get(f"/risk-acceptances/{ra_id}/escalations")
    body = _json(r.json())
    assert body["total"] == 2


# ---------------------------------------------------------------------------
# RAA-51: Escalation trigger stored correctly
# ---------------------------------------------------------------------------


def test_raa_51_escalation_trigger(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=expired_acceptance&level=critical",
    )
    assert _json(r.json())["trigger"] == "expired_acceptance"


# ---------------------------------------------------------------------------
# RAA-52: Escalation resolved=False by default
# ---------------------------------------------------------------------------


def test_raa_52_escalation_not_resolved(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=info"
    )
    assert _json(r.json())["resolved"] is False


# ---------------------------------------------------------------------------
# RAA-53: Escalation details stored (none sent = empty dict in response)
# ---------------------------------------------------------------------------


def test_raa_53_escalation_default_details(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=info"
    )
    body = _json(r.json())
    assert body["details"] is not None


# ---------------------------------------------------------------------------
# RAA-54: List escalations with resolved filter
# ---------------------------------------------------------------------------


def test_raa_54_escalation_resolved_filter(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=info"
    )
    r_unresolved = client.get(f"/risk-acceptances/{ra_id}/escalations?resolved=false")
    assert _json(r_unresolved.json())["total"] >= 1
    r_resolved = client.get(f"/risk-acceptances/{ra_id}/escalations?resolved=true")
    assert _json(r_resolved.json())["total"] == 0


# ---------------------------------------------------------------------------
# RAA-55: Escalation on cross-tenant RA → 404
# ---------------------------------------------------------------------------


def test_raa_55_escalation_cross_tenant(client, client_b, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client_b.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=info"
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-56: Create governance policy
# ---------------------------------------------------------------------------


def test_raa_56_create_policy(client):
    r = client.post(
        "/risk-governance/policies",
        json={
            "policy_name": "Standard Risk Policy",
            "approval_threshold": "single",
            "required_count": 1,
            "review_frequency_days": 90,
        },
    )
    assert r.status_code == 201
    body = _json(r.json())
    assert body["policy_name"] == "Standard Risk Policy"
    assert body["active"] is True


# ---------------------------------------------------------------------------
# RAA-57: Get governance policy
# ---------------------------------------------------------------------------


def test_raa_57_get_policy(client):
    policy_id = _json(
        client.post(
            "/risk-governance/policies",
            json={"policy_name": "Get Test Policy", "approval_threshold": "single"},
        ).json()
    )["id"]
    r = client.get(f"/risk-governance/policies/{policy_id}")
    assert r.status_code == 200
    assert _json(r.json())["id"] == policy_id


# ---------------------------------------------------------------------------
# RAA-58: List governance policies
# ---------------------------------------------------------------------------


def test_raa_58_list_policies(client):
    client.post(
        "/risk-governance/policies",
        json={"policy_name": "Policy A", "approval_threshold": "single"},
    )
    client.post(
        "/risk-governance/policies",
        json={"policy_name": "Policy B", "approval_threshold": "majority"},
    )
    r = client.get("/risk-governance/policies")
    assert r.status_code == 200
    body = _json(r.json())
    assert body["total"] >= 2


# ---------------------------------------------------------------------------
# RAA-59: Policy with QUORUM threshold
# ---------------------------------------------------------------------------


def test_raa_59_quorum_policy(client):
    r = client.post(
        "/risk-governance/policies",
        json={
            "policy_name": "Quorum Policy",
            "approval_threshold": "quorum",
            "quorum_percentage": 67,
        },
    )
    body = _json(r.json())
    assert body["approval_threshold"] == "quorum"
    assert body["quorum_percentage"] == 67


# ---------------------------------------------------------------------------
# RAA-60: Policy with sequential=True
# ---------------------------------------------------------------------------


def test_raa_60_sequential_policy(client):
    r = client.post(
        "/risk-governance/policies",
        json={
            "policy_name": "Sequential Policy",
            "approval_threshold": "unanimous",
            "sequential": True,
        },
    )
    assert _json(r.json())["sequential"] is True


# ---------------------------------------------------------------------------
# RAA-61: Policy with required_roles
# ---------------------------------------------------------------------------


def test_raa_61_required_roles(client):
    roles = ["CISO", "CRO", "Legal"]
    r = client.post(
        "/risk-governance/policies",
        json={
            "policy_name": "Roles Policy",
            "approval_threshold": "unanimous",
            "required_roles": roles,
        },
    )
    assert _json(r.json())["required_roles"] == roles


# ---------------------------------------------------------------------------
# RAA-62: List active-only policies
# ---------------------------------------------------------------------------


def test_raa_62_active_only_filter(client):
    client.post(
        "/risk-governance/policies",
        json={"policy_name": "Active Policy", "approval_threshold": "single"},
    )
    r = client.get("/risk-governance/policies?active_only=true")
    body = _json(r.json())
    assert all(p["active"] for p in body["items"])


# ---------------------------------------------------------------------------
# RAA-63: Get non-existent policy → 404
# ---------------------------------------------------------------------------


def test_raa_63_get_nonexistent_policy(client):
    r = client.get(f"/risk-governance/policies/{uuid.uuid4().hex}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RAA-64: Dashboard pending_approvals count
# ---------------------------------------------------------------------------


def test_raa_64_dashboard_pending_approvals(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r_before = client.get("/risk-governance/dashboard")
    before = _json(r_before.json())["pending_approvals"]
    client.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    r_after = client.get("/risk-governance/dashboard")
    assert _json(r_after.json())["pending_approvals"] >= before + 1


# ---------------------------------------------------------------------------
# RAA-65: Dashboard overdue_reviews count
# ---------------------------------------------------------------------------


def test_raa_65_dashboard_overdue_reviews(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(
        f"/risk-acceptances/{ra_id}/reviews", json=_review_body(review_due_at=_PAST_DUE)
    )
    client.post("/risk-governance/maintenance/mark-overdue-reviews")
    r = client.get("/risk-governance/dashboard")
    assert _json(r.json())["overdue_reviews"] >= 1


# ---------------------------------------------------------------------------
# RAA-66: Dashboard unresolved_escalations count
# ---------------------------------------------------------------------------


def test_raa_66_dashboard_unresolved_escalations(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r_before = client.get("/risk-governance/dashboard")
    before = _json(r_before.json())["unresolved_escalations"]
    client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=warning"
    )
    r_after = client.get("/risk-governance/dashboard")
    assert _json(r_after.json())["unresolved_escalations"] >= before + 1


# ---------------------------------------------------------------------------
# RAA-67: Dashboard expired_risks count
# ---------------------------------------------------------------------------


def test_raa_67_dashboard_expired_risks(client, db_session):
    from services.risk_acceptance.engine import RiskAcceptanceEngine

    _create_ra(client, db_session, _TENANT_A)
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        svc.expire_overdue(actor="test")
        db.commit()
    r = client.get("/risk-governance/dashboard")
    body = _json(r.json())
    assert isinstance(body["expired_risks"], int)
    assert body["expired_risks"] >= 0


# ---------------------------------------------------------------------------
# RAA-68: Dashboard governance_debt_score is non-negative int
# ---------------------------------------------------------------------------


def test_raa_68_dashboard_debt_score(client):
    r = client.get("/risk-governance/dashboard")
    assert r.status_code == 200
    body = _json(r.json())
    assert isinstance(body["governance_debt_score"], int)
    assert body["governance_debt_score"] >= 0


# ---------------------------------------------------------------------------
# RAA-69: Schema version on approval records
# ---------------------------------------------------------------------------


def test_raa_69_schema_version_approval(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    assert _json(r.json())["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# RAA-70: Schema version on review records
# ---------------------------------------------------------------------------


def test_raa_70_schema_version_review(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)
    r = client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body())
    assert _json(r.json())["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# RAA-71: Timeline event on approval creation
# ---------------------------------------------------------------------------


def test_raa_71_timeline_approval_created(client, db_session):
    from api.db_models_timeline import TimelineEventRecord

    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(TimelineEventRecord)
            .filter(
                TimelineEventRecord.tenant_id == _TENANT_A,
                TimelineEventRecord.source_id == ra_id,
                TimelineEventRecord.source_type == "RISK_GOVERNANCE",
                TimelineEventRecord.event_type == "approval_requested",
            )
            .all()
        )
    assert len(events) >= 1


# ---------------------------------------------------------------------------
# RAA-72: Timeline event on review creation
# ---------------------------------------------------------------------------


def test_raa_72_timeline_review_created(client, db_session):
    from api.db_models_timeline import TimelineEventRecord

    ra_id = _create_ra(client, db_session, _TENANT_A)
    client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body())
    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(TimelineEventRecord)
            .filter(
                TimelineEventRecord.tenant_id == _TENANT_A,
                TimelineEventRecord.source_id == ra_id,
                TimelineEventRecord.source_type == "RISK_GOVERNANCE",
                TimelineEventRecord.event_type == "review_created",
            )
            .all()
        )
    assert len(events) >= 1


# ---------------------------------------------------------------------------
# RAA-73: Metrics: RISK_APPROVALS_TOTAL increments on create
# ---------------------------------------------------------------------------


def test_raa_73_metrics_approvals_total(client, db_session):
    from api.observability.metrics import RISK_APPROVALS_TOTAL

    ra_id = _create_ra(client, db_session, _TENANT_A)
    before = RISK_APPROVALS_TOTAL._value.get()
    client.post(f"/risk-acceptances/{ra_id}/approvals", json=_approval_body())
    assert RISK_APPROVALS_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# RAA-74: Metrics: RISK_REVIEWS_TOTAL increments on create
# ---------------------------------------------------------------------------


def test_raa_74_metrics_reviews_total(client, db_session):
    from api.observability.metrics import RISK_REVIEWS_TOTAL

    ra_id = _create_ra(client, db_session, _TENANT_A)
    before = RISK_REVIEWS_TOTAL._value.get()
    client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body())
    assert RISK_REVIEWS_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# RAA-75: Full governance workflow
# ---------------------------------------------------------------------------


def test_raa_75_full_governance_workflow(client, db_session):
    ra_id = _create_ra(client, db_session, _TENANT_A)

    # Create approval
    approval_id = _json(
        client.post(
            f"/risk-acceptances/{ra_id}/approvals", json=_approval_body()
        ).json()
    )["id"]
    assert (
        _json(client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}").json())[
            "status"
        ]
        == "pending"
    )

    # Grant approval
    r = client.post(
        f"/risk-acceptances/{ra_id}/approvals/{approval_id}/decision",
        json={"decision": "approved", "comments": "Approved by CISO."},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "approved"

    # Create review
    review_id = _json(
        client.post(f"/risk-acceptances/{ra_id}/reviews", json=_review_body()).json()
    )["id"]
    assert (
        _json(client.get(f"/risk-acceptances/{ra_id}/reviews/{review_id}").json())[
            "status"
        ]
        == "pending"
    )

    # Complete review
    r2 = client.post(
        f"/risk-acceptances/{ra_id}/reviews/{review_id}/complete",
        json={"status": "completed", "outcome": "continue"},
    )
    assert r2.status_code == 200

    # Create escalation
    r3 = client.post(
        f"/risk-acceptances/{ra_id}/escalations?trigger=missed_review&level=warning"
    )
    assert r3.status_code == 201

    # Dashboard shows governance state
    dash = _json(client.get("/risk-governance/dashboard").json())
    assert isinstance(dash["governance_debt_score"], int)

    # Audit trail preserved
    audit = _json(
        client.get(f"/risk-acceptances/{ra_id}/approvals/{approval_id}/audit").json()
    )
    assert audit["total"] >= 2
