# tests/test_risk_acceptance.py
"""Risk Acceptance Governance test suite — PR 14.1.

Coverage:
  RA-1   Create risk acceptance (DRAFT)
  RA-2   Get risk acceptance
  RA-3   List risk acceptances
  RA-4   Update risk acceptance fields
  RA-5   Update on terminal record denied (409)
  RA-6   Get non-existent record (404)
  RA-7   Tenant isolation — tenant B cannot see tenant A records
  RA-8   Cross-tenant denial — wrong tenant returns 404
  RA-9   Create with compensating controls
  RA-10  Create with review scheduling
  RA-11  Audit event on create
  RA-12  Audit event on update
  RA-13  Audit event on transition
  RA-14  DRAFT → PENDING_APPROVAL
  RA-15  PENDING_APPROVAL → APPROVED (with approver attribution)
  RA-16  APPROVED → ACTIVE (accepted_at set)
  RA-17  ACTIVE → REVOKED (terminal)
  RA-18  PENDING_APPROVAL → REJECTED (terminal)
  RA-19  DRAFT → REVOKED (terminal)
  RA-20  ACTIVE → EXPIRED (illegal manual — EXPIRED only via automatic)
  RA-21  CLOSED → any transition denied (422)
  RA-22  REVOKED → any transition denied (422)
  RA-23  REJECTED → any transition denied (422)
  RA-24  OPEN → ACTIVE denied (422) — skipped states
  RA-25  Transition reason stored in audit
  RA-26  Allowed transitions API — DRAFT
  RA-27  Allowed transitions API — PENDING_APPROVAL
  RA-28  Allowed transitions API — ACTIVE
  RA-29  Allowed transitions API — terminal states return empty
  RA-30  Metrics increment on create
  RA-31  Metrics increment on approve
  RA-32  Metrics increment on reject
  RA-33  Metrics increment on revoke
  RA-34  Compensating controls stored and returned
  RA-35  Residual risk LOW/MEDIUM/HIGH/CRITICAL round-trips
  RA-36  Expiration sweep — ACTIVE record with past expires_at becomes EXPIRED
  RA-37  Expiration sweep — future expires_at unchanged
  RA-38  Review frequency stored
  RA-39  next_review_at stored and returned
  RA-40  Remediation task link stored
  RA-41  List filter by status
  RA-42  List filter by finding_id
  RA-43  List filter by assessment_id
  RA-44  List pagination (limit + offset)
  RA-45  Audit list returned in chronological order
  RA-46  Audit survives parent (record lookup still works even after direct status inspect)
  RA-47  Authorization — write route rejected without write scope
  RA-48  Authorization — read route rejected without read scope
  RA-49  Schema version 1.0 on all created records
  RA-50  State machine integrity — all terminal states have no allowed transitions
  RA-51  Orphaned finding reference rejected (P1 bot fix)
  RA-52  Cross-tenant finding reference rejected (P1 bot fix)
  RA-53  APPROVED → ACTIVE blocked without expires_at (P1 bot fix)
  RA-54  List count matches filtered items for remediation_task_id (P2 bot fix)
  RA-55  Expiry with non-UTC offset timezone swept correctly (P2 bot fix)
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
from services.risk_acceptance.schemas import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATUSES,
    RiskAcceptanceStatus,
)

_TENANT_A = "tenant-ra-a"
_TENANT_B = "tenant-ra-b"


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
        client_name="RA Test Client",
        assessor_id="assessor-ra",
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
        title="RA Test Finding",
        description="A test finding for risk acceptance.",
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


_FUTURE_EXPIRY = "2099-01-01T00:00:00+00:00"
_PAST_EXPIRY = "2020-01-01T00:00:00+00:00"


def _create_body(assessment_id: str, finding_id: str, **overrides: Any) -> dict:
    base: dict[str, Any] = {
        "finding_id": finding_id,
        "assessment_id": assessment_id,
        "title": "Unpatched OpenSSL CVE-2024-XXXX",
        "business_justification": "Patch not available; vendor ETA Q3 2026.",
        "risk_rationale": "Network segmentation limits exposure to internal network only.",
        "accepted_by": "ciso@example.com",
        "compensating_controls": [],
        "review_required": False,
    }
    base.update(overrides)
    return base


def _drive_to_active(client: TestClient, ra_id: str) -> None:
    """Drive a risk acceptance record from DRAFT to ACTIVE."""
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "approved"}
    )
    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "active"}
    )
    assert r.status_code == 200, f"APPROVED→ACTIVE failed: {r.text}"


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
# RA-1: Create risk acceptance
# ---------------------------------------------------------------------------


def test_ra_1_create(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    r = client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))
    assert r.status_code == 201
    data = _json(r.json())
    assert data["status"] == "draft"
    assert data["finding_id"] == finding_id
    assert data["assessment_id"] == assessment_id
    assert data["title"] == "Unpatched OpenSSL CVE-2024-XXXX"
    assert data["accepted_by"] == "ciso@example.com"
    assert "id" in data


# ---------------------------------------------------------------------------
# RA-2: Get risk acceptance
# ---------------------------------------------------------------------------


def test_ra_2_get(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client.get(f"/risk-acceptances/{ra_id}")
    assert r.status_code == 200
    assert _json(r.json())["id"] == ra_id


# ---------------------------------------------------------------------------
# RA-3: List risk acceptances
# ---------------------------------------------------------------------------


def test_ra_3_list(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))
    client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))

    r = client.get("/risk-acceptances")
    assert r.status_code == 200
    data = _json(r.json())
    assert data["total"] >= 2
    assert len(data["items"]) >= 2


# ---------------------------------------------------------------------------
# RA-4: Update risk acceptance fields
# ---------------------------------------------------------------------------


def test_ra_4_update(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client.patch(
        f"/risk-acceptances/{ra_id}",
        json={"title": "Updated Title", "inherent_risk": "high"},
    )
    assert r.status_code == 200
    data = _json(r.json())
    assert data["title"] == "Updated Title"
    assert data["inherent_risk"] == "high"


# ---------------------------------------------------------------------------
# RA-5: Update on terminal record denied (409)
# ---------------------------------------------------------------------------


def test_ra_5_update_terminal_denied(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    # Drive to REVOKED (terminal)
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "revoked", "reason": "test revocation"},
    )

    r = client.patch(f"/risk-acceptances/{ra_id}", json={"title": "Too Late"})
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# RA-6: Get non-existent record returns 404
# ---------------------------------------------------------------------------


def test_ra_6_get_not_found(client: TestClient) -> None:
    r = client.get(f"/risk-acceptances/{uuid.uuid4().hex}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RA-7: Tenant isolation — tenant B list is empty when only tenant A has records
# ---------------------------------------------------------------------------


def test_ra_7_tenant_isolation(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))

    r = client_b.get("/risk-acceptances")
    assert r.status_code == 200
    data = _json(r.json())
    # Tenant B should not see Tenant A's records
    tenant_a_ids = {
        item["id"] for item in _json(client.get("/risk-acceptances").json())["items"]
    }
    for item in data["items"]:
        assert item["id"] not in tenant_a_ids


# ---------------------------------------------------------------------------
# RA-8: Cross-tenant denial — tenant B cannot GET tenant A's record
# ---------------------------------------------------------------------------


def test_ra_8_cross_tenant_get_denied(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client_b.get(f"/risk-acceptances/{ra_id}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# RA-9: Create with compensating controls
# ---------------------------------------------------------------------------


def test_ra_9_compensating_controls(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    controls = [
        {"type": "network_segmentation", "description": "VLAN isolation applied"},
        {"type": "monitoring", "description": "24/7 SOC monitoring active"},
    ]
    r = client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, finding_id, compensating_controls=controls),
    )
    assert r.status_code == 201
    data = _json(r.json())
    assert len(data["compensating_controls"]) == 2
    types = {c["type"] for c in data["compensating_controls"]}
    assert "network_segmentation" in types
    assert "monitoring" in types


# ---------------------------------------------------------------------------
# RA-10: Create with review scheduling
# ---------------------------------------------------------------------------


def test_ra_10_review_scheduling(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    r = client.post(
        "/risk-acceptances",
        json=_create_body(
            assessment_id,
            finding_id,
            review_required=True,
            review_frequency_days=90,
            next_review_at="2026-09-20T00:00:00+00:00",
        ),
    )
    assert r.status_code == 201
    data = _json(r.json())
    assert data["review_required"] is True
    assert data["review_frequency_days"] == 90
    assert data["next_review_at"] == "2026-09-20T00:00:00+00:00"


# ---------------------------------------------------------------------------
# RA-11: Audit event on create
# ---------------------------------------------------------------------------


def test_ra_11_audit_on_create(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client.get(f"/risk-acceptances/{ra_id}/audit")
    assert r.status_code == 200
    data = _json(r.json())
    assert data["total"] >= 1
    assert any(e["event_type"] == "risk_created" for e in data["items"])


# ---------------------------------------------------------------------------
# RA-12: Audit event on update
# ---------------------------------------------------------------------------


def test_ra_12_audit_on_update(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.patch(f"/risk-acceptances/{ra_id}", json={"title": "Patched Title"})

    r = client.get(f"/risk-acceptances/{ra_id}/audit")
    data = _json(r.json())
    assert any(e["event_type"] == "risk_updated" for e in data["items"])


# ---------------------------------------------------------------------------
# RA-13: Audit event on transition
# ---------------------------------------------------------------------------


def test_ra_13_audit_on_transition(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )

    r = client.get(f"/risk-acceptances/{ra_id}/audit")
    data = _json(r.json())
    assert any(e["event_type"] == "risk_submitted" for e in data["items"])


# ---------------------------------------------------------------------------
# RA-14: DRAFT → PENDING_APPROVAL
# ---------------------------------------------------------------------------


def test_ra_14_draft_to_pending(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "pending_approval"


# ---------------------------------------------------------------------------
# RA-15: PENDING_APPROVAL → APPROVED (with approver attribution)
# ---------------------------------------------------------------------------


def test_ra_15_pending_to_approved(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={
            "target_status": "approved",
            "approver_name": "Jane CISO",
            "approver_role": "CISO",
            "approval_authority": "ciso",
        },
    )
    assert r.status_code == 200
    data = _json(r.json())
    assert data["status"] == "approved"
    assert data["approver_name"] == "Jane CISO"
    assert data["approver_role"] == "CISO"
    assert data["approval_authority"] == "ciso"


# ---------------------------------------------------------------------------
# RA-16: APPROVED → ACTIVE (accepted_at is set)
# ---------------------------------------------------------------------------


def test_ra_16_approved_to_active(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances",
            json=_create_body(assessment_id, finding_id, expires_at=_FUTURE_EXPIRY),
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "approved"}
    )

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "active"}
    )
    assert r.status_code == 200
    data = _json(r.json())
    assert data["status"] == "active"
    assert data["accepted_at"] is not None


# ---------------------------------------------------------------------------
# RA-17: ACTIVE → REVOKED (terminal)
# ---------------------------------------------------------------------------


def test_ra_17_active_to_revoked(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances",
            json=_create_body(assessment_id, finding_id, expires_at=_FUTURE_EXPIRY),
        ).json()
    )
    ra_id = created["id"]
    _drive_to_active(client, ra_id)

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "revoked", "reason": "Risk environment changed."},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "revoked"


# ---------------------------------------------------------------------------
# RA-18: PENDING_APPROVAL → REJECTED (terminal)
# ---------------------------------------------------------------------------


def test_ra_18_pending_to_rejected(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "rejected", "reason": "Residual risk too high."},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "rejected"


# ---------------------------------------------------------------------------
# RA-19: DRAFT → REVOKED (terminal)
# ---------------------------------------------------------------------------


def test_ra_19_draft_to_revoked(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "revoked", "reason": "Cancelled before submission."},
    )
    assert r.status_code == 200
    assert _json(r.json())["status"] == "revoked"


# ---------------------------------------------------------------------------
# RA-20: ACTIVE → EXPIRED via engine sweep (not direct manual transition)
# ---------------------------------------------------------------------------


def test_ra_20_active_to_expired_via_sweep(db_session: Session, build_app) -> None:
    """expire_overdue() transitions records with past expires_at to EXPIRED."""
    from services.risk_acceptance.engine import RiskAcceptanceEngine
    from services.risk_acceptance.schemas import CreateRiskAcceptanceRequest

    build_app(auth_enabled=True)

    # Create a record in ACTIVE state with an already-passed expiry
    engine = get_engine()
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        assessment_id = _new_engagement(db_session, _TENANT_A)
        finding_id = _new_finding(db_session, _TENANT_A, assessment_id)

        req = CreateRiskAcceptanceRequest(
            finding_id=finding_id,
            assessment_id=assessment_id,
            title="Expiry Sweep Test",
            business_justification="Test only.",
            risk_rationale="Test.",
            accepted_by="owner@example.com",
            expires_at="2020-01-01T00:00:00+00:00",  # already past
        )
        ra = svc.create(req, actor="test")
        db.commit()
        ra_id = ra.id

        # Drive to ACTIVE
        from services.risk_acceptance.schemas import TransitionRiskAcceptanceRequest

        for target in [
            RiskAcceptanceStatus.PENDING_APPROVAL,
            RiskAcceptanceStatus.APPROVED,
            RiskAcceptanceStatus.ACTIVE,
        ]:
            svc.transition(
                ra_id,
                TransitionRiskAcceptanceRequest(target_status=target),
                actor="test",
            )
            db.commit()

    # Now run the sweep
    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        count = svc.expire_overdue(actor="system")
        db.commit()
        assert count >= 1

    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        result = svc.get(ra_id)
        assert result.status == "expired"


# ---------------------------------------------------------------------------
# RA-21: REVOKED → any transition denied (422)
# ---------------------------------------------------------------------------


def test_ra_21_revoked_no_further_transitions(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "revoked"}
    )

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "draft"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RA-22: REJECTED → any transition denied (422)
# ---------------------------------------------------------------------------


def test_ra_22_rejected_no_further_transitions(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "rejected"}
    )

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "approved"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RA-23: EXPIRED → any transition denied (422) — via engine sweep
# ---------------------------------------------------------------------------


def test_ra_23_expired_no_further_transitions(
    client: TestClient, db_session: Session, build_app
) -> None:
    from services.risk_acceptance.engine import RiskAcceptanceEngine
    from services.risk_acceptance.schemas import (
        CreateRiskAcceptanceRequest,
        TransitionRiskAcceptanceRequest,
    )

    build_app(auth_enabled=True)
    engine = get_engine()
    assessment_id = _new_engagement(db_session, _TENANT_A)
    finding_id = _new_finding(db_session, _TENANT_A, assessment_id)

    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        req = CreateRiskAcceptanceRequest(
            finding_id=finding_id,
            assessment_id=assessment_id,
            title="Expire Test",
            business_justification="test",
            risk_rationale="test",
            accepted_by="owner@example.com",
            expires_at="2020-01-01T00:00:00+00:00",
        )
        ra = svc.create(req, actor="test")
        db.commit()
        ra_id = ra.id

        for target in [
            RiskAcceptanceStatus.PENDING_APPROVAL,
            RiskAcceptanceStatus.APPROVED,
            RiskAcceptanceStatus.ACTIVE,
        ]:
            svc.transition(
                ra_id,
                TransitionRiskAcceptanceRequest(target_status=target),
                actor="test",
            )
            db.commit()

        svc.expire_overdue(actor="system")
        db.commit()

    # Now try to transition from EXPIRED state
    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "active"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RA-24: DRAFT → ACTIVE denied (422) — skipped states
# ---------------------------------------------------------------------------


def test_ra_24_draft_to_active_denied(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "active"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RA-25: Transition reason stored in audit
# ---------------------------------------------------------------------------


def test_ra_25_transition_reason_in_audit(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "revoked", "reason": "Business unit shutdown."},
    )

    r = client.get(f"/risk-acceptances/{ra_id}/audit")
    data = _json(r.json())
    revoke_events = [e for e in data["items"] if e["event_type"] == "risk_revoked"]
    assert len(revoke_events) == 1
    assert revoke_events[0]["reason"] == "Business unit shutdown."


# ---------------------------------------------------------------------------
# RA-26: Allowed transitions — DRAFT
# ---------------------------------------------------------------------------


def test_ra_26_allowed_transitions_draft(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    r = client.get(f"/risk-acceptances/{ra_id}/transitions")
    assert r.status_code == 200
    data = _json(r.json())
    assert data["current_status"] == "draft"
    assert set(data["allowed"]) == {"pending_approval", "revoked"}


# ---------------------------------------------------------------------------
# RA-27: Allowed transitions — PENDING_APPROVAL
# ---------------------------------------------------------------------------


def test_ra_27_allowed_transitions_pending(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )

    r = client.get(f"/risk-acceptances/{ra_id}/transitions")
    data = _json(r.json())
    assert set(data["allowed"]) == {"approved", "rejected", "revoked"}


# ---------------------------------------------------------------------------
# RA-28: Allowed transitions — ACTIVE
# ---------------------------------------------------------------------------


def test_ra_28_allowed_transitions_active(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances",
            json=_create_body(assessment_id, finding_id, expires_at=_FUTURE_EXPIRY),
        ).json()
    )
    ra_id = created["id"]
    _drive_to_active(client, ra_id)

    r = client.get(f"/risk-acceptances/{ra_id}/transitions")
    data = _json(r.json())
    assert set(data["allowed"]) == {"expired", "revoked"}


# ---------------------------------------------------------------------------
# RA-29: Allowed transitions — terminal states return empty
# ---------------------------------------------------------------------------


def test_ra_29_terminal_states_empty_transitions(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "revoked"}
    )

    r = client.get(f"/risk-acceptances/{ra_id}/transitions")
    data = _json(r.json())
    assert data["allowed"] == []


# ---------------------------------------------------------------------------
# RA-30: Metrics increment on create
# ---------------------------------------------------------------------------


def test_ra_30_metrics_on_create(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import RISK_ACCEPTANCE_TOTAL

    before = RISK_ACCEPTANCE_TOTAL._value.get()
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    r = client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))
    assert r.status_code == 201
    assert RISK_ACCEPTANCE_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# RA-31: Metrics increment on approve
# ---------------------------------------------------------------------------


def test_ra_31_metrics_on_approve(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import RISK_APPROVED_TOTAL

    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )

    before = RISK_APPROVED_TOTAL._value.get()
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "approved"}
    )
    assert RISK_APPROVED_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# RA-32: Metrics increment on reject
# ---------------------------------------------------------------------------


def test_ra_32_metrics_on_reject(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import RISK_REJECTED_TOTAL

    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )

    before = RISK_REJECTED_TOTAL._value.get()
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "rejected"}
    )
    assert RISK_REJECTED_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# RA-33: Metrics increment on revoke
# ---------------------------------------------------------------------------


def test_ra_33_metrics_on_revoke(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import RISK_REVOKED_TOTAL

    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    before = RISK_REVOKED_TOTAL._value.get()
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "revoked"}
    )
    assert RISK_REVOKED_TOTAL._value.get() == before + 1


# ---------------------------------------------------------------------------
# RA-34: Compensating controls stored and returned correctly
# ---------------------------------------------------------------------------


def test_ra_34_compensating_controls_roundtrip(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    controls = [
        {"type": "mfa", "description": "MFA enforced on all admin accounts"},
        {"type": "restricted_access", "description": "Read-only access only"},
        {"type": "compensating_policy", "description": "Quarterly manual review"},
    ]
    created = _json(
        client.post(
            "/risk-acceptances",
            json=_create_body(
                assessment_id, finding_id, compensating_controls=controls
            ),
        ).json()
    )
    ra_id = created["id"]

    data = _json(client.get(f"/risk-acceptances/{ra_id}").json())
    assert len(data["compensating_controls"]) == 3
    returned_types = {c["type"] for c in data["compensating_controls"]}
    assert returned_types == {"mfa", "restricted_access", "compensating_policy"}


# ---------------------------------------------------------------------------
# RA-35: Residual risk LOW/MEDIUM/HIGH/CRITICAL round-trips
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
def test_ra_35_risk_levels(level: str, client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    r = client.post(
        "/risk-acceptances",
        json=_create_body(
            assessment_id,
            finding_id,
            inherent_risk=level,
            residual_risk=level,
        ),
    )
    assert r.status_code == 201
    data = _json(r.json())
    assert data["inherent_risk"] == level
    assert data["residual_risk"] == level


# ---------------------------------------------------------------------------
# RA-36: Expiration sweep — ACTIVE record with past expires_at becomes EXPIRED
# ---------------------------------------------------------------------------


def test_ra_36_expiration_sweep_past_date(db_session: Session, build_app) -> None:
    from services.risk_acceptance.engine import RiskAcceptanceEngine
    from services.risk_acceptance.schemas import (
        CreateRiskAcceptanceRequest,
        TransitionRiskAcceptanceRequest,
    )

    build_app(auth_enabled=True)
    engine = get_engine()
    assessment_id = _new_engagement(db_session, _TENANT_A)
    finding_id = _new_finding(db_session, _TENANT_A, assessment_id)

    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        req = CreateRiskAcceptanceRequest(
            finding_id=finding_id,
            assessment_id=assessment_id,
            title="Past Expiry",
            business_justification="test",
            risk_rationale="test",
            accepted_by="owner@example.com",
            expires_at="2020-06-01T00:00:00+00:00",
        )
        ra = svc.create(req, actor="test")
        db.commit()
        ra_id = ra.id

        for target in [
            RiskAcceptanceStatus.PENDING_APPROVAL,
            RiskAcceptanceStatus.APPROVED,
            RiskAcceptanceStatus.ACTIVE,
        ]:
            svc.transition(
                ra_id,
                TransitionRiskAcceptanceRequest(target_status=target),
                actor="test",
            )
            db.commit()

        count = svc.expire_overdue(actor="system")
        db.commit()
        assert count >= 1
        assert svc.get(ra_id).status == "expired"


# ---------------------------------------------------------------------------
# RA-37: Expiration sweep — future expires_at unchanged
# ---------------------------------------------------------------------------


def test_ra_37_expiration_sweep_future_date(db_session: Session, build_app) -> None:
    from services.risk_acceptance.engine import RiskAcceptanceEngine
    from services.risk_acceptance.schemas import (
        CreateRiskAcceptanceRequest,
        TransitionRiskAcceptanceRequest,
    )

    build_app(auth_enabled=True)
    engine = get_engine()
    assessment_id = _new_engagement(db_session, _TENANT_A)
    finding_id = _new_finding(db_session, _TENANT_A, assessment_id)

    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        req = CreateRiskAcceptanceRequest(
            finding_id=finding_id,
            assessment_id=assessment_id,
            title="Future Expiry",
            business_justification="test",
            risk_rationale="test",
            accepted_by="owner@example.com",
            expires_at="2099-01-01T00:00:00+00:00",
        )
        ra = svc.create(req, actor="test")
        db.commit()
        ra_id = ra.id

        for target in [
            RiskAcceptanceStatus.PENDING_APPROVAL,
            RiskAcceptanceStatus.APPROVED,
            RiskAcceptanceStatus.ACTIVE,
        ]:
            svc.transition(
                ra_id,
                TransitionRiskAcceptanceRequest(target_status=target),
                actor="test",
            )
            db.commit()

        svc.expire_overdue(actor="system")
        db.commit()
        # This specific record should NOT be expired
        assert svc.get(ra_id).status == "active"


# ---------------------------------------------------------------------------
# RA-38: Review frequency stored
# ---------------------------------------------------------------------------


def test_ra_38_review_frequency(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    for days in [30, 90, 180, 365]:
        r = client.post(
            "/risk-acceptances",
            json=_create_body(
                assessment_id,
                finding_id,
                review_required=True,
                review_frequency_days=days,
            ),
        )
        assert r.status_code == 201
        assert _json(r.json())["review_frequency_days"] == days


# ---------------------------------------------------------------------------
# RA-39: next_review_at stored and returned
# ---------------------------------------------------------------------------


def test_ra_39_next_review_at(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    review_date = "2026-09-20T00:00:00+00:00"
    r = client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, finding_id, next_review_at=review_date),
    )
    assert r.status_code == 201
    assert _json(r.json())["next_review_at"] == review_date


# ---------------------------------------------------------------------------
# RA-40: Remediation task link stored
# ---------------------------------------------------------------------------


def test_ra_40_remediation_task_link(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = uuid.uuid4().hex
    r = client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, finding_id, remediation_task_id=task_id),
    )
    assert r.status_code == 201
    assert _json(r.json())["remediation_task_id"] == task_id


# ---------------------------------------------------------------------------
# RA-41: List filter by status
# ---------------------------------------------------------------------------


def test_ra_41_list_filter_status(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )

    r = client.get("/risk-acceptances", params={"status": "pending_approval"})
    assert r.status_code == 200
    data = _json(r.json())
    assert all(item["status"] == "pending_approval" for item in data["items"])
    assert any(item["id"] == ra_id for item in data["items"])


# ---------------------------------------------------------------------------
# RA-42: List filter by finding_id
# ---------------------------------------------------------------------------


def test_ra_42_list_filter_finding(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))

    r = client.get("/risk-acceptances", params={"finding_id": finding_id})
    data = _json(r.json())
    assert all(item["finding_id"] == finding_id for item in data["items"])
    assert data["total"] >= 1


# ---------------------------------------------------------------------------
# RA-43: List filter by assessment_id
# ---------------------------------------------------------------------------


def test_ra_43_list_filter_assessment(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))

    r = client.get("/risk-acceptances", params={"assessment_id": assessment_id})
    data = _json(r.json())
    assert all(item["assessment_id"] == assessment_id for item in data["items"])
    assert data["total"] >= 1


# ---------------------------------------------------------------------------
# RA-44: List pagination
# ---------------------------------------------------------------------------


def test_ra_44_list_pagination(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    for _ in range(3):
        client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))

    r1 = client.get(
        "/risk-acceptances",
        params={"limit": 2, "offset": 0, "assessment_id": assessment_id},
    )
    r2 = client.get(
        "/risk-acceptances",
        params={"limit": 2, "offset": 2, "assessment_id": assessment_id},
    )
    d1 = _json(r1.json())
    d2 = _json(r2.json())

    assert len(d1["items"]) == 2
    ids_page1 = {i["id"] for i in d1["items"]}
    ids_page2 = {i["id"] for i in d2["items"]}
    assert ids_page1.isdisjoint(ids_page2)


# ---------------------------------------------------------------------------
# RA-45: Audit list returned in chronological order
# ---------------------------------------------------------------------------


def test_ra_45_audit_chronological_order(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.patch(f"/risk-acceptances/{ra_id}", json={"title": "Updated 1"})
    client.patch(f"/risk-acceptances/{ra_id}", json={"title": "Updated 2"})

    r = client.get(f"/risk-acceptances/{ra_id}/audit")
    events = _json(r.json())["items"]
    timestamps = [e["event_at"] for e in events]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# RA-46: Audit records survive regardless of status (immutability check)
# ---------------------------------------------------------------------------


def test_ra_46_audit_immutability(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]

    # Drive through multiple transitions and then check all events still exist
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "revoked"}
    )

    r = client.get(f"/risk-acceptances/{ra_id}/audit")
    data = _json(r.json())
    event_types = {e["event_type"] for e in data["items"]}
    assert "risk_created" in event_types
    assert "risk_submitted" in event_types
    assert "risk_revoked" in event_types
    assert data["total"] == 3


# ---------------------------------------------------------------------------
# RA-47: Authorization — write routes rejected without write scope
# ---------------------------------------------------------------------------


def test_ra_47_write_requires_write_scope(
    readonly_client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    r = readonly_client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, finding_id),
    )
    assert r.status_code in {401, 403}


# ---------------------------------------------------------------------------
# RA-48: Authorization — read routes rejected without read scope
# ---------------------------------------------------------------------------


def test_ra_48_read_requires_read_scope(
    writeonly_client: TestClient, db_session: Session
) -> None:
    r = writeonly_client.get("/risk-acceptances")
    assert r.status_code in {401, 403}


# ---------------------------------------------------------------------------
# RA-49: Schema version 1.0 on all created records
# ---------------------------------------------------------------------------


def test_ra_49_schema_version(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    r = client.post("/risk-acceptances", json=_create_body(assessment_id, finding_id))
    assert r.status_code == 201
    assert _json(r.json())["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# RA-50: State machine integrity — terminal states have no allowed transitions
# ---------------------------------------------------------------------------


def test_ra_50_state_machine_integrity() -> None:
    """All terminal states must have empty allowed-transitions sets."""
    for terminal in TERMINAL_STATUSES:
        allowed = ALLOWED_TRANSITIONS.get(terminal, set())
        assert allowed == set(), (
            f"Terminal state {terminal.value!r} has non-empty transitions: {allowed}"
        )

    # Non-terminal states must have at least one allowed transition
    non_terminal = set(RiskAcceptanceStatus) - TERMINAL_STATUSES
    for state in non_terminal:
        allowed = ALLOWED_TRANSITIONS.get(state, set())
        assert len(allowed) > 0, (
            f"Non-terminal state {state.value!r} has no allowed transitions"
        )


# ---------------------------------------------------------------------------
# RA-51: Orphaned finding reference rejected (P1 validation)
# ---------------------------------------------------------------------------


def test_ra_51_orphaned_finding_rejected(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, _ = _make_refs(db_session, _TENANT_A)
    r = client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, "nonexistent-finding-id"),
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RA-52: Cross-tenant finding reference rejected (P1 validation)
# ---------------------------------------------------------------------------


def test_ra_52_cross_tenant_finding_rejected(
    client: TestClient, db_session: Session
) -> None:
    # Create refs under tenant B
    assessment_b, finding_b = _make_refs(db_session, _TENANT_B)
    # Try to create acceptance for tenant A using tenant B's IDs
    r = client.post(
        "/risk-acceptances",
        json=_create_body(assessment_b, finding_b),
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# RA-53: APPROVED → ACTIVE blocked without expires_at (P1 validation)
# ---------------------------------------------------------------------------


def test_ra_53_active_requires_expires_at(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    # Create WITHOUT expires_at
    created = _json(
        client.post(
            "/risk-acceptances", json=_create_body(assessment_id, finding_id)
        ).json()
    )
    ra_id = created["id"]
    client.post(
        f"/risk-acceptances/{ra_id}/transitions",
        json={"target_status": "pending_approval"},
    )
    client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "approved"}
    )

    # Attempt ACTIVE without expires_at — must be rejected
    r = client.post(
        f"/risk-acceptances/{ra_id}/transitions", json={"target_status": "active"}
    )
    assert r.status_code == 422
    assert "expires_at" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# RA-54: List count matches filtered items for remediation_task_id (P2 fix)
# ---------------------------------------------------------------------------


def test_ra_54_list_count_matches_task_filter(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = uuid.uuid4().hex
    other_task_id = uuid.uuid4().hex

    # Create 2 linked to task_id, 1 linked to other_task_id
    client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, finding_id, remediation_task_id=task_id),
    )
    client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, finding_id, remediation_task_id=task_id),
    )
    client.post(
        "/risk-acceptances",
        json=_create_body(assessment_id, finding_id, remediation_task_id=other_task_id),
    )

    r = client.get("/risk-acceptances", params={"remediation_task_id": task_id})
    data = _json(r.json())
    # total must equal the number of items returned for this filter
    assert data["total"] == 2
    assert len(data["items"]) == 2
    assert all(item["remediation_task_id"] == task_id for item in data["items"])


# ---------------------------------------------------------------------------
# RA-55: Expiry with non-UTC offset timestamp swept correctly (P2 fix)
# ---------------------------------------------------------------------------


def test_ra_55_expiry_offset_timezone_sweep(db_session: Session, build_app) -> None:
    """expires_at with a non-UTC offset (-05:00) is correctly swept to EXPIRED."""
    from services.risk_acceptance.engine import RiskAcceptanceEngine
    from services.risk_acceptance.schemas import (
        CreateRiskAcceptanceRequest,
        TransitionRiskAcceptanceRequest,
    )

    build_app(auth_enabled=True)
    engine = get_engine()
    assessment_id = _new_engagement(db_session, _TENANT_A)
    finding_id = _new_finding(db_session, _TENANT_A, assessment_id)

    with Session(engine) as db:
        svc = RiskAcceptanceEngine(db, tenant_id=_TENANT_A)
        # 2020-01-01 at midnight US/Central is 2020-01-01T06:00:00Z — clearly in the past
        req = CreateRiskAcceptanceRequest(
            finding_id=finding_id,
            assessment_id=assessment_id,
            title="Offset TZ Test",
            business_justification="test",
            risk_rationale="test",
            accepted_by="owner@example.com",
            expires_at="2020-01-01T00:00:00-05:00",
        )
        ra = svc.create(req, actor="test")
        db.commit()
        ra_id = ra.id

        for target in [
            RiskAcceptanceStatus.PENDING_APPROVAL,
            RiskAcceptanceStatus.APPROVED,
            RiskAcceptanceStatus.ACTIVE,
        ]:
            svc.transition(
                ra_id,
                TransitionRiskAcceptanceRequest(target_status=target),
                actor="test",
            )
            db.commit()

        count = svc.expire_overdue(actor="system")
        db.commit()
        assert count >= 1
        assert svc.get(ra_id).status == "expired"
