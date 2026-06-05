"""tests/test_h14_governance_decisions.py — H14 Governance Decision Ledger.

H14 accountability layers:
  G1  record_decision — creates FaGovernanceDecision with correct fields
  G2  record_decision — H13 audit event emitted atomically in same transaction
  G3  record_decision — transaction_id on decision matches audit event transaction_id
  G4  get_decision tenant isolation — wrong tenant returns None
  G5  append-only enforcement (decision) — no update method on service
  G6  append-only enforcement (risk acceptance) — no update method on service
  G7  append-only enforcement (exception) — no update method on service
  G8  qa_approve route — creates decision of type report_approved with actor attribution
  G9  finding_remediation route — creates decision of type finding_closed
  G10 risk_acceptance POST — creates FaRiskAcceptance + FaGovernanceDecision atomically
  G11 risk_acceptance POST — finding_id from wrong engagement returns 404
  G12 risk_acceptance POST — unknown finding_id returns 404
  G13 risk_acceptance GET list — returns only this engagement's records
  G14 risk_acceptance GET list cross-tenant — other tenant's records not returned
  G15 risk_acceptance GET detail — returns correct record fields
  G16 risk_acceptance GET detail cross-tenant — 404
  G17 exception POST — creates FaGovernanceException + FaGovernanceDecision
  G18 exception POST — engagement not found returns 404
  G19 exception GET list — returns records only for this engagement
  G20 exception GET list cross-tenant — other tenant's exceptions not returned
  G21 exception GET detail — correct fields returned
  G22 exception GET detail cross-tenant — 404
  G23 governance_decision GET list — returns all decisions for engagement
  G24 governance_decision GET list — decision_type filter
  G25 governance_decision GET detail — correct decision_id and entity fields
  G26 governance_decision GET detail cross-tenant — 404
  G27 evidence_snapshot_hash — computed and stored on decision record
  G28 evidence_refs — stored as JSON array and deserialized correctly
  G29 related_finding_ids — stored as JSON array and deserialized correctly
  G30 record_decision_with_risk_acceptance — decision and acceptance share tenant/engagement
  G31 record_decision_with_exception — decision and exception share tenant/engagement
  G32 finding_closed decision — entity_type is finding, entity_id is finding_id
  G33 report_approved decision — entity_type is report, entity_id is report_id
  G34 list_decisions limit — respects limit parameter
  G35 risk acceptance status filter — only active records returned when status=active
"""

from __future__ import annotations

import os
import secrets

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from services.field_assessment.governance_decision_service import (
    GovernanceDecisionService,
    governance_decision_svc,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-h14-test"
_OTHER_TENANT = "tenant-h14-other"

_ENG_BODY = {
    "client_name": "DecisionCorp",
    "assessor_id": "assessor-h14",
    "assessment_type": "ai_governance",
}


# ---------------------------------------------------------------------------
# Helpers — DB
# ---------------------------------------------------------------------------


def _sessionmaker():
    from api.db import get_sessionmaker

    return get_sessionmaker()


def _make_engagement(SM, *, tenant_id: str) -> str:
    from api.db_models_field_assessment import FaEngagement
    from services.canonical import utc_iso8601_z_now

    eng_id = secrets.token_hex(16)
    now = utc_iso8601_z_now()
    db = SM()
    try:
        db.add(
            FaEngagement(
                id=eng_id,
                tenant_id=tenant_id,
                client_name="DecisionCorp",
                assessor_id="assessor-h14",
                assessment_type="ai_governance",
                status="in_progress",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    finally:
        db.close()
    return eng_id


def _make_finding(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_field_assessment import FaNormalizedFinding
    from services.canonical import utc_iso8601_z_now

    fid = secrets.token_hex(16)
    now = utc_iso8601_z_now()
    db = SM()
    try:
        db.add(
            FaNormalizedFinding(
                id=fid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                finding_type="test",
                findings_hash=secrets.token_hex(16),
                severity="high",
                status="open",
                title="Test Finding H14",
                description="Test finding for H14 governance decision tests.",
                source_attribution="test",
                framework_mappings=[],
                nist_ai_rmf_mappings=[],
                evidence_ref_ids=[],
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    finally:
        db.close()
    return fid


def _make_report(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_governance_report import GovernanceReportRecord
    from services.canonical import utc_iso8601_z_now

    rid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            GovernanceReportRecord(
                id=rid,
                tenant_id=tenant_id,
                assessment_id=engagement_id,
                version=1,
                manifest_hash=secrets.token_hex(16),
                report_json={"sections": []},
                generated_at=utc_iso8601_z_now(),
                is_finalized=True,
            )
        )
        db.commit()
    finally:
        db.close()
    return rid


def _mint_key_with_role(
    *scopes: str, tenant_id: str, role_name: str, session_factory
) -> str:
    from sqlalchemy import text as sa_text
    from api.auth_scopes import mint_key
    from api.tenant_rbac import assign_role

    key = mint_key(*scopes, tenant_id=tenant_id)

    db = session_factory()()
    try:
        key_id = db.execute(
            sa_text(
                """
                SELECT id
                FROM api_keys
                WHERE tenant_id = :tenant_id
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {"tenant_id": tenant_id},
        ).scalar_one()

        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="pytest",
            target_key_id=int(key_id),
            role_name=role_name,
        )
    finally:
        db.close()

    return key


# ---------------------------------------------------------------------------
# Fixtures — function-scoped to match conftest.build_app
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = _mint_key_with_role(
        "governance:write",
        "governance:read",
        tenant_id=_TENANT,
        role_name="governance_admin",
        session_factory=_sessionmaker,
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def qa_client(build_app):
    app = build_app(auth_enabled=True)
    key = _mint_key_with_role(
        "governance:write",
        "governance:read",
        tenant_id=_TENANT,
        role_name="auditor",
        session_factory=_sessionmaker,
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def other_client(build_app):
    app = build_app(auth_enabled=True)
    key = _mint_key_with_role(
        "governance:write",
        "governance:read",
        tenant_id=_OTHER_TENANT,
        role_name="governance_admin",
        session_factory=_sessionmaker,
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def SM(build_app):
    build_app(auth_enabled=True)
    return _sessionmaker()


@pytest.fixture()
def eng_id(SM):
    return _make_engagement(SM, tenant_id=_TENANT)


@pytest.fixture()
def other_eng_id(SM):
    return _make_engagement(SM, tenant_id=_OTHER_TENANT)


@pytest.fixture()
def finding_id(SM, eng_id):
    return _make_finding(SM, tenant_id=_TENANT, engagement_id=eng_id)


# ---------------------------------------------------------------------------
# G1–G4: Core record_decision + tenant isolation
# ---------------------------------------------------------------------------


def test_g1_creates_decision_with_correct_fields(SM, eng_id) -> None:
    """G1: record_decision creates FaGovernanceDecision with all required fields."""
    from api.db_models_governance_decision import FaGovernanceDecision

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-001",
            actor_id="key-abc",
            actor_name="Jane Smith",
            actor_email="jane@example.com",
            actor_role="CISO",
            decision_reason="Policy reviewed and approved per Q2 review cycle.",
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    db2 = SM()
    try:
        row = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == d_id)
        ).scalar_one_or_none()
        assert row is not None
        assert row.tenant_id == _TENANT
        assert row.engagement_id == eng_id
        assert row.decision_type == "policy_approved"
        assert row.entity_type == "policy"
        assert row.entity_id == "pol-001"
        assert row.actor_id == "key-abc"
        assert row.actor_name == "Jane Smith"
        assert row.actor_email == "jane@example.com"
        assert row.actor_role == "CISO"
        assert row.actor_auth_source == "api_key"
        assert row.approver_id == "key-abc"
        assert (
            row.decision_reason == "Policy reviewed and approved per Q2 review cycle."
        )
        assert row.status == "active"
        assert row.decision_at is not None
        assert row.transaction_id is not None
        assert len(row.transaction_id) == 32
    finally:
        db2.close()


def test_g2_audit_event_emitted_atomically(SM, eng_id) -> None:
    """G2: H13 audit event is emitted in the same transaction as the decision."""
    from api.db_models_field_assessment import FaEngagementAuditEvent

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="assessment_completed",
            entity_type="engagement",
            entity_id=eng_id,
            actor_id="key-audit-test",
            decision_reason="Assessment cycle completed.",
        )
        db.commit()
        tx_id = decision.transaction_id
    finally:
        db.close()

    db2 = SM()
    try:
        event = db2.execute(
            select(FaEngagementAuditEvent).where(
                FaEngagementAuditEvent.transaction_id == tx_id,
                FaEngagementAuditEvent.tenant_id == _TENANT,
            )
        ).scalar_one_or_none()
        assert event is not None, (
            "audit event must be written atomically with the decision"
        )
        assert event.event_type == "decision.assessment_completed"
        assert event.entity_id == eng_id
    finally:
        db2.close()


def test_g3_transaction_id_matches_audit_event(SM, eng_id) -> None:
    """G3: decision.transaction_id equals the linked audit event's transaction_id."""
    from api.db_models_field_assessment import FaEngagementAuditEvent
    from api.db_models_governance_decision import FaGovernanceDecision

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="remediation_approved",
            entity_type="finding",
            entity_id="find-tx-test",
            actor_id="key-tx",
            decision_reason="Remediation plan reviewed and approved.",
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    db2 = SM()
    try:
        dec = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == d_id)
        ).scalar_one()
        evt = db2.execute(
            select(FaEngagementAuditEvent).where(
                FaEngagementAuditEvent.transaction_id == dec.transaction_id,
            )
        ).scalar_one_or_none()
        assert evt is not None
        assert evt.transaction_id == dec.transaction_id
    finally:
        db2.close()


def test_g4_get_decision_tenant_isolation(SM, eng_id) -> None:
    """G4: get_decision returns None when queried with a different tenant."""
    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-iso",
            actor_id="key-iso",
            decision_reason="Tenant isolation test decision.",
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    db2 = SM()
    try:
        wrong = governance_decision_svc.get_decision(
            db2, decision_id=d_id, tenant_id=_OTHER_TENANT
        )
        assert wrong is None
        correct = governance_decision_svc.get_decision(
            db2, decision_id=d_id, tenant_id=_TENANT
        )
        assert correct is not None
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# G5–G7: Append-only enforcement (service level)
# ---------------------------------------------------------------------------


def test_g5_decision_service_has_no_update_method() -> None:
    """G5: GovernanceDecisionService exposes no update/delete methods for decisions."""
    svc = GovernanceDecisionService()
    assert not hasattr(svc, "update_decision")
    assert not hasattr(svc, "delete_decision")
    assert not hasattr(svc, "patch_decision")


def test_g6_risk_acceptance_service_has_no_update_method() -> None:
    """G6: GovernanceDecisionService exposes no update/delete for risk acceptances."""
    svc = GovernanceDecisionService()
    assert not hasattr(svc, "update_risk_acceptance")
    assert not hasattr(svc, "delete_risk_acceptance")


def test_g7_exception_service_has_no_update_method() -> None:
    """G7: GovernanceDecisionService exposes no update/delete for exceptions."""
    svc = GovernanceDecisionService()
    assert not hasattr(svc, "update_exception")
    assert not hasattr(svc, "delete_exception")


# ---------------------------------------------------------------------------
# G8–G9: Existing route wiring
# ---------------------------------------------------------------------------


def test_g8_qa_approve_creates_report_approved_decision_with_attribution(
    qa_client: TestClient, SM, eng_id
) -> None:
    """G8: qa_approve route creates a report_approved governance decision with actor attribution."""
    from api.db_models_governance_decision import FaGovernanceDecision

    report_id = _make_report(SM, tenant_id=_TENANT, engagement_id=eng_id)

    resp = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={
            "reviewer_name": "Auditor One",
            "actor_email": "auditor@example.com",
            "actor_role": "Senior Auditor",
        },
    )
    assert resp.status_code == 200, resp.text

    db = SM()
    try:
        decisions = list(
            db.execute(
                select(FaGovernanceDecision).where(
                    FaGovernanceDecision.tenant_id == _TENANT,
                    FaGovernanceDecision.engagement_id == eng_id,
                    FaGovernanceDecision.decision_type == "report_approved",
                    FaGovernanceDecision.entity_id == report_id,
                )
            ).scalars()
        )
        assert len(decisions) == 1
        d = decisions[0]
        # G9: actor attribution comes from ActorContext, not spoofable request body.
        assert d.actor_auth_source == "api_key"
        assert d.actor_id == "fgk"
        assert d.actor_email is None
        assert d.actor_role == "qa_reviewer"
        assert d.entity_type == "report"
        assert d.entity_id == report_id  # G33 covered here
        assert d.transaction_id is not None
    finally:
        db.close()


def test_g9_finding_remediation_creates_finding_closed_decision(
    client: TestClient, SM, eng_id, finding_id
) -> None:
    """G9: patch_finding_remediation route creates a finding_closed governance decision."""
    from api.db_models_governance_decision import FaGovernanceDecision

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/findings/{finding_id}/remediation",
        json={
            "remediation_hint": "Implemented MFA on all admin accounts.",
            "decision_reason": "Remediation verified in change management system.",
            "actor_name": "Bob Ops",
            "actor_email": "bob@example.com",
            "actor_role": "IT Operations Lead",
        },
    )
    assert resp.status_code == 200, resp.text

    db = SM()
    try:
        decisions = list(
            db.execute(
                select(FaGovernanceDecision).where(
                    FaGovernanceDecision.tenant_id == _TENANT,
                    FaGovernanceDecision.engagement_id == eng_id,
                    FaGovernanceDecision.decision_type == "finding_closed",
                    FaGovernanceDecision.entity_id == finding_id,
                )
            ).scalars()
        )
        assert len(decisions) >= 1
        d = decisions[-1]
        assert d.entity_type == "finding"
        assert d.entity_id == finding_id  # G32 covered here
        assert d.actor_name == "Bob Ops"
        assert d.actor_email == "bob@example.com"
        assert d.related_finding_ids is not None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# G10–G16: Risk acceptance routes
# ---------------------------------------------------------------------------


def test_g10_risk_acceptance_post_creates_acceptance_and_decision(
    client: TestClient, SM, eng_id, finding_id
) -> None:
    """G10: POST risk-acceptances creates FaRiskAcceptance + FaGovernanceDecision."""
    from api.db_models_governance_decision import FaGovernanceDecision, FaRiskAcceptance

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": finding_id,
            "risk_owner": "Chief Risk Officer",
            "risk_owner_email": "cro@example.com",
            "business_justification": "Cost of remediation exceeds risk exposure this quarter.",
            "accepted_risk_level": "medium",
            "expires_at": "2027-01-01T00:00:00Z",
            "review_date": "2026-10-01T00:00:00Z",
            "actor_name": "CRO Jane",
            "actor_email": "cro@example.com",
            "actor_role": "CRO",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "acceptance_id" in data
    assert "decision" in data
    assert data["decision"]["decision_type"] == "risk_accepted"
    assert data["finding_id"] == finding_id
    assert data["accepted_risk_level"] == "medium"
    assert data["expires_at"] == "2027-01-01T00:00:00Z"

    db = SM()
    try:
        acc = db.execute(
            select(FaRiskAcceptance).where(FaRiskAcceptance.id == data["acceptance_id"])
        ).scalar_one_or_none()
        assert acc is not None
        assert acc.tenant_id == _TENANT
        assert acc.engagement_id == eng_id

        dec = db.execute(
            select(FaGovernanceDecision).where(
                FaGovernanceDecision.id == data["decision"]["decision_id"]
            )
        ).scalar_one_or_none()
        assert dec is not None
        assert dec.decision_type == "risk_accepted"
    finally:
        db.close()


def test_g11_risk_acceptance_wrong_engagement_finding_returns_404(
    client: TestClient, SM, eng_id
) -> None:
    """G11: POST risk-acceptance with finding from different engagement returns 404."""
    other_eng = _make_engagement(SM, tenant_id=_TENANT)
    other_finding = _make_finding(SM, tenant_id=_TENANT, engagement_id=other_eng)

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": other_finding,
            "risk_owner": "CRO",
            "business_justification": "Cross-engagement test justification here.",
            "accepted_risk_level": "low",
            "expires_at": "2027-01-01T00:00:00Z",
            "review_date": "2026-10-01T00:00:00Z",
        },
    )
    assert resp.status_code == 404


def test_g12_risk_acceptance_unknown_finding_returns_404(
    client: TestClient, eng_id
) -> None:
    """G12: POST risk-acceptance with non-existent finding_id returns 404."""
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": "nonexistent-finding-id",
            "risk_owner": "CRO",
            "business_justification": "Unknown finding test — should return 404.",
            "accepted_risk_level": "low",
            "expires_at": "2027-01-01T00:00:00Z",
            "review_date": "2026-10-01T00:00:00Z",
        },
    )
    assert resp.status_code == 404


def test_g13_risk_acceptance_list_returns_only_this_engagement(
    client: TestClient, SM, eng_id, finding_id
) -> None:
    """G13: GET risk-acceptances returns only the specified engagement's records."""
    # Create an acceptance for eng_id
    client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": finding_id,
            "risk_owner": "Owner",
            "business_justification": "G13 list isolation test justification here.",
            "accepted_risk_level": "low",
            "expires_at": "2027-01-01T00:00:00Z",
            "review_date": "2026-10-01T00:00:00Z",
        },
    )

    # Check a different (empty) engagement returns empty list
    other_eng = _make_engagement(SM, tenant_id=_TENANT)
    resp_empty = client.get(
        f"/field-assessment/engagements/{other_eng}/risk-acceptances"
    )
    assert resp_empty.status_code == 200
    assert resp_empty.json()["risk_acceptances"] == []

    # Check eng_id returns at least 1 record
    resp = client.get(f"/field-assessment/engagements/{eng_id}/risk-acceptances")
    assert resp.status_code == 200
    assert len(resp.json()["risk_acceptances"]) >= 1


def test_g14_risk_acceptance_list_cross_tenant_returns_empty(
    other_client: TestClient, SM
) -> None:
    """G14: Other tenant's GET risk-acceptances list returns empty (tenant scope)."""
    other_eng = _make_engagement(SM, tenant_id=_OTHER_TENANT)
    resp = other_client.get(
        f"/field-assessment/engagements/{other_eng}/risk-acceptances"
    )
    assert resp.status_code == 200
    assert resp.json()["risk_acceptances"] == []


def test_g15_risk_acceptance_get_detail_returns_correct_record(
    client: TestClient, SM, eng_id, finding_id
) -> None:
    """G15: GET risk-acceptances/{id} returns the correct acceptance record fields."""
    post_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": finding_id,
            "risk_owner": "Detail Test Owner",
            "business_justification": "Detail test — verifying GET returns correct data.",
            "accepted_risk_level": "high",
            "expires_at": "2027-06-01T00:00:00Z",
            "review_date": "2026-12-01T00:00:00Z",
        },
    )
    assert post_resp.status_code == 201
    acc_id = post_resp.json()["acceptance_id"]

    get_resp = client.get(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances/{acc_id}"
    )
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["acceptance_id"] == acc_id
    assert data["accepted_risk_level"] == "high"
    assert data["risk_owner"] == "Detail Test Owner"
    assert data["expires_at"] == "2027-06-01T00:00:00Z"


def test_g16_risk_acceptance_detail_cross_tenant_returns_404(
    other_client: TestClient, SM, eng_id, finding_id, client: TestClient
) -> None:
    """G16: GET risk-acceptance/{id} from another tenant returns 404."""
    post_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": finding_id,
            "risk_owner": "Owner",
            "business_justification": "G16 cross-tenant isolation test justification.",
            "accepted_risk_level": "low",
            "expires_at": "2027-01-01T00:00:00Z",
            "review_date": "2026-10-01T00:00:00Z",
        },
    )
    assert post_resp.status_code == 201
    acc_id = post_resp.json()["acceptance_id"]

    other_eng = _make_engagement(SM, tenant_id=_OTHER_TENANT)
    resp = other_client.get(
        f"/field-assessment/engagements/{other_eng}/risk-acceptances/{acc_id}"
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# G17–G22: Governance exception routes
# ---------------------------------------------------------------------------


def test_g17_exception_post_creates_exception_and_decision(
    client: TestClient, SM, eng_id
) -> None:
    """G17: POST exceptions creates FaGovernanceException + FaGovernanceDecision."""
    from api.db_models_governance_decision import (
        FaGovernanceDecision,
        FaGovernanceException,
    )

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/exceptions",
        json={
            "exception_type": "control_exception",
            "owner": "Compliance Officer",
            "owner_email": "compliance@example.com",
            "business_justification": (
                "Legacy system cannot be patched before migration completes Q4."
            ),
            "expires_at": "2026-12-31T00:00:00Z",
            "review_schedule": "quarterly",
            "related_control_ids": ["NIST-GOVERN-1.2", "NIST-MANAGE-2.4"],
            "compensating_controls": [
                "Network segmentation applied",
                "Enhanced monitoring enabled",
            ],
            "actor_name": "CCO Smith",
            "actor_email": "cco@example.com",
            "actor_role": "Chief Compliance Officer",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "exception_id" in data
    assert "decision" in data
    assert data["decision"]["decision_type"] == "exception_granted"
    assert data["exception_type"] == "control_exception"
    assert data["owner"] == "Compliance Officer"
    assert data["review_schedule"] == "quarterly"
    assert "NIST-GOVERN-1.2" in data["related_control_ids"]
    assert len(data["compensating_controls"]) == 2

    db = SM()
    try:
        exc = db.execute(
            select(FaGovernanceException).where(
                FaGovernanceException.id == data["exception_id"]
            )
        ).scalar_one_or_none()
        assert exc is not None
        assert exc.tenant_id == _TENANT

        dec = db.execute(
            select(FaGovernanceDecision).where(
                FaGovernanceDecision.id == data["decision"]["decision_id"]
            )
        ).scalar_one_or_none()
        assert dec is not None
        assert dec.decision_type == "exception_granted"
    finally:
        db.close()


def test_g18_exception_post_unknown_engagement_returns_404(
    client: TestClient,
) -> None:
    """G18: POST exception for non-existent engagement returns 404."""
    resp = client.post(
        "/field-assessment/engagements/no-such-engagement/exceptions",
        json={
            "exception_type": "policy_exception",
            "owner": "Owner",
            "business_justification": "Non-existent engagement test justification.",
            "expires_at": "2027-01-01T00:00:00Z",
        },
    )
    assert resp.status_code == 404


def test_g19_exception_list_returns_only_this_engagement(
    client: TestClient, SM, eng_id
) -> None:
    """G19: GET exceptions returns records for this engagement only."""
    client.post(
        f"/field-assessment/engagements/{eng_id}/exceptions",
        json={
            "exception_type": "policy_exception",
            "owner": "G19 Owner",
            "business_justification": "G19 list test justification text here.",
            "expires_at": "2027-01-01T00:00:00Z",
        },
    )

    other_eng = _make_engagement(SM, tenant_id=_TENANT)
    resp_empty = client.get(f"/field-assessment/engagements/{other_eng}/exceptions")
    assert resp_empty.status_code == 200
    assert resp_empty.json()["exceptions"] == []

    resp = client.get(f"/field-assessment/engagements/{eng_id}/exceptions")
    assert resp.status_code == 200
    assert len(resp.json()["exceptions"]) >= 1
    assert all(e["engagement_id"] == eng_id for e in resp.json()["exceptions"])


def test_g20_exception_list_cross_tenant_returns_empty(
    other_client: TestClient, SM
) -> None:
    """G20: Other tenant's GET exceptions list returns empty (tenant scope)."""
    other_eng = _make_engagement(SM, tenant_id=_OTHER_TENANT)
    resp = other_client.get(f"/field-assessment/engagements/{other_eng}/exceptions")
    assert resp.status_code == 200
    assert resp.json()["exceptions"] == []


def test_g21_exception_get_detail_returns_correct_fields(
    client: TestClient, eng_id
) -> None:
    """G21: GET exceptions/{id} returns correct record fields."""
    post_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/exceptions",
        json={
            "exception_type": "finding_exception",
            "owner": "Detail Owner",
            "owner_email": "detail@example.com",
            "business_justification": "Detail test exception justification text here.",
            "expires_at": "2027-03-01T00:00:00Z",
            "review_schedule": "monthly",
        },
    )
    assert post_resp.status_code == 201
    exc_id = post_resp.json()["exception_id"]

    get_resp = client.get(f"/field-assessment/engagements/{eng_id}/exceptions/{exc_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["exception_id"] == exc_id
    assert data["exception_type"] == "finding_exception"
    assert data["owner"] == "Detail Owner"
    assert data["expires_at"] == "2027-03-01T00:00:00Z"


def test_g22_exception_detail_cross_tenant_returns_404(
    client: TestClient, other_client: TestClient, SM, eng_id
) -> None:
    """G22: GET exception/{id} from another tenant returns 404."""
    post_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/exceptions",
        json={
            "exception_type": "control_exception",
            "owner": "Owner",
            "business_justification": "G22 cross-tenant isolation exception test.",
            "expires_at": "2027-01-01T00:00:00Z",
        },
    )
    assert post_resp.status_code == 201
    exc_id = post_resp.json()["exception_id"]

    other_eng = _make_engagement(SM, tenant_id=_OTHER_TENANT)
    resp = other_client.get(
        f"/field-assessment/engagements/{other_eng}/exceptions/{exc_id}"
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# G23–G26: Decision ledger routes
# ---------------------------------------------------------------------------


def test_g23_list_decisions_returns_all_for_engagement(
    client: TestClient, SM, eng_id, finding_id
) -> None:
    """G23: GET governance-decisions returns all decisions for the engagement."""
    # create a few decisions
    client.patch(
        f"/field-assessment/engagements/{eng_id}/findings/{finding_id}/remediation",
        json={"remediation_hint": "Applied patch KB-123 to close finding."},
    )
    client.post(
        f"/field-assessment/engagements/{eng_id}/exceptions",
        json={
            "exception_type": "control_exception",
            "owner": "G23 Owner",
            "business_justification": "G23 decision list test justification text.",
            "expires_at": "2027-01-01T00:00:00Z",
        },
    )

    resp = client.get(f"/field-assessment/engagements/{eng_id}/governance-decisions")
    assert resp.status_code == 200
    data = resp.json()
    assert "decisions" in data
    assert len(data["decisions"]) >= 2


def test_g24_list_decisions_decision_type_filter(
    client: TestClient, SM, eng_id, finding_id
) -> None:
    """G24: ?decision_type= filter returns only matching decisions."""
    # create risk_accepted decision
    client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": finding_id,
            "risk_owner": "G24 Owner",
            "business_justification": "G24 decision type filter test justification.",
            "accepted_risk_level": "low",
            "expires_at": "2027-01-01T00:00:00Z",
            "review_date": "2026-10-01T00:00:00Z",
        },
    )

    resp = client.get(
        f"/field-assessment/engagements/{eng_id}/governance-decisions",
        params={"decision_type": "risk_accepted"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(d["decision_type"] == "risk_accepted" for d in data["decisions"])
    assert len(data["decisions"]) >= 1


def test_g25_get_decision_detail_correct_fields(client: TestClient, SM, eng_id) -> None:
    """G25: GET governance-decisions/{id} returns correct decision_id and entity fields."""
    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-detail",
            actor_id="key-detail",
            decision_reason="Policy reviewed for detail retrieval test.",
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    resp = client.get(
        f"/field-assessment/engagements/{eng_id}/governance-decisions/{d_id}"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision_id"] == d_id
    assert data["entity_type"] == "policy"
    assert data["entity_id"] == "pol-detail"
    assert data["decision_type"] == "policy_approved"
    assert "transaction_id" in data


def test_g26_get_decision_detail_cross_tenant_returns_404(
    other_client: TestClient, SM, eng_id
) -> None:
    """G26: GET governance-decisions/{id} from another tenant returns 404."""
    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-cross",
            actor_id="key-cross",
            decision_reason="Cross-tenant isolation test decision.",
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    other_eng = _make_engagement(SM, tenant_id=_OTHER_TENANT)
    resp = other_client.get(
        f"/field-assessment/engagements/{other_eng}/governance-decisions/{d_id}"
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# G27–G31: Service-level provenance and evidence tracking
# ---------------------------------------------------------------------------


def test_g27_evidence_snapshot_hash_computed_and_stored(SM, eng_id) -> None:
    """G27: evidence_snapshot dict is SHA-256 hashed and stored in decision record."""
    import hashlib
    import json

    from api.db_models_governance_decision import FaGovernanceDecision

    snapshot = {"evidence_id": "ev-001", "state": "locked", "hash": "abc123"}

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="legal_hold_applied",
            entity_type="evidence",
            entity_id="ev-001",
            actor_id="key-snap",
            decision_reason="Legal hold applied per litigation hold notice.",
            evidence_snapshot=snapshot,
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    expected_hash = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True).encode()
    ).hexdigest()[:32]

    db2 = SM()
    try:
        row = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == d_id)
        ).scalar_one()
        assert row.evidence_snapshot_hash == expected_hash
    finally:
        db2.close()


def test_g28_evidence_refs_stored_and_deserialized_as_list(SM, eng_id) -> None:
    """G28: evidence_refs list is stored as JSON and deserialized correctly in to_dict."""
    from api.db_models_governance_decision import FaGovernanceDecision

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-evref",
            actor_id="key-evref",
            decision_reason="Policy approved with full evidence trail.",
            evidence_refs=["ev-001", "ev-002", "ev-003"],
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    db2 = SM()
    try:
        row = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == d_id)
        ).scalar_one()
        serialized = governance_decision_svc.decision_to_dict(row)
        assert serialized["evidence_refs"] == ["ev-001", "ev-002", "ev-003"]
    finally:
        db2.close()


def test_g29_related_finding_ids_stored_and_deserialized(SM, eng_id) -> None:
    """G29: related_finding_ids stored as JSON and returned as list in serialization."""
    from api.db_models_governance_decision import FaGovernanceDecision

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="remediation_approved",
            entity_type="engagement",
            entity_id=eng_id,
            actor_id="key-rfids",
            decision_reason="Remediation plan approved for three linked findings.",
            related_finding_ids=["fid-a", "fid-b", "fid-c"],
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    db2 = SM()
    try:
        row = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == d_id)
        ).scalar_one()
        serialized = governance_decision_svc.decision_to_dict(row)
        assert serialized["related_finding_ids"] == ["fid-a", "fid-b", "fid-c"]
    finally:
        db2.close()


def test_g30_risk_acceptance_decision_and_record_share_tenant_engagement(
    SM, eng_id, finding_id
) -> None:
    """G30: record_decision_with_risk_acceptance — both records share same tenant/engagement."""
    from api.db_models_governance_decision import FaGovernanceDecision, FaRiskAcceptance

    db = SM()
    try:
        dec, acc = governance_decision_svc.record_decision_with_risk_acceptance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            finding_id=finding_id,
            actor_id="key-ratest",
            decision_reason="Formal risk acceptance within board-approved tolerance.",
            risk_owner="Risk Owner",
            business_justification="Residual risk is within the board-approved tolerance.",
            accepted_risk_level="low",
            expires_at="2027-06-30T00:00:00Z",
            review_date="2026-12-31T00:00:00Z",
        )
        db.commit()
        dec_id = dec.id
        acc_id = acc.id
    finally:
        db.close()

    db2 = SM()
    try:
        d = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == dec_id)
        ).scalar_one()
        a = db2.execute(
            select(FaRiskAcceptance).where(FaRiskAcceptance.id == acc_id)
        ).scalar_one()
        assert d.tenant_id == a.tenant_id == _TENANT
        assert d.engagement_id == a.engagement_id == eng_id
        assert a.decision_id == d.id
    finally:
        db2.close()


def test_g31_exception_decision_and_record_share_tenant_engagement(SM, eng_id) -> None:
    """G31: record_decision_with_exception — both records share same tenant/engagement."""
    from api.db_models_governance_decision import (
        FaGovernanceDecision,
        FaGovernanceException,
    )

    db = SM()
    try:
        dec, exc = governance_decision_svc.record_decision_with_exception(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            actor_id="key-exctest",
            decision_reason="Exception granted pending vendor patch release.",
            exception_type="control_exception",
            owner="Security Lead",
            business_justification="Vendor patch not available until next quarter release.",
            expires_at="2026-12-31T00:00:00Z",
        )
        db.commit()
        dec_id = dec.id
        exc_id = exc.id
    finally:
        db.close()

    db2 = SM()
    try:
        d = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == dec_id)
        ).scalar_one()
        e = db2.execute(
            select(FaGovernanceException).where(FaGovernanceException.id == exc_id)
        ).scalar_one()
        assert d.tenant_id == e.tenant_id == _TENANT
        assert d.engagement_id == e.engagement_id == eng_id
        assert e.decision_id == d.id
    finally:
        db2.close()


def test_g32_list_decisions_respects_limit(SM, eng_id) -> None:
    """G32: list_decisions limit parameter is respected."""
    db = SM()
    try:
        for i in range(5):
            governance_decision_svc.record_decision(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                decision_type="policy_approved",
                entity_type="policy",
                entity_id=f"pol-limit-{i}",
                actor_id="key-limit",
                decision_reason=f"Limit test decision number {i}.",
            )
        db.commit()
    finally:
        db.close()

    db2 = SM()
    try:
        result = governance_decision_svc.list_decisions(
            db2, tenant_id=_TENANT, engagement_id=eng_id, limit=3
        )
        assert len(result) <= 3
    finally:
        db2.close()


def test_g33_approver_defaults_to_actor_id_when_not_provided(SM, eng_id) -> None:
    """G33: approver_id defaults to actor_id when not explicitly provided."""
    from api.db_models_governance_decision import FaGovernanceDecision

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-approver",
            actor_id="key-solo",
            decision_reason="Single-actor approval — approver defaults to actor.",
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    db2 = SM()
    try:
        row = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == d_id)
        ).scalar_one()
        assert row.approver_id == "key-solo"
        assert row.creator_id == "key-solo"
    finally:
        db2.close()


def test_g34_risk_acceptance_status_filter(
    client: TestClient, SM, eng_id, finding_id
) -> None:
    """G34: ?status=active filter on risk-acceptances returns only active records."""
    client.post(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        json={
            "finding_id": finding_id,
            "risk_owner": "G34 Owner",
            "business_justification": "G34 status filter test justification text.",
            "accepted_risk_level": "medium",
            "expires_at": "2027-01-01T00:00:00Z",
            "review_date": "2026-10-01T00:00:00Z",
        },
    )

    resp = client.get(
        f"/field-assessment/engagements/{eng_id}/risk-acceptances",
        params={"status": "active"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(r["status"] == "active" for r in data["risk_acceptances"])


def test_g35_decision_actor_auth_source_default_is_api_key(SM, eng_id) -> None:
    """G35: actor_auth_source defaults to 'api_key' when not specified."""
    from api.db_models_governance_decision import FaGovernanceDecision

    db = SM()
    try:
        decision = governance_decision_svc.record_decision(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-auth-src",
            actor_id="key-auth",
            decision_reason="Auth source default test.",
        )
        db.commit()
        d_id = decision.id
    finally:
        db.close()

    db2 = SM()
    try:
        row = db2.execute(
            select(FaGovernanceDecision).where(FaGovernanceDecision.id == d_id)
        ).scalar_one()
        assert row.actor_auth_source == "api_key"
    finally:
        db2.close()
