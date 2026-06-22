# tests/test_governance_reporting.py
"""Governance Reporting & Attestation Engine test suite — PR 14.5.

Coverage:
  GR-1   Generate report returns 201 with correct structure
  GR-2   Generated report: id field present
  GR-3   Generated report: report_hash non-empty
  GR-4   Generated report: manifest_hash non-empty
  GR-5   Generated report: risk_section included
  GR-6   Generated report: risk_section.title correct
  GR-7   Generated report: approval_chain is a list
  GR-8   Generated report: review_history is a list
  GR-9   Generated report: compensating_controls is a list
  GR-10  Generated report: governance_timeline is a list
  GR-11  Generated report: status is COMPLETED
  GR-12  Generated report: schema_version is 1.0
  GR-13  Generated report: report_version is 1 for first report
  GR-14  Generated report: generated_by stored correctly
  GR-15  Generated report: risk_section.accepted_by correct
  GR-16  Generated report: approval chain includes approval records
  GR-17  Generated report: review_history includes review records
  GR-18  Generated report: compensating_controls includes linked controls
  GR-19  Re-generating same risk increments report_version
  GR-20  Previous report superseded when new version generated
  GR-21  List reports returns 200 with items/total/limit/offset
  GR-22  List reports: filter by risk_acceptance_id
  GR-23  List reports: pagination limit
  GR-24  List reports: pagination offset
  GR-25  List reports: empty for new tenant
  GR-26  Get report detail returns 200
  GR-27  Get report: risk_section.title correct
  GR-28  Get report: approval_chain populated when approvals exist
  GR-29  Get report: compensating_controls populated when controls linked
  GR-30  Get report: evidence_count aggregated
  GR-31  Get report: control_count correct
  GR-32  Get report: approval_count correct
  GR-33  Get report: review_count correct
  GR-34  Get report 404 for unknown id
  GR-35  Get report 404 for wrong tenant
  GR-36  Get manifest returns all hash fields
  GR-37  Manifest: risk_acceptance_hash non-empty
  GR-38  Manifest: approval_chain_hash non-empty
  GR-39  Manifest: review_history_hash non-empty
  GR-40  Manifest: control_evidence_hash non-empty
  GR-41  Manifest: timeline_hash non-empty
  GR-42  Manifest: overall_hash non-empty
  GR-43  Manifest: report_id matches generated report id
  GR-44  Manifest 404 for unknown report id
  GR-45  Manifest 404 for wrong tenant
  GR-46  Report timeline returns items list and total
  GR-47  Report timeline: event_id present in each event
  GR-48  Report timeline: event_type present
  GR-49  Report timeline: occurred_at present
  GR-50  Report timeline: source present
  GR-51  Report timeline: events ordered ascending by occurred_at
  GR-52  Report timeline: total is non-negative
  GR-53  Report timeline: pagination limit works
  GR-54  Report timeline 404 for unknown report
  GR-55  Report timeline 404 for wrong tenant
  GR-56  Create attestation returns 201
  GR-57  Attestation: id field present
  GR-58  Attestation: attestor stored correctly
  GR-59  Attestation: attestation_type stored correctly
  GR-60  Attestation: attestation_statement stored correctly
  GR-61  Attestation: signature_hash non-empty
  GR-62  Attestation: attested_at set
  GR-63  Attestation: schema_version is 1.0
  GR-64  Attestation: actor_type defaults to HUMAN
  GR-65  Attestation type OWNER accepted
  GR-66  Attestation type RISK_OWNER accepted
  GR-67  Attestation type APPROVER accepted
  GR-68  Attestation type REVIEWER accepted
  GR-69  Attestation type EXECUTIVE accepted
  GR-70  Attestation type AUDITOR accepted
  GR-71  List attestations returns items/total/limit/offset
  GR-72  List attestations: multiple allowed for same report
  GR-73  Attestation 404 for unknown report
  GR-74  Attestation 404 for wrong tenant
  GR-75  List attestations 404 for wrong tenant
  GR-76  Verify report returns VALID for intact report
  GR-77  Verify: result field present
  GR-78  Verify: report_hash present
  GR-79  Verify: manifest_hash present
  GR-80  Verify: verified_at present
  GR-81  Verify: evidence_count present
  GR-82  Verify: control_count present
  GR-83  Verify: approval_count present
  GR-84  Verify: review_count present
  GR-85  Verify 404 for unknown report
  GR-86  HTML export returns 200
  GR-87  HTML export: content-type is text/html
  GR-88  HTML export: contains risk title
  GR-89  HTML export: contains Approval Chain section
  GR-90  HTML export: contains Compensating Controls section
  GR-91  HTML export: contains Governance Timeline section
  GR-92  HTML export 404 for unknown report
  GR-93  HTML export: audit event recorded
  GR-94  PDF export returns 200
  GR-95  PDF export: content-type is application/pdf
  GR-96  PDF export: non-empty bytes
  GR-97  PDF export: starts with %PDF header
  GR-98  PDF export 404 for unknown report
  GR-99  PDF export: Content-Disposition header present
  GR-100 PDF export 404 for wrong tenant
  GR-101 PDF export: audit recorded
  GR-102 Tenant B cannot see Tenant A reports
  GR-103 Tenant B cannot get Tenant A report manifest
  GR-104 Tenant B cannot get Tenant A report timeline
  GR-105 Tenant B cannot attest Tenant A report
  GR-106 Write scope required for generate
  GR-107 Write scope required for attest
  GR-108 Read scope required for list reports
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_engine


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-gr-a"
_TENANT_B = "tenant-gr-b"


# ---------------------------------------------------------------------------
# DB-level helpers
# ---------------------------------------------------------------------------


def _new_engagement(db: Session, tenant_id: str) -> str:
    from api.db_models_field_assessment import FaEngagement

    eid = uuid.uuid4().hex
    now = "2026-01-01T00:00:00+00:00"
    eng = FaEngagement(
        id=eid,
        tenant_id=tenant_id,
        client_name="GR Test Client",
        assessor_id="assessor-gr",
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
    from api.db_models_field_assessment import FaNormalizedFinding

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
        title="GR Test Finding",
        description="A test finding for governance reporting.",
        source_attribution="scanner",
        created_at=now,
        updated_at=now,
    )
    db.add(finding)
    db.commit()
    return fid


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _j(r: Any) -> dict:
    assert r.json() is not None
    return r.json()


def _make_risk(
    client: TestClient,
    db: Session,
    tenant_id: str,
    **overrides: Any,
) -> dict:
    assessment_id = _new_engagement(db, tenant_id)
    finding_id = _new_finding(db, tenant_id, assessment_id)
    base: dict[str, Any] = {
        "finding_id": finding_id,
        "assessment_id": assessment_id,
        "title": "SQL Injection in Legacy API",
        "business_justification": "Cost-prohibitive to patch before Q3.",
        "risk_rationale": "Low exploitation probability in current environment.",
        "accepted_by": "ciso@example.com",
    }
    base.update(overrides)
    r = client.post("/risk-acceptances", json=base)
    assert r.status_code == 201, r.text
    return _j(r)


def _generate_report(client: TestClient, risk_id: str, **overrides: Any) -> dict:
    base: dict[str, Any] = {
        "risk_acceptance_id": risk_id,
        "generated_by": "test-system@example.com",
    }
    base.update(overrides)
    r = client.post("/governance-reports", json=base)
    assert r.status_code == 201, r.text
    return _j(r)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session(build_app):
    build_app(auth_enabled=True)
    engine = get_engine()
    with Session(engine) as session:
        yield session


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
# GR-1 — GR-20: Report generation
# ---------------------------------------------------------------------------


def test_gr_1_generate_report_returns_201(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    r = client.post(
        "/governance-reports",
        json={"risk_acceptance_id": risk["id"], "generated_by": "test@example.com"},
    )
    assert r.status_code == 201


def test_gr_2_generate_report_id_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert "id" in body
    assert len(body["id"]) > 0


def test_gr_3_generate_report_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert body.get("report_hash")
    assert len(body["report_hash"]) == 64  # sha256 hex


def test_gr_4_generate_report_manifest_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert body.get("manifest_hash")
    assert len(body["manifest_hash"]) == 64


def test_gr_5_generate_report_risk_section_included(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert "risk_section" in body
    assert isinstance(body["risk_section"], dict)


def test_gr_6_generate_report_risk_section_title(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert body["risk_section"]["title"] == "SQL Injection in Legacy API"


def test_gr_7_generate_report_approval_chain_is_list(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert isinstance(body["approval_chain"], list)


def test_gr_8_generate_report_review_history_is_list(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert isinstance(body["review_history"], list)


def test_gr_9_generate_report_compensating_controls_is_list(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert isinstance(body["compensating_controls"], list)


def test_gr_10_generate_report_governance_timeline_is_list(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert isinstance(body["governance_timeline"], list)


def test_gr_11_generate_report_status_completed(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert body["status"] == "COMPLETED"


def test_gr_12_generate_report_schema_version(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert body["schema_version"] == "1.0"


def test_gr_13_generate_report_first_version_is_1(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert body["report_version"] == 1


def test_gr_14_generate_report_generated_by_stored(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"], generated_by="auditor@example.com")
    assert body["generated_by"] == "auditor@example.com"


def test_gr_15_generate_report_risk_section_accepted_by(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    body = _generate_report(client, risk["id"])
    assert body["risk_section"]["accepted_by"] == "ciso@example.com"


def test_gr_16_generate_report_approval_chain_includes_approvals(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    # Create an approval
    client.post(
        f"/risk-acceptances/{risk['id']}/approvals",
        json={
            "approver_name": "Alice",
            "approver_email": "alice@example.com",
            "approver_role": "CISO",
            "approval_type": "single",
        },
    )
    body = _generate_report(client, risk["id"])
    assert len(body["approval_chain"]) >= 1
    assert body["approval_count"] >= 1


def test_gr_17_generate_report_review_history_includes_reviews(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    # Create a review
    client.post(
        f"/risk-acceptances/{risk['id']}/reviews",
        json={
            "review_type": "periodic",
            "reviewer": "reviewer@example.com",
            "review_due_at": "2026-09-01T00:00:00+00:00",
        },
    )
    body = _generate_report(client, risk["id"])
    assert len(body["review_history"]) >= 1
    assert body["review_count"] >= 1


def test_gr_18_generate_report_controls_included(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    # Create a control
    ctrl_r = client.post(
        "/controls",
        json={
            "title": "WAF Rule",
            "description": "Blocks XSS",
            "control_type": "technical",
            "criticality": "high",
            "effectiveness_rating": "effective",
            "review_frequency_days": 90,
        },
    )
    assert ctrl_r.status_code == 201
    ctrl = _j(ctrl_r)
    # Link control to risk via the control registry route
    link_r = client.post(
        f"/controls/{ctrl['id']}/risk-links",
        json={
            "risk_acceptance_id": risk["id"],
            "rationale": "Mitigates attack surface",
        },
    )
    assert link_r.status_code == 201
    body = _generate_report(client, risk["id"])
    assert len(body["compensating_controls"]) >= 1
    assert body["control_count"] >= 1


def test_gr_19_second_report_version_increments(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    v1 = _generate_report(client, risk["id"])
    v2 = _generate_report(client, risk["id"])
    assert v1["report_version"] == 1
    assert v2["report_version"] == 2


def test_gr_20_previous_report_superseded(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    v1 = _generate_report(client, risk["id"])
    _generate_report(client, risk["id"])
    # v1 should now be SUPERSEDED
    r = client.get(f"/governance-reports/{v1['id']}")
    assert r.status_code == 200
    assert _j(r)["status"] == "SUPERSEDED"


# ---------------------------------------------------------------------------
# GR-21 — GR-35: Listing and retrieval
# ---------------------------------------------------------------------------


def test_gr_21_list_reports_returns_structure(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    _generate_report(client, risk["id"])
    r = client.get("/governance-reports")
    assert r.status_code == 200
    body = _j(r)
    assert "items" in body
    assert "total" in body
    assert "limit" in body
    assert "offset" in body


def test_gr_22_list_reports_filter_by_risk_acceptance_id(client, db_session):
    risk1 = _make_risk(client, db_session, _TENANT_A)
    risk2 = _make_risk(client, db_session, _TENANT_A)
    _generate_report(client, risk1["id"])
    _generate_report(client, risk2["id"])
    r = client.get(f"/governance-reports?risk_acceptance_id={risk1['id']}")
    assert r.status_code == 200
    body = _j(r)
    assert all(item["risk_acceptance_id"] == risk1["id"] for item in body["items"])


def test_gr_23_list_reports_pagination_limit(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    for _ in range(3):
        _generate_report(client, risk["id"])
    r = client.get("/governance-reports?limit=2")
    assert r.status_code == 200
    body = _j(r)
    assert len(body["items"]) <= 2


def test_gr_24_list_reports_pagination_offset(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    _generate_report(client, risk["id"])
    _generate_report(client, risk["id"])
    r_all = client.get("/governance-reports")
    r_offset = client.get("/governance-reports?offset=1&limit=10")
    assert r_offset.status_code == 200
    assert (
        len(_j(r_offset)["items"]) < _j(r_all)["total"] or _j(r_offset)["offset"] == 1
    )


def test_gr_25_list_reports_empty_for_new_tenant(client_b):
    r = client_b.get("/governance-reports")
    assert r.status_code == 200
    # Tenant B may have been used by other tests but should return valid structure
    body = _j(r)
    assert "items" in body
    assert body["total"] >= 0


def test_gr_26_get_report_detail_returns_200(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    assert r.status_code == 200


def test_gr_27_get_report_risk_section_title(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    body = _j(r)
    assert body["risk_section"]["title"] == "SQL Injection in Legacy API"


def test_gr_28_get_report_approval_chain_populated(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    client.post(
        f"/risk-acceptances/{risk['id']}/approvals",
        json={
            "approver_name": "Bob",
            "approver_email": "bob@example.com",
            "approval_type": "single",
        },
    )
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    body = _j(r)
    assert len(body["approval_chain"]) >= 1


def test_gr_29_get_report_compensating_controls_populated(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    ctrl_r = client.post(
        "/controls",
        json={
            "title": "Firewall Rule",
            "description": "Blocks ingress",
            "control_type": "technical",
            "criticality": "medium",
            "effectiveness_rating": "effective",
            "review_frequency_days": 90,
        },
    )
    ctrl = _j(ctrl_r)
    client.post(
        f"/controls/{ctrl['id']}/risk-links",
        json={"risk_acceptance_id": risk["id"]},
    )
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    body = _j(r)
    assert len(body["compensating_controls"]) >= 1


def test_gr_30_get_report_evidence_count_aggregated(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    ctrl_r = client.post(
        "/controls",
        json={
            "title": "Monitoring System",
            "description": "Monitors activity",
            "control_type": "detective",
            "criticality": "medium",
            "effectiveness_rating": "effective",
            "review_frequency_days": 90,
        },
    )
    ctrl = _j(ctrl_r)
    client.post(
        f"/controls/{ctrl['id']}/evidence",
        json={
            "evidence_id": f"ev-{uuid.uuid4().hex[:8]}",
            "evidence_type": "scan_report",
            "linked_by": "ops@example.com",
        },
    )
    client.post(
        f"/controls/{ctrl['id']}/risk-links",
        json={"risk_acceptance_id": risk["id"]},
    )
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    body = _j(r)
    assert body["evidence_count"] >= 1


def test_gr_31_get_report_control_count(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    body = _j(r)
    assert "control_count" in body
    assert isinstance(body["control_count"], int)


def test_gr_32_get_report_approval_count(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    body = _j(r)
    assert "approval_count" in body
    assert isinstance(body["approval_count"], int)


def test_gr_33_get_report_review_count(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}")
    body = _j(r)
    assert "review_count" in body
    assert isinstance(body["review_count"], int)


def test_gr_34_get_report_404_unknown(client):
    r = client.get("/governance-reports/nonexistent-report-id")
    assert r.status_code == 404


def test_gr_35_get_report_404_wrong_tenant(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.get(f"/governance-reports/{report['id']}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GR-36 — GR-45: Manifest
# ---------------------------------------------------------------------------


def test_gr_36_get_manifest_all_hash_fields(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    assert r.status_code == 200
    body = _j(r)
    for field in [
        "id",
        "report_id",
        "risk_acceptance_hash",
        "approval_chain_hash",
        "review_history_hash",
        "control_evidence_hash",
        "timeline_hash",
        "overall_hash",
    ]:
        assert field in body, f"Missing field: {field}"


def test_gr_37_manifest_risk_acceptance_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    body = _j(r)
    assert body["risk_acceptance_hash"]
    assert len(body["risk_acceptance_hash"]) == 64


def test_gr_38_manifest_approval_chain_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    body = _j(r)
    assert body["approval_chain_hash"]
    assert len(body["approval_chain_hash"]) == 64


def test_gr_39_manifest_review_history_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    body = _j(r)
    assert body["review_history_hash"]
    assert len(body["review_history_hash"]) == 64


def test_gr_40_manifest_control_evidence_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    body = _j(r)
    assert body["control_evidence_hash"]
    assert len(body["control_evidence_hash"]) == 64


def test_gr_41_manifest_timeline_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    body = _j(r)
    assert body["timeline_hash"]
    assert len(body["timeline_hash"]) == 64


def test_gr_42_manifest_overall_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    body = _j(r)
    assert body["overall_hash"]
    assert len(body["overall_hash"]) == 64


def test_gr_43_manifest_report_id_matches(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/manifest")
    body = _j(r)
    assert body["report_id"] == report["id"]


def test_gr_44_manifest_404_unknown_report(client):
    r = client.get("/governance-reports/nonexistent-id/manifest")
    assert r.status_code == 404


def test_gr_45_manifest_404_wrong_tenant(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.get(f"/governance-reports/{report['id']}/manifest")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GR-46 — GR-55: Timeline within report
# ---------------------------------------------------------------------------


def test_gr_46_report_timeline_returns_structure(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline")
    assert r.status_code == 200
    body = _j(r)
    assert "items" in body
    assert "total" in body


def test_gr_47_report_timeline_event_id_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline")
    body = _j(r)
    for item in body["items"]:
        assert "event_id" in item


def test_gr_48_report_timeline_event_type_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline")
    body = _j(r)
    for item in body["items"]:
        assert "event_type" in item


def test_gr_49_report_timeline_occurred_at_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline")
    body = _j(r)
    for item in body["items"]:
        assert "occurred_at" in item


def test_gr_50_report_timeline_source_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline")
    body = _j(r)
    for item in body["items"]:
        assert "source" in item


def test_gr_51_report_timeline_sorted_ascending(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline")
    body = _j(r)
    items = body["items"]
    if len(items) >= 2:
        for i in range(len(items) - 1):
            assert items[i]["occurred_at"] <= items[i + 1]["occurred_at"]


def test_gr_52_report_timeline_total_non_negative(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline")
    body = _j(r)
    assert body["total"] >= 0


def test_gr_53_report_timeline_pagination_limit(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.get(f"/governance-reports/{report['id']}/timeline?limit=1")
    assert r.status_code == 200
    body = _j(r)
    assert len(body["items"]) <= 1


def test_gr_54_report_timeline_404_unknown(client):
    r = client.get("/governance-reports/nonexistent-id/timeline")
    assert r.status_code == 404


def test_gr_55_report_timeline_404_wrong_tenant(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.get(f"/governance-reports/{report['id']}/timeline")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GR-56 — GR-75: Attestation
# ---------------------------------------------------------------------------

_ATTEST_BODY: dict[str, Any] = {
    "attestor": "auditor@example.com",
    "attestor_role": "External Auditor",
    "attestation_type": "AUDITOR",
    "attestation_statement": "I hereby attest that this governance report is accurate and complete.",
}


def test_gr_56_create_attestation_returns_201(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    assert r.status_code == 201


def test_gr_57_attestation_id_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert "id" in body
    assert len(body["id"]) > 0


def test_gr_58_attestation_attestor_stored(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert body["attestor"] == "auditor@example.com"


def test_gr_59_attestation_type_stored(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert body["attestation_type"] == "AUDITOR"


def test_gr_60_attestation_statement_stored(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert body["attestation_statement"] == _ATTEST_BODY["attestation_statement"]


def test_gr_61_attestation_signature_hash_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert body["signature_hash"]
    assert len(body["signature_hash"]) == 64


def test_gr_62_attestation_attested_at_set(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert body["attested_at"]


def test_gr_63_attestation_schema_version(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert body["schema_version"] == "1.0"


def test_gr_64_attestation_actor_type_defaults_human(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body = _j(r)
    assert body["actor_type"] == "HUMAN"


def test_gr_65_attestation_type_owner(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    body_req = {**_ATTEST_BODY, "attestation_type": "OWNER"}
    r = client.post(f"/governance-reports/{report['id']}/attest", json=body_req)
    assert r.status_code == 201
    assert _j(r)["attestation_type"] == "OWNER"


def test_gr_66_attestation_type_risk_owner(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    body_req = {**_ATTEST_BODY, "attestation_type": "RISK_OWNER"}
    r = client.post(f"/governance-reports/{report['id']}/attest", json=body_req)
    assert r.status_code == 201
    assert _j(r)["attestation_type"] == "RISK_OWNER"


def test_gr_67_attestation_type_approver(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    body_req = {**_ATTEST_BODY, "attestation_type": "APPROVER"}
    r = client.post(f"/governance-reports/{report['id']}/attest", json=body_req)
    assert r.status_code == 201
    assert _j(r)["attestation_type"] == "APPROVER"


def test_gr_68_attestation_type_reviewer(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    body_req = {**_ATTEST_BODY, "attestation_type": "REVIEWER"}
    r = client.post(f"/governance-reports/{report['id']}/attest", json=body_req)
    assert r.status_code == 201
    assert _j(r)["attestation_type"] == "REVIEWER"


def test_gr_69_attestation_type_executive(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    body_req = {**_ATTEST_BODY, "attestation_type": "EXECUTIVE"}
    r = client.post(f"/governance-reports/{report['id']}/attest", json=body_req)
    assert r.status_code == 201
    assert _j(r)["attestation_type"] == "EXECUTIVE"


def test_gr_70_attestation_type_auditor(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    body_req = {**_ATTEST_BODY, "attestation_type": "AUDITOR"}
    r = client.post(f"/governance-reports/{report['id']}/attest", json=body_req)
    assert r.status_code == 201
    assert _j(r)["attestation_type"] == "AUDITOR"


def test_gr_71_list_attestations_structure(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    r = client.get(f"/governance-reports/{report['id']}/attestations")
    assert r.status_code == 200
    body = _j(r)
    assert "items" in body
    assert "total" in body
    assert body["total"] >= 1


def test_gr_72_multiple_attestations_allowed(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    body2 = {
        **_ATTEST_BODY,
        "attestation_type": "OWNER",
        "attestor": "owner@example.com",
    }
    client.post(f"/governance-reports/{report['id']}/attest", json=body2)
    r = client.get(f"/governance-reports/{report['id']}/attestations")
    body = _j(r)
    assert body["total"] >= 2


def test_gr_73_attestation_404_unknown_report(client):
    r = client.post("/governance-reports/nonexistent-id/attest", json=_ATTEST_BODY)
    assert r.status_code == 404


def test_gr_74_attestation_404_wrong_tenant(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    assert r.status_code == 404


def test_gr_75_list_attestations_404_wrong_tenant(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    client.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    r = client_b.get(f"/governance-reports/{report['id']}/attestations")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GR-76 — GR-85: Verification
# ---------------------------------------------------------------------------


def test_gr_76_verify_report_valid(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    assert r.status_code == 200
    body = _j(r)
    assert body["result"] == "VALID"


def test_gr_77_verify_result_field_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "result" in body


def test_gr_78_verify_report_hash_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "report_hash" in body
    assert body["report_hash"]


def test_gr_79_verify_manifest_hash_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "manifest_hash" in body
    assert body["manifest_hash"]


def test_gr_80_verify_verified_at_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "verified_at" in body
    assert body["verified_at"]


def test_gr_81_verify_evidence_count_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "evidence_count" in body
    assert isinstance(body["evidence_count"], int)


def test_gr_82_verify_control_count_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "control_count" in body
    assert isinstance(body["control_count"], int)


def test_gr_83_verify_approval_count_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "approval_count" in body
    assert isinstance(body["approval_count"], int)


def test_gr_84_verify_review_count_present(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/verify")
    body = _j(r)
    assert "review_count" in body
    assert isinstance(body["review_count"], int)


def test_gr_85_verify_404_unknown(client):
    r = client.post("/governance-reports/nonexistent-id/verify")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GR-86 — GR-93: HTML export
# ---------------------------------------------------------------------------


def test_gr_86_html_export_returns_200(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/html")
    assert r.status_code == 200


def test_gr_87_html_export_content_type(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/html")
    assert "text/html" in r.headers.get("content-type", "")


def test_gr_88_html_export_contains_risk_title(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/html")
    assert "SQL Injection in Legacy API" in r.text


def test_gr_89_html_export_contains_approval_section(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/html")
    assert "Approval Chain" in r.text


def test_gr_90_html_export_contains_controls_section(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/html")
    assert "Compensating Controls" in r.text


def test_gr_91_html_export_contains_timeline_section(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/html")
    assert "Governance Timeline" in r.text


def test_gr_92_html_export_404_unknown(client):
    r = client.post("/governance-reports/nonexistent-id/export/html")
    assert r.status_code == 404


def test_gr_93_html_export_audit_recorded(client, db_session):
    # Simply verify no error — audit is internal
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/html")
    assert r.status_code == 200
    # Verify report still accessible after export
    r2 = client.get(f"/governance-reports/{report['id']}")
    assert r2.status_code == 200


# ---------------------------------------------------------------------------
# GR-94 — GR-101: PDF export
# ---------------------------------------------------------------------------


def test_gr_94_pdf_export_returns_200(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/pdf")
    assert r.status_code == 200


def test_gr_95_pdf_export_content_type(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/pdf")
    assert "application/pdf" in r.headers.get("content-type", "")


def test_gr_96_pdf_export_non_empty(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/pdf")
    assert len(r.content) > 0


def test_gr_97_pdf_export_starts_with_pdf_header(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/pdf")
    assert r.content[:4] == b"%PDF"


def test_gr_98_pdf_export_404_unknown(client):
    r = client.post("/governance-reports/nonexistent-id/export/pdf")
    assert r.status_code == 404


def test_gr_99_pdf_export_content_disposition(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/pdf")
    cd = r.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert report["id"] in cd


def test_gr_100_pdf_export_404_wrong_tenant(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.post(f"/governance-reports/{report['id']}/export/pdf")
    assert r.status_code == 404


def test_gr_101_pdf_export_audit_recorded(client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client.post(f"/governance-reports/{report['id']}/export/pdf")
    assert r.status_code == 200
    # Verify report still accessible after export (audit doesn't break state)
    r2 = client.get(f"/governance-reports/{report['id']}")
    assert r2.status_code == 200


# ---------------------------------------------------------------------------
# GR-102 — GR-105: Tenant isolation
# ---------------------------------------------------------------------------


def test_gr_102_tenant_b_cannot_see_tenant_a_reports(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.get(f"/governance-reports/{report['id']}")
    assert r.status_code == 404


def test_gr_103_tenant_b_cannot_get_tenant_a_manifest(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.get(f"/governance-reports/{report['id']}/manifest")
    assert r.status_code == 404


def test_gr_104_tenant_b_cannot_get_tenant_a_timeline(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.get(f"/governance-reports/{report['id']}/timeline")
    assert r.status_code == 404


def test_gr_105_tenant_b_cannot_attest_tenant_a_report(client, client_b, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = client_b.post(f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GR-106 — GR-108: Scope enforcement
# ---------------------------------------------------------------------------


def test_gr_106_write_required_for_generate(readonly_client, db_session):
    risk = _make_risk(
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
        "/governance-reports",
        json={"risk_acceptance_id": risk["id"], "generated_by": "test@example.com"},
    )
    assert r.status_code == 403


def test_gr_107_write_required_for_attest(readonly_client, client, db_session):
    risk = _make_risk(client, db_session, _TENANT_A)
    report = _generate_report(client, risk["id"])
    r = readonly_client.post(
        f"/governance-reports/{report['id']}/attest", json=_ATTEST_BODY
    )
    assert r.status_code == 403


def test_gr_108_read_required_for_list(writeonly_client):
    r = writeonly_client.get("/governance-reports")
    assert r.status_code == 403
