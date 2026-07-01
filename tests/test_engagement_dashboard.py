"""Tests for PR 18.2 — Engagement Portal Dashboard.

Coverage:
  EP-D-1   to EP-D-60: Dashboard engine + API surface
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from services.engagement_portal.engine import EngagementPortalEngine
from services.engagement_portal.schemas import DashboardResponse

_TENANT = "tenant-ep-dash-001"
_TENANT_B = "tenant-ep-dash-002"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return EngagementPortalEngine(db, tenant_id=_TENANT)


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("portal:read", "portal:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def ro_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("portal:read", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def wrong_scope_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def public_client(build_app):
    app = build_app(auth_enabled=True)
    return TestClient(app)


# ------------------------------ Engine ---------------------------------


def test_EP_D_1_dashboard_response_type(svc):
    assert isinstance(svc.get_dashboard(), DashboardResponse)


def test_EP_D_2_dashboard_has_tenant_id(svc):
    assert svc.get_dashboard().tenant_id == _TENANT


def test_EP_D_3_dashboard_engagement_id_none_by_default(svc):
    assert svc.get_dashboard().engagement_id is None


def test_EP_D_4_dashboard_engagement_id_set_when_provided(svc):
    assert svc.get_dashboard(assessment_id="a-1").engagement_id == "a-1"


def test_EP_D_5_dashboard_evidence_collected_int(svc):
    d = svc.get_dashboard()
    assert isinstance(d.evidence_collected, int)


def test_EP_D_6_dashboard_evidence_verified_int(svc):
    d = svc.get_dashboard()
    assert isinstance(d.evidence_verified, int)


def test_EP_D_7_dashboard_open_findings_non_negative(svc):
    assert svc.get_dashboard().open_findings >= 0


def test_EP_D_8_dashboard_pending_approvals_non_negative(svc):
    assert svc.get_dashboard().pending_approvals >= 0


def test_EP_D_9_dashboard_generated_at_non_empty(svc):
    assert len(svc.get_dashboard().generated_at) > 0


def test_EP_D_10_dashboard_latest_report_id_none_when_empty(svc):
    assert svc.get_dashboard().latest_report_id is None


def test_EP_D_11_dashboard_safe_defaults_for_overall_readiness(svc):
    assert svc.get_dashboard().overall_readiness is None


def test_EP_D_12_dashboard_safe_defaults_for_governance_score(svc):
    assert svc.get_dashboard().governance_score is None


def test_EP_D_13_dashboard_safe_defaults_for_assessment_progress(svc):
    assert svc.get_dashboard().assessment_progress is None


def test_EP_D_14_dashboard_safe_defaults_for_freshness_pct(svc):
    assert svc.get_dashboard().evidence_freshness_pct is None


def test_EP_D_15_dashboard_safe_defaults_for_remediation_progress(svc):
    assert svc.get_dashboard().remediation_progress is None


def test_EP_D_16_dashboard_safe_defaults_for_verification_status(svc):
    assert svc.get_dashboard().verification_status is None


def test_EP_D_17_dashboard_safe_defaults_for_trust_status(svc):
    assert svc.get_dashboard().trust_status is None


def test_EP_D_18_dashboard_safe_defaults_for_transparency_status(svc):
    assert svc.get_dashboard().transparency_status is None


def test_EP_D_19_dashboard_latest_state_none_when_empty(svc):
    assert svc.get_dashboard().latest_report_state is None


@pytest.mark.parametrize("aid", ["assess-1", "assess-2", None, "x"])
def test_EP_D_20_dashboard_with_assessments(svc, aid):
    assert svc.get_dashboard(assessment_id=aid).engagement_id == aid


# Tenant isolation
def test_EP_D_21_dashboard_tenant_isolation(db):
    e1 = EngagementPortalEngine(db, tenant_id=_TENANT)
    e2 = EngagementPortalEngine(db, tenant_id=_TENANT_B)
    d1 = e1.get_dashboard()
    d2 = e2.get_dashboard()
    assert d1.tenant_id == _TENANT
    assert d2.tenant_id == _TENANT_B
    assert d1.tenant_id != d2.tenant_id


# Schema-level checks
@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "t"),
        ("evidence_collected", 0),
        ("evidence_verified", 0),
        ("open_findings", 0),
        ("pending_approvals", 0),
        ("generated_at", "2025-01-01T00:00:00Z"),
    ],
)
def test_EP_D_22_dashboard_required_fields(field, value):
    payload = {
        "tenant_id": "t",
        "engagement_id": None,
        "overall_readiness": None,
        "governance_score": None,
        "assessment_progress": None,
        "evidence_collected": 0,
        "evidence_verified": 0,
        "evidence_freshness_pct": None,
        "open_findings": 0,
        "remediation_progress": None,
        "pending_approvals": 0,
        "latest_report_id": None,
        "latest_report_state": None,
        "verification_status": None,
        "trust_status": None,
        "transparency_status": None,
        "generated_at": "2025-01-01T00:00:00Z",
    }
    DashboardResponse(**payload)
    payload.pop(field)
    with pytest.raises(ValidationError):
        DashboardResponse(**payload)


def test_EP_D_23_dashboard_extra_field_rejected():
    payload = {
        "tenant_id": "t",
        "engagement_id": None,
        "overall_readiness": None,
        "governance_score": None,
        "assessment_progress": None,
        "evidence_collected": 0,
        "evidence_verified": 0,
        "evidence_freshness_pct": None,
        "open_findings": 0,
        "remediation_progress": None,
        "pending_approvals": 0,
        "latest_report_id": None,
        "latest_report_state": None,
        "verification_status": None,
        "trust_status": None,
        "transparency_status": None,
        "generated_at": "2025-01-01T00:00:00Z",
        "extra": "x",
    }
    with pytest.raises(ValidationError):
        DashboardResponse.model_validate(payload)


# ------------------------------ API ------------------------------------


def test_EP_D_30_api_dashboard_returns_200(ro_client):
    r = ro_client.get("/portal/engagement/dashboard")
    assert r.status_code == 200


def test_EP_D_31_api_dashboard_returns_json(ro_client):
    r = ro_client.get("/portal/engagement/dashboard")
    assert r.headers.get("content-type", "").startswith("application/json")


def test_EP_D_32_api_dashboard_tenant_id_field(ro_client):
    r = ro_client.get("/portal/engagement/dashboard")
    assert r.json()["tenant_id"] == _TENANT


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "engagement_id",
        "overall_readiness",
        "governance_score",
        "assessment_progress",
        "evidence_collected",
        "evidence_verified",
        "evidence_freshness_pct",
        "open_findings",
        "remediation_progress",
        "pending_approvals",
        "latest_report_id",
        "latest_report_state",
        "verification_status",
        "trust_status",
        "transparency_status",
        "generated_at",
    ],
)
def test_EP_D_33_api_dashboard_required_fields_present(ro_client, field):
    body = ro_client.get("/portal/engagement/dashboard").json()
    assert field in body


def test_EP_D_34_api_dashboard_wrong_scope_forbidden(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/dashboard")
    assert r.status_code in (401, 403)


def test_EP_D_35_api_dashboard_no_auth_forbidden(public_client):
    r = public_client.get("/portal/engagement/dashboard")
    assert r.status_code in (401, 403)


def test_EP_D_36_api_dashboard_with_assessment_id(ro_client):
    r = ro_client.get("/portal/engagement/dashboard?assessment_id=a-1")
    assert r.status_code == 200
    assert r.json()["engagement_id"] == "a-1"


def test_EP_D_37_api_dashboard_evidence_collected_is_int(ro_client):
    body = ro_client.get("/portal/engagement/dashboard").json()
    assert isinstance(body["evidence_collected"], int)


def test_EP_D_38_api_dashboard_evidence_verified_is_int(ro_client):
    body = ro_client.get("/portal/engagement/dashboard").json()
    assert isinstance(body["evidence_verified"], int)


def test_EP_D_39_api_dashboard_pending_approvals_non_negative(ro_client):
    body = ro_client.get("/portal/engagement/dashboard").json()
    assert body["pending_approvals"] >= 0


def test_EP_D_40_api_dashboard_open_findings_non_negative(ro_client):
    body = ro_client.get("/portal/engagement/dashboard").json()
    assert body["open_findings"] >= 0


# Health endpoint
def test_EP_D_41_health_public_no_auth(public_client):
    r = public_client.get("/portal/engagement/health")
    assert r.status_code == 200


def test_EP_D_42_health_response_ok(public_client):
    body = public_client.get("/portal/engagement/health").json()
    assert body["status"] == "ok"


def test_EP_D_43_health_schema_version(public_client):
    body = public_client.get("/portal/engagement/health").json()
    assert body["schema_version"] == "1.0"


def test_EP_D_44_health_has_timestamp(public_client):
    body = public_client.get("/portal/engagement/health").json()
    assert "timestamp" in body
    assert isinstance(body["timestamp"], str)


# Statistics
def test_EP_D_45_api_statistics_returns_200(ro_client):
    r = ro_client.get("/portal/engagement/statistics")
    assert r.status_code == 200


def test_EP_D_46_api_statistics_tenant_id(ro_client):
    body = ro_client.get("/portal/engagement/statistics").json()
    assert body["tenant_id"] == _TENANT


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "total_activities",
        "total_reports_viewed",
        "total_evidence_viewed",
        "total_searches",
        "active_notifications",
        "preferences_set",
        "computed_at",
    ],
)
def test_EP_D_47_api_statistics_has_field(ro_client, field):
    body = ro_client.get("/portal/engagement/statistics").json()
    assert field in body


def test_EP_D_48_api_statistics_counts_non_negative(ro_client):
    body = ro_client.get("/portal/engagement/statistics").json()
    for k in (
        "total_activities",
        "total_reports_viewed",
        "total_evidence_viewed",
        "total_searches",
        "active_notifications",
    ):
        assert body[k] >= 0


def test_EP_D_49_api_statistics_wrong_scope(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/statistics")
    assert r.status_code in (401, 403)


def test_EP_D_50_dashboard_deterministic_shape(svc):
    d1 = svc.get_dashboard().model_dump()
    d2 = svc.get_dashboard().model_dump()
    assert set(d1.keys()) == set(d2.keys())


def test_EP_D_51_dashboard_evidence_collected_default_zero(svc):
    assert svc.get_dashboard().evidence_collected == 0


def test_EP_D_52_dashboard_evidence_verified_default_zero(svc):
    assert svc.get_dashboard().evidence_verified == 0


def test_EP_D_53_dashboard_open_findings_default_zero(svc):
    assert svc.get_dashboard().open_findings == 0


def test_EP_D_54_dashboard_pending_approvals_default_zero(svc):
    assert svc.get_dashboard().pending_approvals == 0


def test_EP_D_55_dashboard_returns_string_timestamp(svc):
    assert isinstance(svc.get_dashboard().generated_at, str)


def test_EP_D_56_dashboard_engagement_id_str_type(svc):
    out = svc.get_dashboard(assessment_id="assess-A")
    assert isinstance(out.engagement_id, str)


def test_EP_D_57_dashboard_response_no_extras(svc):
    d = svc.get_dashboard()
    payload = d.model_dump()
    expected_keys = {
        "tenant_id",
        "engagement_id",
        "overall_readiness",
        "governance_score",
        "assessment_progress",
        "evidence_collected",
        "evidence_verified",
        "evidence_freshness_pct",
        "open_findings",
        "remediation_progress",
        "pending_approvals",
        "latest_report_id",
        "latest_report_state",
        "verification_status",
        "trust_status",
        "transparency_status",
        "generated_at",
    }
    assert set(payload.keys()) == expected_keys


def test_EP_D_58_dashboard_does_not_crash_when_no_data(svc):
    svc.get_dashboard()


def test_EP_D_59_dashboard_does_not_crash_with_unknown_assessment(svc):
    svc.get_dashboard(assessment_id="never-existed")


def test_EP_D_60_api_dashboard_method_not_allowed(ro_client):
    r = ro_client.post("/portal/engagement/dashboard")
    assert r.status_code == 405
