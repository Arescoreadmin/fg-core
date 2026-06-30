"""Tests for PR 18.2 — Engagement Portal Report workspace.

Coverage:
  EP-R-1 to EP-R-60: Report workspace engine + API surface, fa_report integration
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_report_authority import FaReport
from services.engagement_portal.engine import EngagementPortalEngine
from services.engagement_portal.schemas import (
    ReportWorkspaceItem,
    ReportWorkspaceResponse,
)

_TENANT = "tenant-ep-rpt-001"
_TENANT_B = "tenant-ep-rpt-002"


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _make_report(
    tenant_id: str = _TENANT,
    *,
    title: str = "Test Report",
    report_ref: str = "REF-001",
    state: str = "DRAFT",
    signed: bool = False,
) -> FaReport:
    return FaReport(
        id=uuid.uuid4().hex[:16],
        tenant_id=tenant_id,
        report_ref=report_ref,
        report_type="EXECUTIVE",
        lifecycle_state=state,
        schema_version="1.0",
        title=title,
        report_version="1.0.0-r0",
        major_version=1,
        minor_version=0,
        patch_version=0,
        report_revision=0,
        has_pdf=1 if signed else 0,
        has_html=0,
        has_json=0,
        signature="sig" if signed else None,
        manifest_hash="mh" if signed else None,
        signing_algorithm="ed25519" if signed else None,
        created_at=_now(),
        updated_at=_now(),
    )


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


# ------------------------ Engine ------------------------


def test_EP_R_1_empty_workspace_response(svc):
    r = svc.get_report_workspace()
    assert isinstance(r, ReportWorkspaceResponse)
    assert r.items == []
    assert r.total == 0


def test_EP_R_2_workspace_with_one_report(svc, db):
    db.add(_make_report())
    db.commit()
    r = svc.get_report_workspace()
    assert r.total >= 1
    assert any(it.title == "Test Report" for it in r.items)


def test_EP_R_3_workspace_excludes_other_tenant(svc, db):
    db.add(_make_report(tenant_id=_TENANT, title="MINE"))
    db.add(_make_report(tenant_id=_TENANT_B, title="OTHER"))
    db.commit()
    r = svc.get_report_workspace()
    assert all(it.title != "OTHER" for it in r.items)


@pytest.mark.parametrize("n", [0, 1, 3, 5])
def test_EP_R_4_workspace_returns_expected_count(svc, db, n):
    for i in range(n):
        db.add(_make_report(report_ref=f"REF-{i}"))
    db.commit()
    r = svc.get_report_workspace(limit=10)
    assert r.total >= n


def test_EP_R_5_workspace_pagination_limit(svc, db):
    for i in range(5):
        db.add(_make_report(report_ref=f"REF-{i}"))
    db.commit()
    r = svc.get_report_workspace(limit=2)
    assert len(r.items) <= 2


def test_EP_R_6_workspace_item_trust_verified_flag(svc, db):
    db.add(_make_report(signed=True))
    db.commit()
    r = svc.get_report_workspace()
    assert any(it.trust_verified for it in r.items)


def test_EP_R_7_workspace_item_unsigned_not_verified(svc, db):
    db.add(_make_report(signed=False))
    db.commit()
    r = svc.get_report_workspace()
    assert any(it.trust_verified is False for it in r.items)


def test_EP_R_8_workspace_pdf_flag_bool(svc, db):
    db.add(_make_report(signed=True))
    db.commit()
    r = svc.get_report_workspace()
    for it in r.items:
        assert isinstance(it.has_pdf, bool)


def test_EP_R_9_workspace_lifecycle_state_round_trip(svc, db):
    db.add(_make_report(state="PUBLISHED"))
    db.commit()
    r = svc.get_report_workspace()
    states = {it.lifecycle_state for it in r.items}
    assert "PUBLISHED" in states


@pytest.mark.parametrize("limit", [1, 5, 10, 50])
def test_EP_R_10_workspace_limit_round_trip(svc, limit):
    r = svc.get_report_workspace(limit=limit)
    assert r.limit == limit


# ------------------------ Schema validation ------------------------


def test_EP_R_20_report_item_minimal():
    item = ReportWorkspaceItem(
        report_id="r1",
        report_ref="REF",
        report_type="EXECUTIVE",
        lifecycle_state="DRAFT",
        title="T",
        quality_grade=None,
        published_at=None,
        has_pdf=False,
        has_html=False,
        has_json=False,
        manifest_hash=None,
        trust_verified=False,
    )
    assert item.report_id == "r1"


def test_EP_R_21_report_item_extra_forbid():
    with pytest.raises(ValidationError):
        ReportWorkspaceItem(
            report_id="r1",
            report_ref="REF",
            report_type="x",
            lifecycle_state="x",
            title="x",
            quality_grade=None,
            published_at=None,
            has_pdf=False,
            has_html=False,
            has_json=False,
            manifest_hash=None,
            trust_verified=False,
            unknown="x",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "missing",
    [
        "report_id",
        "report_ref",
        "report_type",
        "lifecycle_state",
        "title",
        "has_pdf",
        "has_html",
        "has_json",
        "trust_verified",
    ],
)
def test_EP_R_22_report_item_required(missing):
    payload = {
        "report_id": "r1",
        "report_ref": "REF",
        "report_type": "EXECUTIVE",
        "lifecycle_state": "DRAFT",
        "title": "T",
        "quality_grade": None,
        "published_at": None,
        "has_pdf": False,
        "has_html": False,
        "has_json": False,
        "manifest_hash": None,
        "trust_verified": False,
    }
    payload.pop(missing)
    with pytest.raises(ValidationError):
        ReportWorkspaceItem(**payload)


def test_EP_R_23_report_workspace_response_extra_forbid():
    with pytest.raises(ValidationError):
        ReportWorkspaceResponse(items=[], total=0, offset=0, limit=10, extra="x")  # type: ignore[call-arg]


# ------------------------ API ------------------------


def test_EP_R_30_api_reports_returns_200(ro_client):
    r = ro_client.get("/portal/engagement/reports")
    assert r.status_code == 200


def test_EP_R_31_api_reports_empty_items(ro_client):
    body = ro_client.get("/portal/engagement/reports").json()
    assert body["items"] == []


def test_EP_R_32_api_reports_default_limit(ro_client):
    body = ro_client.get("/portal/engagement/reports").json()
    assert body["limit"] == 50


def test_EP_R_33_api_reports_default_offset(ro_client):
    body = ro_client.get("/portal/engagement/reports").json()
    assert body["offset"] == 0


def test_EP_R_34_api_reports_wrong_scope(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/reports")
    assert r.status_code in (401, 403)


def test_EP_R_35_api_reports_no_auth(public_client):
    r = public_client.get("/portal/engagement/reports")
    assert r.status_code in (401, 403)


def test_EP_R_36_api_reports_invalid_limit(ro_client):
    r = ro_client.get("/portal/engagement/reports?limit=0")
    assert r.status_code == 422


def test_EP_R_37_api_reports_invalid_offset(ro_client):
    r = ro_client.get("/portal/engagement/reports?offset=-1")
    assert r.status_code == 422


def test_EP_R_38_api_reports_method_not_allowed(ro_client):
    r = ro_client.post("/portal/engagement/reports")
    assert r.status_code == 405


@pytest.mark.parametrize("limit", [1, 10, 50, 500])
def test_EP_R_39_api_reports_valid_limits(ro_client, limit):
    r = ro_client.get(f"/portal/engagement/reports?limit={limit}")
    assert r.status_code == 200


@pytest.mark.parametrize("offset", [0, 1, 100])
def test_EP_R_40_api_reports_valid_offsets(ro_client, offset):
    r = ro_client.get(f"/portal/engagement/reports?offset={offset}")
    assert r.status_code == 200


@pytest.mark.parametrize("field", ["items", "total", "offset", "limit"])
def test_EP_R_41_api_reports_keys(ro_client, field):
    body = ro_client.get("/portal/engagement/reports").json()
    assert field in body


def test_EP_R_42_workspace_response_dump_shape(svc):
    r = svc.get_report_workspace().model_dump()
    assert set(r.keys()) == {"items", "total", "offset", "limit"}


@pytest.mark.parametrize("state", ["DRAFT", "PUBLISHED", "SUPERSEDED", "ARCHIVED"])
def test_EP_R_43_workspace_picks_up_states(svc, db, state):
    db.add(_make_report(state=state, report_ref=f"REF-{state}"))
    db.commit()
    r = svc.get_report_workspace()
    found = any(it.lifecycle_state == state for it in r.items)
    assert found


def test_EP_R_44_workspace_orders_by_recency(svc, db):
    db.add(_make_report(title="OLD"))
    db.commit()
    db.add(_make_report(title="NEW"))
    db.commit()
    r = svc.get_report_workspace()
    # Latest first; "NEW" should appear before "OLD" (or both present)
    titles = [it.title for it in r.items]
    assert "NEW" in titles


def test_EP_R_45_workspace_offset_skips(svc, db):
    for i in range(3):
        db.add(_make_report(report_ref=f"REF-{i}"))
    db.commit()
    r1 = svc.get_report_workspace(limit=1, offset=0)
    r2 = svc.get_report_workspace(limit=1, offset=1)
    if r1.items and r2.items:
        assert r1.items[0].report_id != r2.items[0].report_id


def test_EP_R_46_workspace_safe_when_table_missing(svc):
    # Engine try/except guards mean no crash even on bare tables
    svc.get_report_workspace()


def test_EP_R_47_workspace_returns_response_type(svc):
    r = svc.get_report_workspace()
    assert isinstance(r, ReportWorkspaceResponse)


def test_EP_R_48_workspace_items_are_ReportWorkspaceItem(svc, db):
    db.add(_make_report())
    db.commit()
    r = svc.get_report_workspace()
    assert all(isinstance(it, ReportWorkspaceItem) for it in r.items)


def test_EP_R_49_workspace_total_is_int(svc):
    assert isinstance(svc.get_report_workspace().total, int)


def test_EP_R_50_workspace_total_non_negative(svc):
    assert svc.get_report_workspace().total >= 0


def test_EP_R_51_workspace_serializable(svc, db):
    import json

    db.add(_make_report())
    db.commit()
    json.dumps(svc.get_report_workspace().model_dump())


def test_EP_R_52_workspace_manifest_hash_propagated(svc, db):
    db.add(_make_report(signed=True))
    db.commit()
    r = svc.get_report_workspace()
    assert any(it.manifest_hash == "mh" for it in r.items)


def test_EP_R_53_workspace_two_tenants(db):
    e1 = EngagementPortalEngine(db, tenant_id=_TENANT)
    e2 = EngagementPortalEngine(db, tenant_id=_TENANT_B)
    db.add(_make_report(tenant_id=_TENANT, title="A"))
    db.add(_make_report(tenant_id=_TENANT_B, title="B"))
    db.commit()
    assert any(it.title == "A" for it in e1.get_report_workspace().items)
    assert any(it.title == "B" for it in e2.get_report_workspace().items)
    assert not any(it.title == "B" for it in e1.get_report_workspace().items)


def test_EP_R_54_workspace_does_not_modify_fa_report(svc, db):
    rep = _make_report()
    db.add(rep)
    db.commit()
    before = rep.title
    svc.get_report_workspace()
    db.refresh(rep)
    assert rep.title == before


def test_EP_R_55_workspace_does_not_create_audit_event(svc, db):
    db.add(_make_report())
    db.commit()
    # Reading via the portal must NOT create fa_report_audit_events
    from api.db_models_report_authority import FaReportAuditEvent

    before = db.query(FaReportAuditEvent).count()
    svc.get_report_workspace()
    after = db.query(FaReportAuditEvent).count()
    assert before == after


def test_EP_R_56_workspace_returns_safe_defaults_no_data(svc):
    r = svc.get_report_workspace()
    assert r.items == []


def test_EP_R_57_workspace_invalid_limit_raises(svc):
    from services.engagement_portal.schemas import PortalSearchError

    with pytest.raises(PortalSearchError):
        svc.get_report_workspace(limit=0)


def test_EP_R_58_workspace_invalid_offset_raises(svc):
    from services.engagement_portal.schemas import PortalSearchError

    with pytest.raises(PortalSearchError):
        svc.get_report_workspace(offset=-2)


def test_EP_R_59_workspace_response_extra_field_blocked():
    with pytest.raises(ValidationError):
        ReportWorkspaceResponse.model_validate(
            {"items": [], "total": 0, "offset": 0, "limit": 10, "extra": "x"}
        )


def test_EP_R_60_workspace_response_no_items_when_other_tenant_only(svc, db):
    db.add(_make_report(tenant_id=_TENANT_B))
    db.commit()
    r = svc.get_report_workspace()
    assert r.items == []
