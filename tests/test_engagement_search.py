"""Tests for PR 18.2 — Engagement Portal Search.

Coverage:
  EP-S-1 to EP-S-60: Search engine + API
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
    PortalSearchError,
    SearchRequest,
    SearchResponse,
    SearchResultItem,
)

_TENANT = "tenant-ep-srch-001"
_TENANT_B = "tenant-ep-srch-002"


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _make_report(
    tenant_id: str = _TENANT, *, title: str = "Quarterly Audit", report_ref: str = "REF"
) -> FaReport:
    return FaReport(
        id=uuid.uuid4().hex[:16],
        tenant_id=tenant_id,
        report_ref=report_ref,
        report_type="EXECUTIVE",
        lifecycle_state="DRAFT",
        schema_version="1.0",
        title=title,
        report_version="1.0.0-r0",
        major_version=1,
        minor_version=0,
        patch_version=0,
        report_revision=0,
        has_pdf=0,
        has_html=0,
        has_json=0,
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


def test_EP_S_1_empty_query_rejected(svc):
    with pytest.raises(PortalSearchError):
        svc.search("")


def test_EP_S_2_whitespace_query_rejected(svc):
    with pytest.raises(PortalSearchError):
        svc.search("   ")


def test_EP_S_3_too_long_query_rejected(svc):
    with pytest.raises(PortalSearchError):
        svc.search("x" * 513)


def test_EP_S_4_no_matches_returns_empty(svc):
    r = svc.search("never-existing-zz-001")
    assert r.total == 0
    assert r.items == []


def test_EP_S_5_match_on_title(svc, db):
    db.add(_make_report(title="Quarterly Audit"))
    db.commit()
    r = svc.search("Quarterly")
    assert r.total >= 1


def test_EP_S_6_match_on_report_ref(svc, db):
    db.add(_make_report(report_ref="AUDIT-REF-2026"))
    db.commit()
    r = svc.search("AUDIT-REF")
    assert r.total >= 1


def test_EP_S_7_case_insensitive_match(svc, db):
    db.add(_make_report(title="Compliance Review"))
    db.commit()
    r = svc.search("compliance")
    assert r.total >= 1


def test_EP_S_8_no_cross_tenant_match(svc, db):
    db.add(_make_report(tenant_id=_TENANT_B, title="SECRET"))
    db.commit()
    r = svc.search("SECRET")
    assert r.total == 0


def test_EP_S_9_result_items_have_type_report(svc, db):
    db.add(_make_report(title="Test Search Hit"))
    db.commit()
    r = svc.search("Search Hit")
    assert all(it.result_type == "report" for it in r.items)


def test_EP_S_10_search_records_took_ms(svc):
    r = svc.search("anything")
    assert r.took_ms is not None and r.took_ms >= 0


def test_EP_S_11_query_echoed_in_response(svc):
    r = svc.search("hello world")
    assert r.query == "hello world"


@pytest.mark.parametrize("limit", [1, 5, 10, 50])
def test_EP_S_12_search_limit_round_trip(svc, db, limit):
    for i in range(20):
        db.add(_make_report(title=f"Report {i}"))
    db.commit()
    r = svc.search("Report", limit=limit)
    assert len(r.items) <= limit


def test_EP_S_13_search_pagination(svc, db):
    for i in range(5):
        db.add(_make_report(title=f"R{i}", report_ref=f"REF-{i}"))
    db.commit()
    r1 = svc.search("R", limit=2, offset=0)
    r2 = svc.search("R", limit=2, offset=2)
    if r1.items and r2.items:
        assert r1.items[0].result_id != r2.items[0].result_id


def test_EP_S_14_search_invalid_limit(svc):
    with pytest.raises(PortalSearchError):
        svc.search("q", limit=0)


def test_EP_S_15_search_invalid_offset(svc):
    with pytest.raises(PortalSearchError):
        svc.search("q", offset=-1)


def test_EP_S_16_search_result_has_score(svc, db):
    db.add(_make_report(title="hit"))
    db.commit()
    r = svc.search("hit")
    for it in r.items:
        assert it.score is not None


def test_EP_S_17_search_result_has_ref(svc, db):
    db.add(_make_report(title="alpha", report_ref="REF-A"))
    db.commit()
    r = svc.search("alpha")
    assert any(it.ref == "REF-A" for it in r.items)


def test_EP_S_18_search_result_matched_field_is_title(svc, db):
    db.add(_make_report(title="matched"))
    db.commit()
    r = svc.search("matched")
    assert all(it.matched_field == "title" for it in r.items)


# ------------------------ Schemas ------------------------


def test_EP_S_30_search_request_min_length():
    with pytest.raises(ValidationError):
        SearchRequest(query="")


def test_EP_S_31_search_request_max_length():
    with pytest.raises(ValidationError):
        SearchRequest(query="x" * 513)


def test_EP_S_32_search_request_default_pagination():
    req = SearchRequest(query="q")
    assert req.limit == 50
    assert req.offset == 0


def test_EP_S_33_search_request_extra_forbid():
    with pytest.raises(ValidationError):
        SearchRequest(query="q", unknown="x")  # type: ignore[call-arg]


def test_EP_S_34_search_response_extra_forbid():
    with pytest.raises(ValidationError):
        SearchResponse(query="q", items=[], total=0, took_ms=1, x="y")  # type: ignore[call-arg]


def test_EP_S_35_search_result_item_extra_forbid():
    with pytest.raises(ValidationError):
        SearchResultItem(
            result_id="r",
            result_type="report",
            title=None,
            ref=None,
            matched_field=None,
            score=None,
            extra="x",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize("missing", ["result_id", "result_type"])
def test_EP_S_36_search_result_item_required(missing):
    payload = {
        "result_id": "r",
        "result_type": "report",
        "title": None,
        "ref": None,
        "matched_field": None,
        "score": None,
    }
    payload.pop(missing)
    with pytest.raises(ValidationError):
        SearchResultItem(**payload)


# ------------------------ API ------------------------


def test_EP_S_40_api_search_requires_q(ro_client):
    r = ro_client.get("/portal/engagement/search")
    assert r.status_code == 422


def test_EP_S_41_api_search_returns_200_with_q(ro_client):
    r = ro_client.get("/portal/engagement/search?q=hello")
    assert r.status_code == 200


def test_EP_S_42_api_search_empty_q_rejected(ro_client):
    r = ro_client.get("/portal/engagement/search?q=")
    assert r.status_code == 422


def test_EP_S_43_api_search_no_match_total_zero(ro_client):
    body = ro_client.get("/portal/engagement/search?q=zzzz-no-match").json()
    assert body["total"] == 0


def test_EP_S_44_api_search_wrong_scope(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/search?q=x")
    assert r.status_code in (401, 403)


def test_EP_S_45_api_search_no_auth(public_client):
    r = public_client.get("/portal/engagement/search?q=x")
    assert r.status_code in (401, 403)


def test_EP_S_46_api_search_method_not_allowed(ro_client):
    r = ro_client.post("/portal/engagement/search")
    assert r.status_code == 405


def test_EP_S_47_api_search_limit_too_high(ro_client):
    r = ro_client.get("/portal/engagement/search?q=x&limit=501")
    assert r.status_code == 422


def test_EP_S_48_api_search_invalid_offset(ro_client):
    r = ro_client.get("/portal/engagement/search?q=x&offset=-1")
    assert r.status_code == 422


@pytest.mark.parametrize("limit", [1, 50, 500])
def test_EP_S_49_api_search_valid_limits(ro_client, limit):
    r = ro_client.get(f"/portal/engagement/search?q=x&limit={limit}")
    assert r.status_code == 200


@pytest.mark.parametrize("offset", [0, 10, 100])
def test_EP_S_50_api_search_valid_offsets(ro_client, offset):
    r = ro_client.get(f"/portal/engagement/search?q=x&offset={offset}")
    assert r.status_code == 200


def test_EP_S_51_api_search_q_echoed(ro_client):
    body = ro_client.get("/portal/engagement/search?q=alpha").json()
    assert body["query"] == "alpha"


def test_EP_S_52_api_search_keys(ro_client):
    body = ro_client.get("/portal/engagement/search?q=x").json()
    for field in ("query", "items", "total", "took_ms"):
        assert field in body


def test_EP_S_53_search_items_empty_when_no_match(svc):
    assert svc.search("nope-xyz").items == []


def test_EP_S_54_search_max_length_query_accepted(svc):
    r = svc.search("x" * 512)
    assert r.query.startswith("x")


def test_EP_S_55_search_strips_whitespace(svc, db):
    db.add(_make_report(title="HelloWorld"))
    db.commit()
    r = svc.search("  HelloWorld  ")
    assert r.total >= 1


def test_EP_S_56_search_tenant_isolated_when_data_present(db):
    e1 = EngagementPortalEngine(db, tenant_id=_TENANT)
    e2 = EngagementPortalEngine(db, tenant_id=_TENANT_B)
    db.add(_make_report(tenant_id=_TENANT, title="mine"))
    db.add(_make_report(tenant_id=_TENANT_B, title="yours"))
    db.commit()
    assert e1.search("mine").total >= 1
    assert e1.search("yours").total == 0
    assert e2.search("yours").total >= 1


def test_EP_S_57_search_result_id_string(svc, db):
    db.add(_make_report(title="strid"))
    db.commit()
    r = svc.search("strid")
    for it in r.items:
        assert isinstance(it.result_id, str)


def test_EP_S_58_search_no_side_effect_on_db(svc, db):
    db.add(_make_report(title="audited"))
    db.commit()
    n_before = db.query(FaReport).count()
    svc.search("audited")
    n_after = db.query(FaReport).count()
    assert n_before == n_after


def test_EP_S_59_search_serializable(svc):
    import json

    json.dumps(svc.search("anything").model_dump())


def test_EP_S_60_search_query_round_trip_unicode(svc):
    r = svc.search("café")
    assert r.query == "café"
