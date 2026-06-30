"""Tests for PR 18.2 — Engagement Portal Timeline workspace.

Coverage:
  EP-T-1 to EP-T-50: Timeline engine + API surface
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from services.engagement_portal.engine import EngagementPortalEngine
from services.engagement_portal.schemas import (
    PortalSearchError,
    TimelineEvent,
    TimelineResponse,
)

_TENANT = "tenant-ep-tl-001"
_TENANT_B = "tenant-ep-tl-002"


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


# ------------------------ Engine path ------------------------


def test_EP_T_1_timeline_returns_response(svc):
    assert isinstance(svc.get_timeline(), TimelineResponse)


def test_EP_T_2_timeline_empty_items(svc):
    assert svc.get_timeline().items == []


def test_EP_T_3_timeline_zero_total(svc):
    assert svc.get_timeline().total == 0


def test_EP_T_4_timeline_default_limit(svc):
    assert svc.get_timeline().limit == 50


def test_EP_T_5_timeline_default_offset(svc):
    assert svc.get_timeline().offset == 0


@pytest.mark.parametrize("limit,offset", [(1, 0), (10, 0), (50, 100), (500, 0)])
def test_EP_T_6_timeline_pagination(svc, limit, offset):
    r = svc.get_timeline(limit=limit, offset=offset)
    assert r.limit == limit
    assert r.offset == offset


@pytest.mark.parametrize("limit", [0, -1, 501])
def test_EP_T_7_timeline_invalid_limit_rejected(svc, limit):
    with pytest.raises(PortalSearchError):
        svc.get_timeline(limit=limit)


def test_EP_T_8_timeline_invalid_offset_rejected(svc):
    with pytest.raises(PortalSearchError):
        svc.get_timeline(offset=-1)


def test_EP_T_9_timeline_tenant_isolation(db):
    e1 = EngagementPortalEngine(db, tenant_id=_TENANT)
    e2 = EngagementPortalEngine(db, tenant_id=_TENANT_B)
    assert e1.get_timeline().items == []
    assert e2.get_timeline().items == []


# ------------------------ Schema validation ------------------------


def test_EP_T_10_timeline_event_minimal():
    e = TimelineEvent(
        event_id="e",
        event_type="t",
        source_system="s",
        entity_id=None,
        entity_type=None,
        actor_id=None,
        summary="s",
        occurred_at="2025-01-01T00:00:00Z",
        authoritative_ref=None,
    )
    assert e.event_id == "e"


def test_EP_T_11_timeline_event_extra_forbid():
    with pytest.raises(ValidationError):
        TimelineEvent(
            event_id="e",
            event_type="t",
            source_system="s",
            entity_id=None,
            entity_type=None,
            actor_id=None,
            summary="s",
            occurred_at="x",
            authoritative_ref=None,
            extra="x",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "missing",
    [
        "event_id",
        "event_type",
        "source_system",
        "summary",
        "occurred_at",
    ],
)
def test_EP_T_12_timeline_event_required_fields(missing):
    payload = {
        "event_id": "e",
        "event_type": "t",
        "source_system": "s",
        "entity_id": None,
        "entity_type": None,
        "actor_id": None,
        "summary": "s",
        "occurred_at": "x",
        "authoritative_ref": None,
    }
    payload.pop(missing)
    with pytest.raises(ValidationError):
        TimelineEvent(**payload)


def test_EP_T_13_timeline_response_empty_valid():
    r = TimelineResponse(items=[], total=0, offset=0, limit=10)
    assert r.total == 0


def test_EP_T_14_timeline_response_extra_forbid():
    with pytest.raises(ValidationError):
        TimelineResponse(items=[], total=0, offset=0, limit=10, extra="x")  # type: ignore[call-arg]


@pytest.mark.parametrize("field", ["items", "total", "offset", "limit"])
def test_EP_T_15_timeline_response_required_fields(field):
    payload = {"items": [], "total": 0, "offset": 0, "limit": 10}
    payload.pop(field)
    with pytest.raises(ValidationError):
        TimelineResponse(**payload)


# ------------------------ API ------------------------


def test_EP_T_30_api_timeline_returns_200(ro_client):
    r = ro_client.get("/portal/engagement/timeline")
    assert r.status_code == 200


def test_EP_T_31_api_timeline_returns_empty_list(ro_client):
    body = ro_client.get("/portal/engagement/timeline").json()
    assert body["items"] == []


def test_EP_T_32_api_timeline_default_limit(ro_client):
    body = ro_client.get("/portal/engagement/timeline").json()
    assert body["limit"] == 50


def test_EP_T_33_api_timeline_default_offset(ro_client):
    body = ro_client.get("/portal/engagement/timeline").json()
    assert body["offset"] == 0


def test_EP_T_34_api_timeline_custom_limit(ro_client):
    body = ro_client.get("/portal/engagement/timeline?limit=10").json()
    assert body["limit"] == 10


def test_EP_T_35_api_timeline_invalid_limit(ro_client):
    r = ro_client.get("/portal/engagement/timeline?limit=0")
    assert r.status_code == 422


def test_EP_T_36_api_timeline_invalid_offset(ro_client):
    r = ro_client.get("/portal/engagement/timeline?offset=-1")
    assert r.status_code == 422


def test_EP_T_37_api_timeline_wrong_scope(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/timeline")
    assert r.status_code in (401, 403)


def test_EP_T_38_api_timeline_no_auth(public_client):
    r = public_client.get("/portal/engagement/timeline")
    assert r.status_code in (401, 403)


def test_EP_T_39_api_timeline_post_not_allowed(ro_client):
    r = ro_client.post("/portal/engagement/timeline")
    assert r.status_code == 405


@pytest.mark.parametrize("limit", [1, 10, 50, 500])
def test_EP_T_40_api_timeline_valid_limits(ro_client, limit):
    r = ro_client.get(f"/portal/engagement/timeline?limit={limit}")
    assert r.status_code == 200


@pytest.mark.parametrize("offset", [0, 1, 100, 1000])
def test_EP_T_41_api_timeline_valid_offsets(ro_client, offset):
    r = ro_client.get(f"/portal/engagement/timeline?offset={offset}")
    assert r.status_code == 200


def test_EP_T_42_api_timeline_total_zero(ro_client):
    body = ro_client.get("/portal/engagement/timeline").json()
    assert body["total"] == 0


@pytest.mark.parametrize("field", ["items", "total", "offset", "limit"])
def test_EP_T_43_api_timeline_keys(ro_client, field):
    body = ro_client.get("/portal/engagement/timeline").json()
    assert field in body


def test_EP_T_44_api_timeline_limit_over_max(ro_client):
    r = ro_client.get("/portal/engagement/timeline?limit=501")
    assert r.status_code == 422


def test_EP_T_45_engine_timeline_callable_repeatedly(svc):
    for _ in range(3):
        svc.get_timeline()


def test_EP_T_46_engine_timeline_dump_shape(svc):
    r = svc.get_timeline().model_dump()
    assert set(r.keys()) == {"items", "total", "offset", "limit"}


def test_EP_T_47_engine_timeline_items_list(svc):
    assert isinstance(svc.get_timeline().items, list)


def test_EP_T_48_engine_timeline_total_int(svc):
    assert isinstance(svc.get_timeline().total, int)


def test_EP_T_49_engine_timeline_serializable(svc):
    import json

    json.dumps(svc.get_timeline().model_dump())


def test_EP_T_50_engine_timeline_does_not_raise_for_unknown_tenant(db):
    EngagementPortalEngine(db, tenant_id="never-seen").get_timeline()
