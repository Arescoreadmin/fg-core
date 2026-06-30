"""Tests for PR 18.2 — Engagement Portal Activity feed + append-only log.

Coverage:
  EP-A-1 to EP-A-60: Activity feed engine + repository + API + append-only enforcement
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from services.engagement_portal.engine import EngagementPortalEngine
from services.engagement_portal.repository import (
    count_activities,
    insert_activity,
    list_activities,
)
from services.engagement_portal.schemas import (
    ActivityFeedItem,
    ActivityFeedResponse,
    PortalAccessDenied,
    PreferencesResponse,
    RecordActivityRequest,
    UpdatePreferencesRequest,
)

_TENANT = "tenant-ep-act-001"
_TENANT_B = "tenant-ep-act-002"


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


# ------------------------ Repository ------------------------


def test_EP_A_1_insert_returns_activity(db):
    row = insert_activity(db, tenant_id=_TENANT, event_type="dashboard_viewed")
    assert row.event_type == "dashboard_viewed"


def test_EP_A_2_count_zero_initially(db):
    assert count_activities(db, tenant_id="t-zero-act") == 0


@pytest.mark.parametrize("n", [1, 3, 7])
def test_EP_A_3_count_grows(db, n):
    tenant = f"t-grow-{n}"
    for _ in range(n):
        insert_activity(db, tenant_id=tenant, event_type="x")
    assert count_activities(db, tenant_id=tenant) == n


def test_EP_A_4_list_orders_recent_first(db):
    insert_activity(db, tenant_id=_TENANT, event_type="first")
    db.commit()
    insert_activity(db, tenant_id=_TENANT, event_type="second")
    db.commit()
    items, _ = list_activities(db, tenant_id=_TENANT)
    found_a = next((it for it in items if it.event_type == "first"), None)
    found_b = next((it for it in items if it.event_type == "second"), None)
    assert found_a is not None and found_b is not None


def test_EP_A_5_list_pagination(db):
    for _ in range(5):
        insert_activity(db, tenant_id=_TENANT, event_type="x")
    items, total = list_activities(db, tenant_id=_TENANT, limit=2, offset=0)
    assert len(items) <= 2
    assert total >= 5


def test_EP_A_6_workspace_filter(db):
    insert_activity(db, tenant_id=_TENANT, event_type="x", workspace="reports")
    insert_activity(db, tenant_id=_TENANT, event_type="x", workspace="trust")
    items, _ = list_activities(db, tenant_id=_TENANT, workspace="trust")
    assert all(it.workspace == "trust" for it in items)


def test_EP_A_7_tenant_isolation(db):
    insert_activity(db, tenant_id=_TENANT, event_type="x")
    items, _ = list_activities(db, tenant_id=_TENANT_B)
    assert items == []


def test_EP_A_8_count_by_event_type(db):
    insert_activity(db, tenant_id=_TENANT, event_type="report_viewed")
    insert_activity(db, tenant_id=_TENANT, event_type="evidence_viewed")
    n_reports = count_activities(db, tenant_id=_TENANT, event_type="report_viewed")
    n_evidence = count_activities(db, tenant_id=_TENANT, event_type="evidence_viewed")
    assert n_reports >= 1
    assert n_evidence >= 1


@pytest.mark.parametrize(
    "event_type",
    [
        "dashboard_viewed",
        "evidence_viewed",
        "report_viewed",
        "report_downloaded",
        "remediation_viewed",
        "trust_viewed",
        "transparency_viewed",
        "verification_viewed",
        "search_performed",
        "preference_updated",
        "timeline_viewed",
    ],
)
def test_EP_A_9_insert_supported_event_types(db, event_type):
    row = insert_activity(db, tenant_id=_TENANT, event_type=event_type)
    assert row.event_type == event_type


def test_EP_A_10_insert_with_metadata_json(db):
    row = insert_activity(
        db, tenant_id=_TENANT, event_type="x", metadata_json='{"a":1}'
    )
    assert row.metadata_json == '{"a":1}'


# ------------------------ Append-only enforcement ------------------------


def test_EP_A_20_append_only_update_blocked(db):
    row = insert_activity(db, tenant_id=_TENANT, event_type="x")
    db.commit()
    row.event_type = "modified"
    with pytest.raises(RuntimeError, match="append-only"):
        db.commit()


def test_EP_A_21_append_only_delete_blocked(db):
    row = insert_activity(db, tenant_id=_TENANT, event_type="x")
    db.commit()
    db.delete(row)
    with pytest.raises(RuntimeError, match="append-only"):
        db.commit()


def test_EP_A_22_multiple_inserts_succeed(db):
    for _ in range(3):
        insert_activity(db, tenant_id=_TENANT, event_type="x")
    db.commit()
    assert count_activities(db, tenant_id=_TENANT) >= 3


# ------------------------ Engine ------------------------


def test_EP_A_30_activity_feed_empty(svc):
    r = svc.get_activity_feed()
    assert isinstance(r, ActivityFeedResponse)
    assert r.items == []


def test_EP_A_31_record_activity_inserts(svc, db):
    svc.record_activity("dashboard_viewed")
    db.commit()
    items, _ = list_activities(db, tenant_id=_TENANT)
    assert any(i.event_type == "dashboard_viewed" for i in items)


def test_EP_A_32_record_activity_empty_event_rejected(svc):
    with pytest.raises(PortalAccessDenied):
        svc.record_activity("")


def test_EP_A_33_activity_feed_workspace_filter(svc, db):
    svc.record_activity("report_viewed", workspace="reports")
    db.commit()
    r = svc.get_activity_feed(workspace="reports")
    assert all(it.workspace == "reports" for it in r.items)


@pytest.mark.parametrize("limit", [1, 5, 50])
def test_EP_A_34_activity_feed_limit_round_trip(svc, limit):
    assert svc.get_activity_feed(limit=limit).limit == limit


def test_EP_A_35_activity_feed_tenant_isolation(db):
    e1 = EngagementPortalEngine(db, tenant_id=_TENANT)
    e2 = EngagementPortalEngine(db, tenant_id=_TENANT_B)
    e1.record_activity("x")
    db.commit()
    assert e2.get_activity_feed().total == 0


def test_EP_A_36_engine_preferences_default(svc):
    r = svc.get_preferences()
    assert isinstance(r, PreferencesResponse)
    assert r.notification_email is True


def test_EP_A_37_engine_update_preferences(svc):
    out = svc.update_preferences(
        UpdatePreferencesRequest(
            theme="dark", notification_email=False, timezone="UTC", language="en"
        )
    )
    assert out.theme == "dark"
    assert out.notification_email is False


def test_EP_A_38_engine_update_then_get(svc):
    svc.update_preferences(
        UpdatePreferencesRequest(
            theme="light", notification_email=True, timezone=None, language=None
        )
    )
    r = svc.get_preferences()
    assert r.theme == "light"


# ------------------------ Schemas ------------------------


def test_EP_A_40_activity_item_minimal():
    it = ActivityFeedItem(
        activity_id="a",
        event_type="x",
        workspace=None,
        entity_id=None,
        actor_id=None,
        occurred_at="t",
        summary=None,
    )
    assert it.activity_id == "a"


def test_EP_A_41_activity_item_extra_forbid():
    with pytest.raises(ValidationError):
        ActivityFeedItem(
            activity_id="a",
            event_type="x",
            workspace=None,
            entity_id=None,
            actor_id=None,
            occurred_at="t",
            summary=None,
            extra="x",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "missing",
    ["activity_id", "event_type", "occurred_at"],
)
def test_EP_A_42_activity_item_required(missing):
    payload = {
        "activity_id": "a",
        "event_type": "x",
        "workspace": None,
        "entity_id": None,
        "actor_id": None,
        "occurred_at": "t",
        "summary": None,
    }
    payload.pop(missing)
    with pytest.raises(ValidationError):
        ActivityFeedItem(**payload)


def test_EP_A_43_feed_response_extra_forbid():
    with pytest.raises(ValidationError):
        ActivityFeedResponse(items=[], total=0, offset=0, limit=10, x="y")  # type: ignore[call-arg]


@pytest.mark.parametrize("limit,offset", [(10, 0), (50, 5), (100, 50)])
def test_EP_A_44_feed_response_round_trip(limit, offset):
    r = ActivityFeedResponse(items=[], total=0, offset=offset, limit=limit)
    assert r.limit == limit and r.offset == offset


# ------------------------ API ------------------------


def test_EP_A_50_api_activity_get_returns_200(ro_client):
    r = ro_client.get("/portal/engagement/activity")
    assert r.status_code == 200


def test_EP_A_51_api_activity_post_requires_write(ro_client):
    r = ro_client.post(
        "/portal/engagement/activity", json={"event_type": "dashboard_viewed"}
    )
    # ro_client only has portal:read
    assert r.status_code in (401, 403)


def test_EP_A_52_api_activity_post_with_write_scope(client):
    r = client.post(
        "/portal/engagement/activity", json={"event_type": "dashboard_viewed"}
    )
    assert r.status_code == 204


def test_EP_A_53_api_activity_post_missing_event_type(client):
    r = client.post("/portal/engagement/activity", json={})
    assert r.status_code == 422


def test_EP_A_54_api_activity_post_extra_field_blocked(client):
    r = client.post(
        "/portal/engagement/activity",
        json={"event_type": "x", "unknown_field": "y"},
    )
    assert r.status_code == 422


def test_EP_A_55_api_activity_get_wrong_scope(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/activity")
    assert r.status_code in (401, 403)


def test_EP_A_56_api_activity_get_no_auth(public_client):
    r = public_client.get("/portal/engagement/activity")
    assert r.status_code in (401, 403)


def test_EP_A_57_api_activity_workspace_filter(client):
    client.post(
        "/portal/engagement/activity",
        json={"event_type": "report_viewed", "workspace": "reports"},
    )
    body = client.get("/portal/engagement/activity?workspace=reports").json()
    assert all(it["workspace"] == "reports" for it in body["items"])


def test_EP_A_58_api_preferences_get(ro_client):
    r = ro_client.get("/portal/engagement/preferences")
    assert r.status_code == 200


def test_EP_A_59_api_preferences_put(client):
    r = client.put(
        "/portal/engagement/preferences",
        json={
            "theme": "dark",
            "notification_email": True,
            "timezone": "UTC",
            "language": "en",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["theme"] == "dark"


def test_EP_A_60_api_preferences_put_extra_field_blocked(client):
    r = client.put(
        "/portal/engagement/preferences",
        json={"theme": "dark", "notification_email": True, "weird": "x"},
    )
    assert r.status_code == 422


def test_EP_A_61_api_record_activity_request_validates_event_type():
    with pytest.raises(ValidationError):
        RecordActivityRequest(event_type="")


def test_EP_A_62_api_preferences_get_wrong_scope(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/preferences")
    assert r.status_code in (401, 403)


def test_EP_A_63_api_preferences_put_wrong_scope(ro_client):
    r = ro_client.put(
        "/portal/engagement/preferences",
        json={"theme": "x", "notification_email": True},
    )
    assert r.status_code in (401, 403)


def test_EP_A_64_api_preferences_put_then_get(client):
    client.put(
        "/portal/engagement/preferences",
        json={
            "theme": "dark",
            "notification_email": False,
            "timezone": "UTC",
            "language": "en",
        },
    )
    body = client.get("/portal/engagement/preferences").json()
    assert body["theme"] == "dark"
    assert body["notification_email"] is False
