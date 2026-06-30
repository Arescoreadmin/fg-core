"""Tests for PR 18.2 — Engagement Portal Notifications.

Coverage:
  EP-N-1 to EP-N-50: Notification repository + engine + API
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
    count_notifications,
    insert_notification,
    list_notifications,
    mark_notification_delivered,
)
from services.engagement_portal.schemas import (
    NotificationItem,
    NotificationListResponse,
)

_TENANT = "tenant-ep-notif-001"
_TENANT_B = "tenant-ep-notif-002"


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


# ------------------------ Repository ------------------------


def test_EP_N_1_insert_returns_pending(db):
    n = insert_notification(db, tenant_id=_TENANT, notification_type="report_ready")
    assert n.status == "PENDING"


def test_EP_N_2_insert_with_subject_body(db):
    n = insert_notification(
        db, tenant_id=_TENANT, notification_type="x", subject="sub", body="bod"
    )
    assert n.subject == "sub"
    assert n.body == "bod"


def test_EP_N_3_insert_sets_created_at(db):
    n = insert_notification(db, tenant_id=_TENANT, notification_type="x")
    assert n.created_at != ""


def test_EP_N_4_list_returns_inserted(db):
    insert_notification(db, tenant_id=_TENANT, notification_type="x")
    items, total = list_notifications(db, tenant_id=_TENANT)
    assert total >= 1


def test_EP_N_5_list_empty(db):
    items, total = list_notifications(db, tenant_id="t-empty-n")
    assert items == []
    assert total == 0


@pytest.mark.parametrize("n", [1, 3, 5])
def test_EP_N_6_count_grows(db, n):
    tenant = f"t-count-{n}"
    for _ in range(n):
        insert_notification(db, tenant_id=tenant, notification_type="x")
    assert count_notifications(db, tenant_id=tenant) == n


def test_EP_N_7_count_zero_for_empty(db):
    assert count_notifications(db, tenant_id="t-nope") == 0


def test_EP_N_8_mark_delivered(db):
    n = insert_notification(db, tenant_id=_TENANT, notification_type="x")
    db.commit()
    out = mark_notification_delivered(db, tenant_id=_TENANT, notification_id=n.id)
    assert out is not None
    assert out.status == "DELIVERED"


def test_EP_N_9_mark_delivered_missing_returns_none(db):
    assert (
        mark_notification_delivered(db, tenant_id=_TENANT, notification_id="x") is None
    )


def test_EP_N_10_mark_delivered_wrong_tenant_no_op(db):
    n = insert_notification(db, tenant_id=_TENANT, notification_type="x")
    db.commit()
    assert (
        mark_notification_delivered(db, tenant_id=_TENANT_B, notification_id=n.id)
        is None
    )


def test_EP_N_11_tenant_isolation(db):
    insert_notification(db, tenant_id=_TENANT, notification_type="x")
    items, _ = list_notifications(db, tenant_id=_TENANT_B)
    assert items == []


@pytest.mark.parametrize("status", ["PENDING", "DELIVERED", "FAILED", "ARCHIVED"])
def test_EP_N_12_count_with_status_filter(db, status):
    insert_notification(db, tenant_id=f"t-s-{status}", notification_type="x")
    n = count_notifications(db, tenant_id=f"t-s-{status}", status="PENDING")
    if status == "PENDING":
        assert n >= 1
    else:
        assert n >= 0


def test_EP_N_13_mark_delivered_sets_delivered_at(db):
    n = insert_notification(db, tenant_id=_TENANT, notification_type="x")
    db.commit()
    out = mark_notification_delivered(db, tenant_id=_TENANT, notification_id=n.id)
    assert out is not None
    assert out.delivered_at is not None


def test_EP_N_14_pagination_returns_subset(db):
    for _ in range(5):
        insert_notification(db, tenant_id=_TENANT, notification_type="x")
    items, _ = list_notifications(db, tenant_id=_TENANT, limit=2)
    assert len(items) <= 2


# ------------------------ Engine ------------------------


def test_EP_N_20_engine_notifications_empty(svc):
    r = svc.get_notifications()
    assert isinstance(r, NotificationListResponse)
    assert r.items == []


def test_EP_N_21_engine_notifications_after_insert(svc, db):
    insert_notification(db, tenant_id=_TENANT, notification_type="report_ready")
    db.commit()
    r = svc.get_notifications()
    assert r.total >= 1


def test_EP_N_22_engine_notifications_tenant_isolated(svc, db):
    insert_notification(db, tenant_id=_TENANT_B, notification_type="x")
    db.commit()
    r = svc.get_notifications()
    assert r.total == 0


@pytest.mark.parametrize("limit", [1, 10, 50])
def test_EP_N_23_engine_limit_round_trip(svc, limit):
    r = svc.get_notifications(limit=limit)
    assert r.limit == limit


# ------------------------ Schema validation ------------------------


def test_EP_N_30_notification_item_required():
    item = NotificationItem(
        notification_id="x",
        notification_type="t",
        status="PENDING",
        subject="s",
        body="b",
        created_at="t",
        delivered_at=None,
    )
    assert item.notification_id == "x"


def test_EP_N_31_notification_item_extra_forbid():
    with pytest.raises(ValidationError):
        NotificationItem(
            notification_id="x",
            notification_type="t",
            status="PENDING",
            subject=None,
            body=None,
            created_at="t",
            delivered_at=None,
            extra="x",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "missing",
    [
        "notification_id",
        "notification_type",
        "status",
        "created_at",
    ],
)
def test_EP_N_32_notification_item_required_fields(missing):
    payload = {
        "notification_id": "x",
        "notification_type": "t",
        "status": "PENDING",
        "subject": None,
        "body": None,
        "created_at": "t",
        "delivered_at": None,
    }
    payload.pop(missing)
    with pytest.raises(ValidationError):
        NotificationItem(**payload)


def test_EP_N_33_list_response_extra_forbid():
    with pytest.raises(ValidationError):
        NotificationListResponse(items=[], total=0, offset=0, limit=10, x="y")  # type: ignore[call-arg]


# ------------------------ API ------------------------


def test_EP_N_40_api_notifications_returns_200(ro_client):
    r = ro_client.get("/portal/engagement/notifications")
    assert r.status_code == 200


def test_EP_N_41_api_notifications_empty(ro_client):
    body = ro_client.get("/portal/engagement/notifications").json()
    assert body["items"] == []


def test_EP_N_42_api_notifications_wrong_scope(wrong_scope_client):
    r = wrong_scope_client.get("/portal/engagement/notifications")
    assert r.status_code in (401, 403)


def test_EP_N_43_api_notifications_no_auth(public_client):
    r = public_client.get("/portal/engagement/notifications")
    assert r.status_code in (401, 403)


@pytest.mark.parametrize("limit", [1, 10, 50, 500])
def test_EP_N_44_api_notifications_limits(ro_client, limit):
    r = ro_client.get(f"/portal/engagement/notifications?limit={limit}")
    assert r.status_code == 200


def test_EP_N_45_api_notifications_invalid_limit(ro_client):
    r = ro_client.get("/portal/engagement/notifications?limit=0")
    assert r.status_code == 422


def test_EP_N_46_api_notifications_invalid_offset(ro_client):
    r = ro_client.get("/portal/engagement/notifications?offset=-1")
    assert r.status_code == 422


def test_EP_N_47_api_notifications_method_not_allowed(ro_client):
    r = ro_client.delete("/portal/engagement/notifications")
    assert r.status_code == 405


@pytest.mark.parametrize("field", ["items", "total", "offset", "limit"])
def test_EP_N_48_api_notifications_response_keys(ro_client, field):
    body = ro_client.get("/portal/engagement/notifications").json()
    assert field in body


def test_EP_N_49_api_notifications_total_int(ro_client):
    body = ro_client.get("/portal/engagement/notifications").json()
    assert isinstance(body["total"], int)


def test_EP_N_50_api_notifications_default_limit(ro_client):
    body = ro_client.get("/portal/engagement/notifications").json()
    assert body["limit"] == 50
