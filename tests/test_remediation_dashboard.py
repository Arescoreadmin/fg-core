"""Tests for PR 18.3 — Remediation Authority dashboard, risk, search, health."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.models import (
    RemediationPriority,
    RemediationTaskState,
)
from services.remediation_authority.schemas import (
    CreateTaskRequest,
    DashboardResponse,
    HealthResponse,
    RiskResponse,
    SearchResponse,
    TransitionTaskRequest,
)


_TENANT = "tenant-ra-dash-001"


# ---------------------------------------------------------------------------
# Engine-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return RemediationAuthorityEngine(db, tenant_id=_TENANT)


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("remediation:read", "remediation:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def ro_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("remediation:read", tenant_id=_TENANT)
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


# ---------------------------------------------------------------------------
# Engine-level dashboard
# ---------------------------------------------------------------------------


def test_RA_DB_1_dashboard_returns_dashboard_response(svc):
    assert isinstance(svc.get_dashboard(), DashboardResponse)


def test_RA_DB_2_dashboard_open_tasks_zero(svc):
    assert svc.get_dashboard().open_tasks == 0


def test_RA_DB_3_dashboard_open_tasks_counted(svc, db):
    for _ in range(3):
        svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.get_dashboard()
    assert r.open_tasks == 3


def test_RA_DB_4_dashboard_in_progress_counted(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    r = svc.get_dashboard()
    assert r.in_progress_tasks >= 1


def test_RA_DB_5_dashboard_blocked_counted(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.BLOCKED),
        actor_id="u",
    )
    db.commit()
    r = svc.get_dashboard()
    assert r.blocked_tasks >= 1


def test_RA_DB_6_dashboard_upcoming_deadlines_limited(svc, db):
    for i in range(10):
        svc.create_task(
            CreateTaskRequest(title=f"T-{i}", target_date="2099-12-31T00:00:00Z"),
            actor_id="u",
        )
    db.commit()
    r = svc.get_dashboard()
    assert len(r.upcoming_deadlines) <= 5


def test_RA_DB_7_dashboard_priority_breakdown(svc, db):
    for p in list(RemediationPriority):
        svc.create_task(
            CreateTaskRequest(title=f"T-{p.value}", priority=p), actor_id="u"
        )
    db.commit()
    r = svc.get_dashboard()
    for p in list(RemediationPriority):
        assert r.priority_breakdown.get(p.value, 0) >= 1


def test_RA_DB_8_dashboard_breached_sla(svc, db):
    svc.create_task(
        CreateTaskRequest(title="T", target_date="2000-01-01T00:00:00Z"),
        actor_id="u",
    )
    db.commit()
    r = svc.get_dashboard()
    assert r.breached_sla >= 1


# ---------------------------------------------------------------------------
# Engine-level search + risk + health
# ---------------------------------------------------------------------------


def test_RA_DB_9_search_returns_response(svc, db):
    svc.create_task(CreateTaskRequest(title="hello world"), actor_id="u")
    db.commit()
    r = svc.search_tasks("hello")
    assert isinstance(r, SearchResponse)
    assert r.total >= 1


def test_RA_DB_10_search_no_match(svc):
    r = svc.search_tasks("no-such-widget")
    assert r.total == 0


def test_RA_DB_11_search_case_insensitive(svc, db):
    svc.create_task(CreateTaskRequest(title="Widget"), actor_id="u")
    db.commit()
    r = svc.search_tasks("widget")
    assert r.total >= 1


def test_RA_DB_12_risk_returns_response(svc):
    assert isinstance(svc.get_risk(), RiskResponse)


def test_RA_DB_13_risk_totals_zero_when_no_scores(svc):
    r = svc.get_risk()
    assert r.total_risk_score == 0.0


def test_RA_DB_14_risk_totals_positive_with_scores(svc, db):
    svc.create_task(CreateTaskRequest(title="T", risk_score=0.5), actor_id="u")
    db.commit()
    assert svc.get_risk().total_risk_score >= 0.5


def test_RA_DB_15_health_returns_response(svc):
    assert isinstance(svc.health(), HealthResponse)


def test_RA_DB_16_health_ok(svc):
    assert svc.health().status == "ok"


def test_RA_DB_17_health_authority_name(svc):
    assert svc.health().authority == "remediation_authority"


# ---------------------------------------------------------------------------
# API surface tests
# ---------------------------------------------------------------------------


def test_RA_DB_18_health_public(public_client):
    r = public_client.get("/remediation-authority/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_RA_DB_19_health_no_auth_needed(public_client):
    r = public_client.get("/remediation-authority/health")
    assert r.status_code == 200


def test_RA_DB_20_dashboard_requires_scope(wrong_scope_client):
    r = wrong_scope_client.get("/remediation-authority/dashboard")
    assert r.status_code in (401, 403)


def test_RA_DB_21_dashboard_with_read_scope(ro_client):
    r = ro_client.get("/remediation-authority/dashboard")
    assert r.status_code == 200


def test_RA_DB_22_statistics_with_read_scope(ro_client):
    r = ro_client.get("/remediation-authority/statistics")
    assert r.status_code == 200


def test_RA_DB_23_forecast_with_read_scope(ro_client):
    r = ro_client.get("/remediation-authority/forecast")
    assert r.status_code == 200


def test_RA_DB_24_risk_with_read_scope(ro_client):
    r = ro_client.get("/remediation-authority/risk")
    assert r.status_code == 200


def test_RA_DB_25_search_requires_query(ro_client):
    r = ro_client.get("/remediation-authority/search")
    assert r.status_code == 422


def test_RA_DB_26_search_with_query(ro_client):
    r = ro_client.get("/remediation-authority/search?q=widget")
    assert r.status_code == 200


def test_RA_DB_27_plans_list_requires_scope(wrong_scope_client):
    r = wrong_scope_client.get("/remediation-authority/plans")
    assert r.status_code in (401, 403)


def test_RA_DB_28_plans_create_requires_write_scope(ro_client):
    r = ro_client.post("/remediation-authority/plans", json={"title": "P"})
    assert r.status_code in (401, 403)


def test_RA_DB_29_plans_create_with_write_scope(client):
    r = client.post("/remediation-authority/plans", json={"title": "P"})
    assert r.status_code == 201


def test_RA_DB_30_plan_get_after_create(client):
    r = client.post("/remediation-authority/plans", json={"title": "P"})
    assert r.status_code == 201
    plan_id = r.json()["id"]
    r2 = client.get(f"/remediation-authority/plans/{plan_id}")
    assert r2.status_code == 200


def test_RA_DB_31_plan_get_missing_404(client):
    r = client.get("/remediation-authority/plans/missing")
    assert r.status_code == 404


def test_RA_DB_32_plan_patch(client):
    r = client.post("/remediation-authority/plans", json={"title": "P"})
    pid = r.json()["id"]
    r2 = client.patch(
        f"/remediation-authority/plans/{pid}",
        json={"title": "P2"},
    )
    assert r2.status_code == 200
    assert r2.json()["title"] == "P2"


def test_RA_DB_33_tasks_create_requires_write_scope(ro_client):
    r = ro_client.post("/remediation-authority/tasks", json={"title": "T"})
    assert r.status_code in (401, 403)


def test_RA_DB_34_tasks_create_with_write_scope(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    assert r.status_code == 201


def test_RA_DB_35_task_get_missing_404(client):
    r = client.get("/remediation-authority/tasks/missing")
    assert r.status_code == 404


def test_RA_DB_36_task_patch(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.patch(f"/remediation-authority/tasks/{tid}", json={"title": "T2"})
    assert r2.status_code == 200


def test_RA_DB_37_task_transition(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.post(
        f"/remediation-authority/tasks/{tid}/transition",
        json={"to_state": "IN_PROGRESS"},
    )
    assert r2.status_code == 200
    assert r2.json()["task_state"] == "IN_PROGRESS"


def test_RA_DB_38_task_transition_invalid(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.post(
        f"/remediation-authority/tasks/{tid}/transition",
        json={"to_state": "COMPLETED"},
    )
    assert r2.status_code == 409


def test_RA_DB_39_task_timeline(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.get(f"/remediation-authority/tasks/{tid}/timeline")
    assert r2.status_code == 200
    assert r2.json()["total"] >= 1


def test_RA_DB_40_task_history(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.get(f"/remediation-authority/tasks/{tid}/history")
    assert r2.status_code == 200


def test_RA_DB_41_create_assignment(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.post(
        "/remediation-authority/assignments",
        json={"task_id": tid, "actor_id": "alice", "role": "OWNER"},
    )
    assert r2.status_code == 201


def test_RA_DB_42_list_assignments(ro_client):
    r = ro_client.get("/remediation-authority/assignments")
    assert r.status_code == 200


def test_RA_DB_43_create_dependency(client):
    t1 = client.post("/remediation-authority/tasks", json={"title": "T1"}).json()["id"]
    t2 = client.post("/remediation-authority/tasks", json={"title": "T2"}).json()["id"]
    r = client.post(
        "/remediation-authority/dependencies",
        json={"source_task_id": t1, "target_task_id": t2},
    )
    assert r.status_code == 201


def test_RA_DB_44_list_dependencies(ro_client):
    r = ro_client.get("/remediation-authority/dependencies")
    assert r.status_code == 200


def test_RA_DB_45_delete_dependency(client):
    t1 = client.post("/remediation-authority/tasks", json={"title": "T1"}).json()["id"]
    t2 = client.post("/remediation-authority/tasks", json={"title": "T2"}).json()["id"]
    dep_id = client.post(
        "/remediation-authority/dependencies",
        json={"source_task_id": t1, "target_task_id": t2},
    ).json()["id"]
    r = client.delete(f"/remediation-authority/dependencies/{dep_id}")
    assert r.status_code == 204


def test_RA_DB_46_create_verification(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.post(
        "/remediation-authority/verification",
        json={"task_id": tid, "verifier_id": "v"},
    )
    assert r2.status_code == 201


def test_RA_DB_47_list_verifications(ro_client):
    r = ro_client.get("/remediation-authority/verification")
    assert r.status_code == 200


def test_RA_DB_48_dashboard_shape_via_api(ro_client):
    r = ro_client.get("/remediation-authority/dashboard")
    body = r.json()
    assert "open_tasks" in body
    assert "priority_breakdown" in body


def test_RA_DB_49_statistics_shape_via_api(ro_client):
    r = ro_client.get("/remediation-authority/statistics")
    body = r.json()
    assert "total_tasks" in body


def test_RA_DB_50_forecast_shape_via_api(ro_client):
    r = ro_client.get("/remediation-authority/forecast?horizon_days=30")
    body = r.json()
    assert body["horizon_days"] == 30


def test_RA_DB_51_risk_shape_via_api(ro_client):
    r = ro_client.get("/remediation-authority/risk")
    body = r.json()
    assert 0 <= body["risk_reduction_pct"] <= 100


def test_RA_DB_52_search_shape_via_api(ro_client):
    r = ro_client.get("/remediation-authority/search?q=widget")
    body = r.json()
    assert "items" in body


def test_RA_DB_53_plans_list_via_api(ro_client):
    r = ro_client.get("/remediation-authority/plans")
    assert r.status_code == 200
    assert "items" in r.json()


def test_RA_DB_54_tasks_list_via_api(ro_client):
    r = ro_client.get("/remediation-authority/tasks")
    assert r.status_code == 200


def test_RA_DB_55_task_list_pagination(ro_client, client, db):
    for i in range(3):
        client.post("/remediation-authority/tasks", json={"title": f"T-{i}"})
    r = ro_client.get("/remediation-authority/tasks?limit=2&offset=0")
    assert r.status_code == 200
    assert len(r.json()["items"]) <= 2


def test_RA_DB_56_task_get_via_api(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.get(f"/remediation-authority/tasks/{tid}")
    assert r2.status_code == 200


def test_RA_DB_57_task_search_returns_matching(client, ro_client):
    client.post("/remediation-authority/tasks", json={"title": "widget review"})
    r = ro_client.get("/remediation-authority/search?q=widget")
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_RA_DB_58_task_transition_missing_state_422(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T"})
    tid = r.json()["id"]
    r2 = client.post(f"/remediation-authority/tasks/{tid}/transition", json={})
    assert r2.status_code == 422


def test_RA_DB_59_plans_create_extra_forbid(client):
    r = client.post("/remediation-authority/plans", json={"title": "P", "extra": "x"})
    assert r.status_code == 422


def test_RA_DB_60_task_create_extra_forbid(client):
    r = client.post("/remediation-authority/tasks", json={"title": "T", "extra": "x"})
    assert r.status_code == 422


def test_RA_DB_61_task_target_date_recomputes_sla(client):
    r = client.post(
        "/remediation-authority/tasks",
        json={"title": "T", "target_date": "2099-12-31T00:00:00Z"},
    )
    assert r.status_code == 201
    assert r.json()["sla_status"] in ("ON_TRACK", "AT_RISK")


def test_RA_DB_62_task_owner_id_persisted(client):
    r = client.post(
        "/remediation-authority/tasks",
        json={"title": "T", "owner_id": "alice"},
    )
    assert r.status_code == 201
    assert r.json()["owner_id"] == "alice"


def test_RA_DB_63_task_priority_set(client):
    r = client.post(
        "/remediation-authority/tasks", json={"title": "T", "priority": "CRITICAL"}
    )
    assert r.status_code == 201
    assert r.json()["priority"] == "CRITICAL"


def test_RA_DB_64_public_health_via_client(client):
    r = client.get("/remediation-authority/health")
    assert r.status_code == 200


def test_RA_DB_65_missing_scope_returns_403_or_401(wrong_scope_client):
    r = wrong_scope_client.get("/remediation-authority/tasks")
    assert r.status_code in (401, 403)


@pytest.mark.parametrize("i", range(1, 21))
def test_RA_DB_66_bulk_task_create_via_api(client, i):
    r = client.post("/remediation-authority/tasks", json={"title": f"BT-{i}"})
    assert r.status_code == 201


@pytest.mark.parametrize("i", range(1, 21))
def test_RA_DB_67_bulk_plan_create_via_api(client, i):
    r = client.post("/remediation-authority/plans", json={"title": f"BP-{i}"})
    assert r.status_code == 201
