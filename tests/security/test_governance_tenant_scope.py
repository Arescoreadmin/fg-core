from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.auth_scopes import mint_key
from api.db import get_sessionmaker
from api.db_models import PolicyChangeRequest


def _headers(scope: str, tenant_id: str) -> dict[str, str]:
    return {"X-API-Key": mint_key(scope, tenant_id=tenant_id)}


def test_governance_list_scoped_to_tenant(build_app, monkeypatch):
    monkeypatch.setenv("FG_GOVERNANCE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    create_a = client.post(
        "/governance/changes",
        headers=_headers("governance:write", "tenant-a"),
        json={
            "change_type": "add_rule",
            "proposed_by": "tenant-a-user",
            "justification": "tenant-a-change",
        },
    )
    assert create_a.status_code == 200, create_a.text

    create_b = client.post(
        "/governance/changes",
        headers=_headers("governance:write", "tenant-b"),
        json={
            "change_type": "add_rule",
            "proposed_by": "tenant-b-user",
            "justification": "tenant-b-change",
        },
    )
    assert create_b.status_code == 200, create_b.text

    listed = client.get(
        "/governance/changes",
        headers=_headers("governance:write", "tenant-a"),
    )
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert len(body) == 1
    assert body[0]["proposed_by"] == "tenant-a-user"


def test_governance_create_binds_tenant(build_app, monkeypatch):
    monkeypatch.setenv("FG_GOVERNANCE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    created = client.post(
        "/governance/changes",
        headers=_headers("governance:write", "tenant-a"),
        json={
            "tenant_id": "tenant-b",
            "change_type": "add_rule",
            "proposed_by": "tenant-a-user",
            "justification": "spoof-tenant-in-body",
        },
    )
    assert created.status_code == 200, created.text
    change_id = created.json()["change_id"]

    session = get_sessionmaker()()
    try:
        row = session.execute(
            select(PolicyChangeRequest).where(
                PolicyChangeRequest.change_id == change_id
            )
        ).scalar_one()
        assert row.tenant_id == "tenant-a"
    finally:
        session.close()


def test_governance_approve_cross_tenant_404(build_app, monkeypatch):
    monkeypatch.setenv("FG_GOVERNANCE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    create_b = client.post(
        "/governance/changes",
        headers=_headers("governance:write", "tenant-b"),
        json={
            "change_type": "add_rule",
            "proposed_by": "tenant-b-user",
            "justification": "tenant-b-only",
        },
    )
    assert create_b.status_code == 200, create_b.text
    change_id = create_b.json()["change_id"]

    approve_as_a = client.post(
        f"/governance/changes/{change_id}/approve",
        headers=_headers("governance:write", "tenant-a"),
        json={"approver": "security-lead"},
    )
    assert approve_as_a.status_code == 404


def test_governance_pagination_caps_and_order(build_app, monkeypatch):
    monkeypatch.setenv("FG_GOVERNANCE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    tenant = "tenant-a"
    SessionLocal = get_sessionmaker()
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        for i in range(205):
            db.add(
                PolicyChangeRequest(
                    tenant_id=tenant,
                    change_id=f"pcr-{i:08d}",
                    change_type="add_rule",
                    proposed_by="seed",
                    proposed_at=now + timedelta(seconds=i),
                    justification="seeded",
                    simulation_results_json={},
                    estimated_false_positives=0,
                    estimated_true_positives=0,
                    confidence="medium",
                    requires_approval_from_json=["security-lead", "ciso"],
                    approvals_json=[],
                    status="pending",
                )
            )
        db.commit()

    listed = client.get(
        "/governance/changes?limit=500&offset=0",
        headers=_headers("governance:write", tenant),
    )
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert len(body) == 200
    assert body[0]["change_id"] == "pcr-00000204"
    assert body[1]["change_id"] == "pcr-00000203"

    tail = client.get(
        "/governance/changes?limit=10&offset=200",
        headers=_headers("governance:write", tenant),
    )
    assert tail.status_code == 200, tail.text
    tail_body = tail.json()
    assert len(tail_body) == 5
    assert tail_body[0]["change_id"] == "pcr-00000004"
