"""REPORT-QA-001 proof: exact-version, canonical reviewer QA evidence."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault(
    "FG_REPORT_SIGNING_KEY",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2",
)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

TENANT = "tenant-report-qa-001"


@pytest.fixture()
def client(build_app):
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)
    key = mint_key(
        "governance:read", "governance:write", "governance:qa_approve", tenant_id=TENANT
    )
    return TestClient(app, headers={"X-API-Key": key})


def _setup(client: TestClient) -> tuple[str, str, dict]:
    engagement = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "QA Proof Corp",
            "assessor_id": "assessor-001",
            "assessment_type": "ai_governance",
        },
    )
    assert engagement.status_code == 201, engagement.text
    eid = engagement.json()["id"]
    report = client.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert report.status_code == 201, report.text
    rid = report.json()["report_id"]
    version = client.post(f"/field-assessment/engagements/{eid}/reports/{rid}/versions")
    assert version.status_code == 201, version.text
    version_body = version.json()
    submitted = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{version_body['id']}/submit-for-review"
    )
    assert submitted.status_code == 200, submitted.text
    return eid, rid, version_body


def test_approval_persists_exact_version_and_canonical_reviewer(client, build_app):
    eid, rid, version = _setup(client)
    response = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{version['id']}/approve",
        json={
            "reviewer_name": "forged display",
            "reviewer_role": "forged role",
            "approval_notes": "reviewed",
        },
    )
    assert response.status_code == 200, response.text

    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaReportQaDecision

    db = get_sessionmaker()()
    try:
        decision = db.execute(
            select(FaReportQaDecision).where(
                FaReportQaDecision.report_version_id == version["id"]
            )
        ).scalar_one()
        assert decision.tenant_id == TENANT
        assert decision.engagement_id == eid
        assert decision.report_id == rid
        assert decision.report_version == version["version"]
        assert decision.report_hash == version["report_hash"]
        assert decision.manifest_hash == version["manifest_hash"]
        assert decision.qa_stage == "report"
        assert decision.decision == "approved"
        assert decision.reviewer_id == response.json()["approved_by"]
        assert decision.actor_type == "human"
        decision.reviewer_id = "forged-after-the-fact"
        with pytest.raises(RuntimeError, match="append-only"):
            db.flush()
        db.rollback()
    finally:
        db.close()


def test_replay_cannot_create_second_version_decision(client):
    eid, rid, version = _setup(client)
    path = f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{version['id']}/approve"
    first = client.post(path, json={"reviewer_name": "reviewer", "reviewer_role": "qa"})
    assert first.status_code == 200, first.text
    second = client.post(
        path, json={"reviewer_name": "different", "reviewer_role": "qa"}
    )
    assert second.status_code == 409
    assert "REPORT_VERSION_IMMUTABLE" in second.text


def test_service_actor_is_not_human_qa_authority():
    from api.actor_context import ActorContext
    from api.field_assessment import _require_human_qa_actor
    from fastapi import HTTPException

    actor = ActorContext(
        subject="service-1",
        email="",
        name="",
        permissions=frozenset({"report.qa_approve"}),
        roles=["platform_service"],
        auth_source="api_key",
        tenant_id=TENANT,
        service_principal_id="psp-1",
    )
    with pytest.raises(HTTPException) as exc:
        _require_human_qa_actor(actor)
    assert exc.value.status_code == 403
