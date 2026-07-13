"""tests/test_report_delivery.py — Enterprise Report Delivery workflow tests.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Covers the review → approve → deliver → supersede lineage that turns a signed
GovernanceReportRecord into an enterprise-grade deliverable with a full
append-only delivery audit trail and deterministic manifest.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient


_TENANT_A = "tenant-report-delivery-A"
_TENANT_B = "tenant-report-delivery-B"

_SIGNING_KEY_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"

_ENGAGEMENT_BODY = {
    "client_name": "Delivery Test Corp",
    "assessor_id": "assessor-del-001",
    "assessment_type": "ai_governance",
}

_APPROVAL_BODY = {
    "reviewer_name": "Jane Reviewer",
    "reviewer_role": "Senior Assessor",
    "approval_notes": "Approved after full internal review.",
    "signature_placeholder": "sig-placeholder-v1",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app, monkeypatch):
    """Tenant A client — writes AND qa-approves.

    We intentionally do NOT assign a tenant_rbac role: with no DB role the
    api-key actor derives permissions from scopes, so the combination of
    governance:write + governance:qa_approve grants both report.generate
    (from assessor) and report.qa_approve (from qa_reviewer). Assigning
    a single role would drop one of those permission sets.
    """
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=_TENANT_A,
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_b(build_app, monkeypatch):
    """Tenant B client used to verify cross-tenant isolation."""
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=_TENANT_B,
    )
    return TestClient(app, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_engagement(client: TestClient) -> str:
    resp = client.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _create_report(client: TestClient, engagement_id: str) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_version(client: TestClient, engagement_id: str, report_id: str) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}/versions",
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _submit(
    client: TestClient, engagement_id: str, report_id: str, version_id: str
) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}/versions/{version_id}/submit-for-review",
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _approve(
    client: TestClient,
    engagement_id: str,
    report_id: str,
    version_id: str,
    body: dict | None = None,
) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}/versions/{version_id}/approve",
        json=body or _APPROVAL_BODY,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _deliver(
    client: TestClient, engagement_id: str, report_id: str, version_id: str
) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}/versions/{version_id}/deliver",
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _bootstrap(client: TestClient) -> tuple[str, str]:
    eid = _create_engagement(client)
    report = _create_report(client, eid)
    return eid, report["report_id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_report_version_from_report(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    version = _create_version(client, eid, rid)
    assert version["status"] == "draft"
    assert version["version"] == 1
    assert version["revision"] == "1.0"
    assert version["report_hash"] and len(version["report_hash"]) == 64
    assert version["manifest_hash"] and len(version["manifest_hash"]) == 64
    assert version["engagement_id"] == eid
    assert version["report_id"] == rid


def test_list_report_versions(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    _create_version(client, eid, rid)
    _create_version(client, eid, rid)
    resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions",
    )
    assert resp.status_code == 200, resp.text
    versions = resp.json()
    assert len(versions) == 2
    assert versions[0]["version"] == 1
    assert versions[1]["version"] == 2


def test_get_report_version(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    version = _create_version(client, eid, rid)
    resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{version['id']}",
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["id"] == version["id"]


def test_submit_for_review_transitions_status(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    result = _submit(client, eid, rid, v["id"])
    assert result["status"] == "internal_review"


def test_approve_version_sets_metadata(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    _submit(client, eid, rid, v["id"])
    approved = _approve(client, eid, rid, v["id"])
    assert approved["status"] == "approved"
    assert approved["reviewer_name"] == _APPROVAL_BODY["reviewer_name"]
    assert approved["reviewer_role"] == _APPROVAL_BODY["reviewer_role"]
    assert approved["approval_notes"] == _APPROVAL_BODY["approval_notes"]


def test_approve_records_approval_timestamp(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    _submit(client, eid, rid, v["id"])
    approved = _approve(client, eid, rid, v["id"])
    assert approved["approved_at"] is not None
    assert approved["approved_by"] is not None


def test_delivered_version_is_immutable(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    _submit(client, eid, rid, v["id"])
    _approve(client, eid, rid, v["id"])
    _deliver(client, eid, rid, v["id"])

    # Re-approving a delivered version must be rejected
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v['id']}/approve",
        json=_APPROVAL_BODY,
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "REPORT_VERSION_IMMUTABLE"

    # Re-submitting a delivered version must be rejected
    resp2 = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v['id']}/submit-for-review",
    )
    assert resp2.status_code == 409, resp2.text


def test_deliver_report(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    _submit(client, eid, rid, v["id"])
    _approve(client, eid, rid, v["id"])
    delivered = _deliver(client, eid, rid, v["id"])
    assert delivered["status"] == "delivered"
    assert delivered["delivered_at"] is not None


def test_deliver_requires_approved_status(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    # Skip submit and approve — deliver from draft should fail
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v['id']}/deliver",
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "REPORT_VERSION_INVALID_TRANSITION"


def test_supersede_creates_lineage(client: TestClient) -> None:
    eid, rid = _bootstrap(client)

    v1 = _create_version(client, eid, rid)
    _submit(client, eid, rid, v1["id"])
    _approve(client, eid, rid, v1["id"])
    _deliver(client, eid, rid, v1["id"])

    v2 = _create_version(client, eid, rid)
    _submit(client, eid, rid, v2["id"])
    _approve(client, eid, rid, v2["id"])

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v1['id']}/supersede",
        json={"new_version_id": v2["id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "superseded"
    assert body["superseded_by_id"] == v2["id"]

    # Verify parent link on the new version
    v2_resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v2['id']}",
    )
    assert v2_resp.status_code == 200, v2_resp.text
    assert v2_resp.json()["parent_version_id"] == v1["id"]


def test_manifest_is_deterministic(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)

    r1 = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v['id']}/manifest",
    )
    r2 = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v['id']}/manifest",
    )
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()

    # Recompute hash on the manifest and ensure it matches the stored hash
    import hashlib
    import json

    canonical = json.dumps(r1.json(), sort_keys=True, ensure_ascii=True)
    manifest_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert manifest_hash == v["manifest_hash"]


def test_manifest_contains_evidence_hashes(client: TestClient) -> None:
    eid = _create_engagement(client)
    # Add one scan result so the report has an evidence link
    scan_resp = client.post(
        f"/field-assessment/engagements/{eid}/scan-results",
        json={
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-05-25T00:00:00Z",
            "raw_payload": {"users": []},
            "object_count": 0,
        },
    )
    assert scan_resp.status_code in (200, 201), scan_resp.text

    report = _create_report(client, eid)
    v = _create_version(client, eid, report["report_id"])
    manifest = client.get(
        f"/field-assessment/engagements/{eid}/reports/{report['report_id']}/versions/{v['id']}/manifest",
    ).json()
    assert manifest["evidence_count"] >= 1
    assert len(manifest["evidence_hashes"]) >= 1
    entry = manifest["evidence_hashes"][0]
    assert "evidence_id" in entry
    assert "sha256" in entry


def test_delivery_history_records_events(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    _submit(client, eid, rid, v["id"])
    _approve(client, eid, rid, v["id"])
    _deliver(client, eid, rid, v["id"])

    resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v['id']}/history",
    )
    assert resp.status_code == 200, resp.text
    history = resp.json()
    types = [e["event_type"] for e in history]
    assert "generated" in types
    assert "reviewed" in types
    assert "approved" in types
    assert "downloaded" in types


def test_tenant_isolation(client: TestClient, client_b: TestClient) -> None:
    eid_a, rid_a = _bootstrap(client)
    v_a = _create_version(client, eid_a, rid_a)

    # Tenant B lists on tenant A's engagement — engagement lookup returns 404
    resp = client_b.get(
        f"/field-assessment/engagements/{eid_a}/reports/{rid_a}/versions",
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["code"] == "ENGAGEMENT_NOT_FOUND"

    # Tenant B cannot fetch tenant A's specific version
    resp2 = client_b.get(
        f"/field-assessment/engagements/{eid_a}/reports/{rid_a}/versions/{v_a['id']}",
    )
    assert resp2.status_code == 404


def test_cross_tenant_denial(client: TestClient, client_b: TestClient) -> None:
    """Tenant B creates an engagement + report; tenant A cannot access it."""
    eid_b, rid_b = _bootstrap(client_b)
    v_b = _create_version(client_b, eid_b, rid_b)

    resp = client.get(
        f"/field-assessment/engagements/{eid_b}/reports/{rid_b}/versions/{v_b['id']}",
    )
    assert resp.status_code == 404


def test_approval_requires_reviewer_name(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v = _create_version(client, eid, rid)
    _submit(client, eid, rid, v["id"])
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v['id']}/approve",
        json={"reviewer_role": "Senior Assessor"},
    )
    assert resp.status_code == 422, resp.text


def test_version_increment_on_new_version(client: TestClient) -> None:
    eid, rid = _bootstrap(client)
    v1 = _create_version(client, eid, rid)
    v2 = _create_version(client, eid, rid)
    assert v1["version"] == 1
    assert v2["version"] == 2
    assert v1["id"] != v2["id"]


def test_evidence_links_preserved(client: TestClient) -> None:
    """Creating additional versions must not disturb the original evidence links."""
    from sqlalchemy import select

    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaEvidenceReportLink

    eid = _create_engagement(client)
    scan_resp = client.post(
        f"/field-assessment/engagements/{eid}/scan-results",
        json={
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-05-25T00:00:00Z",
            "raw_payload": {"users": []},
            "object_count": 0,
        },
    )
    assert scan_resp.status_code in (200, 201), scan_resp.text

    report = _create_report(client, eid)
    rid = report["report_id"]

    # Snapshot the report links
    SM = get_sessionmaker()
    db = SM()
    try:
        pre_ids = sorted(
            row.id
            for row in db.execute(
                select(FaEvidenceReportLink).where(
                    FaEvidenceReportLink.tenant_id == _TENANT_A,
                    FaEvidenceReportLink.engagement_id == eid,
                    FaEvidenceReportLink.report_id == rid,
                )
            )
            .scalars()
            .all()
        )
    finally:
        db.close()

    _create_version(client, eid, rid)
    _create_version(client, eid, rid)

    db = SM()
    try:
        post_ids = sorted(
            row.id
            for row in db.execute(
                select(FaEvidenceReportLink).where(
                    FaEvidenceReportLink.tenant_id == _TENANT_A,
                    FaEvidenceReportLink.engagement_id == eid,
                    FaEvidenceReportLink.report_id == rid,
                )
            )
            .scalars()
            .all()
        )
    finally:
        db.close()

    assert pre_ids == post_ids
