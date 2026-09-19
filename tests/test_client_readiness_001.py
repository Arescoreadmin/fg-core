"""CLIENT-READINESS-001 focused golden-path boundary proof.

This test deliberately stops at the first native commercial blocker.  It does
not seed production qualification or bypass the result-truth authority.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")

from fastapi.testclient import TestClient


TENANT_A = "high-table-financial-707"
TENANT_B = "continental-holdings-707"
HIGH_TABLE_SENTINEL = "HIGH_TABLE_ONLY_707"
SIGNING_KEY_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"


def _client(app: object, tenant_id: str) -> TestClient:
    from api.auth_scopes import mint_key

    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=tenant_id,
    )
    return TestClient(app, headers={"X-API-Key": key})  # type: ignore[arg-type]


def test_legitimate_assessment_stops_at_production_qualification(
    build_app: object, monkeypatch: object
) -> None:
    """Truth can pass natively; delivery still fails closed without qualification."""
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", SIGNING_KEY_HEX)  # type: ignore[attr-defined]
    app = build_app(auth_enabled=True)  # type: ignore[operator]
    tenant_a = _client(app, TENANT_A)
    tenant_b = _client(app, TENANT_B)

    engagement_response = tenant_a.post(
        "/field-assessment/engagements",
        json={
            "client_name": "The High Table Financial",
            "client_domain": "high-table.example",
            "assessor_id": "assessor-707",
            "assessment_type": "ai_governance",
            "engagement_metadata": {"audit_sentinel": HIGH_TABLE_SENTINEL},
        },
    )
    assert engagement_response.status_code == 201, engagement_response.text
    engagement_id = engagement_response.json()["id"]

    foreign_read = tenant_b.get(f"/field-assessment/engagements/{engagement_id}")
    assert foreign_read.status_code == 404
    assert HIGH_TABLE_SENTINEL not in foreign_read.text

    evidence_response = tenant_a.post(
        f"/field-assessment/engagements/{engagement_id}/scan-results",
        json={
            "source_type": "microsoft_graph",
            "schema_version": "1.0",
            "collected_at": "2026-09-19T12:00:00Z",
            "raw_payload": {
                "source": "synthetic-client-readiness-audit",
                "sentinel": HIGH_TABLE_SENTINEL,
                "users": [],
            },
            "object_count": 1,
        },
    )
    assert evidence_response.status_code == 201, evidence_response.text
    evidence = evidence_response.json()
    assert len(evidence["evidence_hash"]) == 64

    report_response = tenant_a.post(
        f"/field-assessment/engagements/{engagement_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert report_response.status_code == 201, report_response.text
    report_id = report_response.json()["report_id"]
    report_version = report_response.json()["version"]

    report_document_response = tenant_a.get(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_version}"
    )
    assert report_document_response.status_code == 200
    report_document = report_document_response.json()["report"]
    assert report_document["result_truth_gate"]["decision"] == "PASS"
    assert report_document["production_qualification"]["status"] == "NOT_REQUESTED"
    assert report_document["production_qualification"]["qualified"] is False
    assert report_document["evidence_population"]["eligible_count"] == 1

    foreign_report = tenant_b.get(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_version}"
    )
    assert foreign_report.status_code == 404
    assert HIGH_TABLE_SENTINEL not in foreign_report.text

    version_response = tenant_a.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}/versions"
    )
    assert version_response.status_code == 201, version_response.text
    version_id = version_response.json()["id"]

    submitted = tenant_a.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}"
        f"/versions/{version_id}/submit-for-review"
    )
    assert submitted.status_code == 200, submitted.text

    approved = tenant_a.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}"
        f"/versions/{version_id}/approve",
        json={
            "reviewer_name": "Synthetic Reviewer 707",
            "reviewer_role": "Senior Assessor",
            "approval_notes": "Synthetic readiness audit only.",
        },
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"

    history_before = tenant_a.get(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}"
        f"/versions/{version_id}/history"
    )
    assert history_before.status_code == 200

    delivery = tenant_a.post(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}"
        f"/versions/{version_id}/deliver"
    )
    assert delivery.status_code == 422
    assert delivery.json()["detail"]["code"] == "PRODUCTION_QUALIFICATION_BLOCKED"

    version_after = tenant_a.get(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}"
        f"/versions/{version_id}"
    )
    assert version_after.status_code == 200
    assert version_after.json()["status"] == "approved"
    assert version_after.json()["delivered_at"] is None

    history_after = tenant_a.get(
        f"/field-assessment/engagements/{engagement_id}/reports/{report_id}"
        f"/versions/{version_id}/history"
    )
    assert history_after.status_code == 200
    assert history_after.json() == history_before.json()
    assert "downloaded" not in {event["event_type"] for event in history_after.json()}
