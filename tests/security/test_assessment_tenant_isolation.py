"""
tests/security/test_assessment_tenant_isolation.py

Wrong-tenant denial coverage for the assessment/report commercial workflow.

Invariants verified:
  1. Tenant-A cannot read, mutate, checkout, submit, or generate reports for
     Tenant-B assessments.
  2. Pre-tenant lead records (lead:<assessment_id>) are not accessible by any
     tenant-bound caller unless that tenant matches.
  3. Tenant-bound callers cannot enumerate or access pre-tenant lead records.
  4. Pre-tenant callers cannot access tenant-bound assessments.
  5. Report get/download enforce the same tenant boundary.
  6. Missing tenant context (unbound caller with no X-Assessment-Id) fails closed.
  7. No metadata is leaked on denial (error shape is uniform 404).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch as mpatch

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ORG_PAYLOAD: dict[str, Any] = {
    "name": "Acme Corp",
    "industry": "tech",
    "employee_count": "51-200",
}


def _create_assessment(client: TestClient, key: str) -> tuple[str, str]:
    """Create an org+assessment; return (assessment_id, org_id)."""
    resp = client.post(
        "/ingest/assessment/orgs",
        headers={"X-API-Key": key},
        json=_ORG_PAYLOAD,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return data["assessment_id"], data["org_id"]


def _save_responses(client: TestClient, key: str, assessment_id: str) -> None:
    """Autosave one response so the assessment is in_progress."""
    resp = client.patch(
        f"/ingest/assessment/{assessment_id}/responses",
        headers={"X-API-Key": key},
        json={"responses": {"q1": True}},
    )
    assert resp.status_code == 200, resp.text


def _force_scored(assessment_id: str) -> None:
    """Directly write 'scored' status into the test DB — no question bank needed.

    This bypasses the submit endpoint entirely so report-related security tests
    always run regardless of whether database seeds are present.
    """
    from api.db import get_sessionmaker
    from api.db_models import AssessmentRecord

    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        rec = (
            db.query(AssessmentRecord)
            .filter(AssessmentRecord.id == assessment_id)
            .first()
        )
        if rec:
            rec.status = "scored"
            rec.overall_score = 72.5
            rec.risk_band = "medium"
            rec.scores = {
                "data_governance": 70.0,
                "security_posture": 75.0,
                "ai_maturity": 65.0,
                "infra_readiness": 80.0,
                "compliance_awareness": 68.0,
                "automation_potential": 72.0,
            }
            rec.submitted_at = datetime.now(timezone.utc)
            rec.scored_at = datetime.now(timezone.utc)
            db.commit()


def _prepare_scored_assessment(client: TestClient, key: str) -> str:
    """Create an assessment, save a response, force it to scored. Returns assessment_id."""
    assessment_id, _ = _create_assessment(client, key)
    _save_responses(client, key, assessment_id)
    _force_scored(assessment_id)
    return assessment_id


def _enqueue_report(client: TestClient, key: str, assessment_id: str) -> str:
    """Enqueue report generation (background task mocked). Returns report_id."""
    with mpatch("api.reports_engine._generate_report_sync"):
        gen = client.post(
            "/ingest/assessment/reports/generate",
            headers={"X-API-Key": key},
            json={"assessment_id": assessment_id, "prompt_type": "executive"},
        )
    assert gen.status_code == 202, gen.text
    return gen.json()["report_id"]


# ---------------------------------------------------------------------------
# Tenant-A vs Tenant-B isolation
# ---------------------------------------------------------------------------


def test_wrong_tenant_cannot_read_assessment(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id, _ = _create_assessment(client, key_a)

    # Tenant-B must not read Tenant-A's assessment.
    resp = client.get(
        f"/ingest/assessment/{assessment_id}",
        headers={"X-API-Key": key_b},
    )
    assert resp.status_code == 404
    # No data leakage — detail must not reference the real assessment.
    assert "tenant" not in resp.json().get("detail", "").lower()


def test_wrong_tenant_cannot_mutate_assessment(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id, _ = _create_assessment(client, key_a)

    resp = client.patch(
        f"/ingest/assessment/{assessment_id}/responses",
        headers={"X-API-Key": key_b},
        json={"responses": {"q1": True}},
    )
    assert resp.status_code == 404


def test_wrong_tenant_cannot_get_questions(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id, _ = _create_assessment(client, key_a)

    resp = client.get(
        f"/ingest/assessment/{assessment_id}/questions",
        headers={"X-API-Key": key_b},
    )
    assert resp.status_code == 404


def test_wrong_tenant_cannot_submit_assessment(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id, _ = _create_assessment(client, key_a)

    # Pre-submit responses with owner key.
    client.patch(
        f"/ingest/assessment/{assessment_id}/responses",
        headers={"X-API-Key": key_a},
        json={"responses": {"q1": True}},
    )

    resp = client.post(
        f"/ingest/assessment/{assessment_id}/submit",
        headers={"X-API-Key": key_b},
    )
    assert resp.status_code == 404


def test_wrong_tenant_cannot_checkout_assessment(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id, _ = _create_assessment(client, key_a)

    resp = client.post(
        f"/ingest/assessment/{assessment_id}/checkout",
        headers={"X-API-Key": key_b},
    )
    assert resp.status_code == 404


def test_wrong_tenant_cannot_generate_report(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id = _prepare_scored_assessment(client, key_a)

    resp = client.post(
        "/ingest/assessment/reports/generate",
        headers={"X-API-Key": key_b},
        json={"assessment_id": assessment_id, "prompt_type": "executive"},
    )
    assert resp.status_code == 404


def test_wrong_tenant_cannot_poll_report(build_app):
    """Tenant-B must not poll Tenant-A's report (including via report_id brute-force)."""
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id = _prepare_scored_assessment(client, key_a)
    report_id = _enqueue_report(client, key_a, assessment_id)

    resp = client.get(
        f"/ingest/assessment/reports/{report_id}",
        headers={"X-API-Key": key_b},
    )
    assert resp.status_code == 404


def test_wrong_tenant_cannot_download_report(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id = _prepare_scored_assessment(client, key_a)
    report_id = _enqueue_report(client, key_a, assessment_id)

    resp = client.get(
        f"/ingest/assessment/reports/{report_id}/download",
        headers={"X-API-Key": key_b},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Pre-tenant lead isolation
# ---------------------------------------------------------------------------


def test_tenant_bound_caller_cannot_access_lead_assessment(build_app):
    """A tenant-bound caller must not access a pre-tenant lead-namespaced assessment."""
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    # Create assessment with unbound global key (pre-tenant lead).
    unbound_key = mint_key("ingest:assessment")  # no tenant_id
    assessment_id, _ = _create_assessment(client, unbound_key)

    # Tenant-bound caller attempts to access.
    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    resp = client.get(
        f"/ingest/assessment/{assessment_id}",
        headers={"X-API-Key": key_a},
    )
    assert resp.status_code == 404


def test_pretenant_caller_cannot_access_tenant_bound_assessment(build_app):
    """An unbound caller must not access a tenant-bound assessment."""
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    assessment_id, _ = _create_assessment(client, key_a)

    unbound_key = mint_key("ingest:assessment")
    resp = client.get(
        f"/ingest/assessment/{assessment_id}",
        headers={"X-API-Key": unbound_key},
    )
    assert resp.status_code == 404


def test_pretenant_report_poll_requires_assessment_id_header(build_app):
    """Unbound caller polling a report without X-Assessment-Id header must get 404."""
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    unbound_key = mint_key("ingest:assessment")
    assessment_id = _prepare_scored_assessment(client, unbound_key)
    report_id = _enqueue_report(client, unbound_key, assessment_id)

    # No ownership header → fail closed.
    resp = client.get(
        f"/ingest/assessment/reports/{report_id}",
        headers={"X-API-Key": unbound_key},
    )
    assert resp.status_code == 404


def test_pretenant_report_poll_wrong_assessment_id_fails(build_app):
    """Unbound caller providing wrong assessment_id in header must get 404."""
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    unbound_key = mint_key("ingest:assessment")
    assessment_id = _prepare_scored_assessment(client, unbound_key)
    report_id = _enqueue_report(client, unbound_key, assessment_id)

    wrong_id = str(uuid.uuid4())
    resp = client.get(
        f"/ingest/assessment/reports/{report_id}",
        headers={"X-API-Key": unbound_key, "X-Assessment-Id": wrong_id},
    )
    assert resp.status_code == 404


def test_pretenant_report_poll_correct_assessment_id_succeeds(build_app):
    """Unbound caller with correct X-Assessment-Id header must access their own report."""
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    unbound_key = mint_key("ingest:assessment")
    assessment_id = _prepare_scored_assessment(client, unbound_key)
    report_id = _enqueue_report(client, unbound_key, assessment_id)

    resp = client.get(
        f"/ingest/assessment/reports/{report_id}",
        headers={"X-API-Key": unbound_key, "X-Assessment-Id": assessment_id},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Fail-closed: non-existent assessment IDs
# ---------------------------------------------------------------------------


def test_nonexistent_assessment_returns_404_not_500(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key = mint_key("ingest:assessment", tenant_id="tenant-x")
    fake_id = str(uuid.uuid4())

    resp = client.get(
        f"/ingest/assessment/{fake_id}",
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 404
    # No stack trace, internal path, or tenant info in response body.
    body = resp.text
    assert "tenant" not in body.lower()
    assert "traceback" not in body.lower()
    assert "sqlalchemy" not in body.lower()


# ---------------------------------------------------------------------------
# Ownership lineage: report derives tenant from assessment
# ---------------------------------------------------------------------------


def test_report_tenant_inherits_from_assessment(build_app):
    """Report created from Tenant-A assessment must be scoped to Tenant-A."""
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    key_a = mint_key("ingest:assessment", tenant_id="tenant-a")
    key_b = mint_key("ingest:assessment", tenant_id="tenant-b")

    assessment_id = _prepare_scored_assessment(client, key_a)
    report_id = _enqueue_report(client, key_a, assessment_id)

    # Tenant-A can poll it.
    resp_a = client.get(
        f"/ingest/assessment/reports/{report_id}",
        headers={"X-API-Key": key_a},
    )
    assert resp_a.status_code == 200

    # Tenant-B cannot.
    resp_b = client.get(
        f"/ingest/assessment/reports/{report_id}",
        headers={"X-API-Key": key_b},
    )
    assert resp_b.status_code == 404
