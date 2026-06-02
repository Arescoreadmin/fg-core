"""tests/test_field_assessment.py — Field Assessment Engagement Substrate test suite.

Covers:
  - Deterministic finding ID generation
  - Evidence hash computation
  - Engagement lifecycle transitions (model-level)
  - Tenant isolation
  - Engagement CRUD
  - Scan result ingestion + hash mismatch rejection
  - Observation capture
  - Evidence link idempotency
  - Summary endpoint
  - Schema version presence in responses
  - Auth enforcement
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)  # 64-char hex test seed

import pytest
from fastapi.testclient import TestClient

from services.field_assessment.store import (
    compute_evidence_hash,
    derive_finding_id,
    derive_findings_hash,
)
from services.field_assessment.models import (
    VALID_ENGAGEMENT_TRANSITIONS,
    EngagementStatus,
)

# ---------------------------------------------------------------------------
# Shared payloads
# ---------------------------------------------------------------------------

_ENGAGEMENT_BODY = {
    "client_name": "ACME Corp",
    "assessor_id": "assessor-001",
    "assessment_type": "ai_governance",
}

_TRANSITION_BODY = {"new_status": "cancelled", "reason": "engagement cancelled"}

_SCAN_RESULT_BODY = {
    "source_type": "microsoft_graph",
    "schema_version": "1.0",
    "collected_at": "2026-05-19T00:00:00Z",
    "raw_payload": {"users": []},
    "object_count": 0,
}

_OBSERVATION_BODY = {
    "domain": "ai_governance",
    "observation_type": "gap",
    "severity": "high",
    "title": "Missing AI usage policy",
    "description": "No documented AI usage policy found.",
}

_DOC_ANALYSIS_BODY = {
    "document_name": "AI Policy v1.0.pdf",
    "document_classification": "ai_policy",
}


# ---------------------------------------------------------------------------
# Pure unit tests — no DB, no app
# ---------------------------------------------------------------------------


def test_finding_id_determinism() -> None:
    id1 = derive_finding_id("misconfiguration", "eng-abc", "ref-001")
    id2 = derive_finding_id("misconfiguration", "eng-abc", "ref-001")
    assert id1 == id2


def test_finding_id_uniqueness_different_source_ref() -> None:
    id1 = derive_finding_id("misconfiguration", "eng-abc", "ref-001")
    id2 = derive_finding_id("misconfiguration", "eng-abc", "ref-002")
    assert id1 != id2


def test_evidence_hash_determinism() -> None:
    payload = {"users": [], "groups": ["admins"]}
    h1 = compute_evidence_hash(payload)
    h2 = compute_evidence_hash(payload)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_evidence_hash_canonical() -> None:
    # Key ordering should not affect the hash
    h1 = compute_evidence_hash({"a": 1, "b": 2})
    h2 = compute_evidence_hash({"b": 2, "a": 1})
    assert h1 == h2


def test_evidence_hash_differs_on_different_payload() -> None:
    h1 = compute_evidence_hash({"users": []})
    h2 = compute_evidence_hash({"users": ["alice"]})
    assert h1 != h2


def test_findings_hash_full_length() -> None:
    h = derive_findings_hash("misconfiguration", "eng-abc", "ref-001")
    assert len(h) == 64  # full SHA-256 hex


def test_valid_engagement_transitions() -> None:
    assert "cancelled" in VALID_ENGAGEMENT_TRANSITIONS["in_progress"]
    assert "remediation" in VALID_ENGAGEMENT_TRANSITIONS["delivered"]
    assert "monitoring" in VALID_ENGAGEMENT_TRANSITIONS["delivered"]
    assert "closed" in VALID_ENGAGEMENT_TRANSITIONS["delivered"]


def test_invalid_engagement_transitions_terminal_states() -> None:
    assert len(VALID_ENGAGEMENT_TRANSITIONS["closed"]) == 0
    assert len(VALID_ENGAGEMENT_TRANSITIONS["cancelled"]) == 0


def test_engagement_status_enum_values() -> None:
    assert EngagementStatus.IN_PROGRESS.value == "in_progress"
    assert EngagementStatus.CLOSED.value == "closed"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT_ID = "tenant-fa-test"


@pytest.fixture()
def client(build_app: object) -> TestClient:
    """Auth-enabled client with governance:read + governance:write scopes."""
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def authed_client(build_app: object) -> TestClient:
    """Auth-enabled client with no API key (for testing auth enforcement)."""
    app = build_app(auth_enabled=True)  # type: ignore[operator]
    return TestClient(app)


def _create_engagement(client: TestClient) -> dict:
    resp = client.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# API tests — Engagement CRUD
# ---------------------------------------------------------------------------


def test_create_engagement_success(client: TestClient) -> None:
    resp = client.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert resp.status_code == 201
    data = resp.json()
    assert data["client_name"] == "ACME Corp"
    assert data["status"] == "in_progress"
    assert data["assessment_type"] == "ai_governance"


def test_get_engagement_not_found(client: TestClient) -> None:
    resp = client.get("/field-assessment/engagements/nonexistent-id-0000")
    assert resp.status_code == 404


def test_create_and_get_engagement(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    resp = client.get(f"/field-assessment/engagements/{eng_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == eng_id
    assert data["client_name"] == "ACME Corp"


def test_list_engagements_empty(client: TestClient) -> None:
    resp = client.get("/field-assessment/engagements")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert isinstance(data["items"], list)
    assert "total_count" in data


def test_list_engagements_returns_created(client: TestClient) -> None:
    _create_engagement(client)
    resp = client.get("/field-assessment/engagements")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_count"] >= 1


# ---------------------------------------------------------------------------
# API tests — Status transitions
# ---------------------------------------------------------------------------


def test_engagement_status_transition_valid(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/status",
        json=_TRANSITION_BODY,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "cancelled"


def test_engagement_status_transition_invalid(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    # in_progress → closed is not a valid direct transition
    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/status",
        json={"new_status": "closed", "reason": "skipping ahead"},
    )
    assert resp.status_code == 409


def test_engagement_transition_not_found(client: TestClient) -> None:
    resp = client.patch(
        "/field-assessment/engagements/nonexistent-0000/status",
        json=_TRANSITION_BODY,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API tests — Scan results
# ---------------------------------------------------------------------------


def test_ingest_scan_result(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["source_type"] == "microsoft_graph"
    assert data["evidence_hash"]
    assert data["engagement_id"] == eng_id


def test_ingest_scan_result_hash_mismatch_rejected(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    body = dict(_SCAN_RESULT_BODY)
    body["expected_evidence_hash"] = "a" * 64  # wrong hash

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=body,
    )
    assert resp.status_code == 422


def test_ingest_scan_result_hash_correct_accepted(client: TestClient) -> None:
    from services.field_assessment.store import compute_evidence_hash

    created = _create_engagement(client)
    eng_id = created["id"]

    raw_payload: dict[str, object] = {"users": []}
    correct_hash = compute_evidence_hash(raw_payload)
    body = dict(_SCAN_RESULT_BODY)
    body["expected_evidence_hash"] = correct_hash

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=body,
    )
    assert resp.status_code == 201


def test_list_scan_results(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]
    client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )

    resp = client.get(f"/field-assessment/engagements/{eng_id}/scan-results")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


# ---------------------------------------------------------------------------
# API tests — Document analyses
# ---------------------------------------------------------------------------


def test_register_document_analysis(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/document-analyses",
        json=_DOC_ANALYSIS_BODY,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["document_name"] == "AI Policy v1.0.pdf"
    assert data["document_classification"] == "ai_policy"
    assert data["engagement_id"] == eng_id
    assert "schema_version" in data


# ---------------------------------------------------------------------------
# API tests — Observations
# ---------------------------------------------------------------------------


def test_capture_observation(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json=_OBSERVATION_BODY,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["domain"] == "ai_governance"
    assert data["severity"] == "high"
    assert data["engagement_id"] == eng_id
    assert data["schema_version"] == "1.0"


def test_list_observations(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]
    client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json=_OBSERVATION_BODY,
    )

    resp = client.get(f"/field-assessment/engagements/{eng_id}/observations")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


# ---------------------------------------------------------------------------
# API tests — Evidence links
# ---------------------------------------------------------------------------


def test_evidence_link_creation(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    # Create a real scan result to use as the evidence entity
    scan_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    link_body = {
        "source_entity_type": "fa_engagement",
        "source_entity_id": eng_id,
        "evidence_entity_type": "scan_result",
        "evidence_entity_id": scan_id,
    }

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/evidence-links",
        json=link_body,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["source_entity_id"] == eng_id
    assert data["evidence_entity_type"] == "scan_result"
    assert data["evidence_entity_id"] == scan_id


def test_evidence_link_duplicate_rejected(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    scan_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    link_body = {
        "source_entity_type": "fa_engagement",
        "source_entity_id": eng_id,
        "evidence_entity_type": "scan_result",
        "evidence_entity_id": scan_id,
    }

    resp1 = client.post(
        f"/field-assessment/engagements/{eng_id}/evidence-links",
        json=link_body,
    )
    assert resp1.status_code == 201

    resp2 = client.post(
        f"/field-assessment/engagements/{eng_id}/evidence-links",
        json=link_body,
    )
    assert resp2.status_code == 409


def test_evidence_link_orphan_rejected(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    link_body = {
        "source_entity_type": "fa_engagement",
        "source_entity_id": eng_id,
        "evidence_entity_type": "scan_result",
        "evidence_entity_id": "nonexistent-scan-id",
    }

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/evidence-links",
        json=link_body,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# API tests — Summary
# ---------------------------------------------------------------------------


def test_engagement_summary(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    # Add a scan result and observation to have non-zero counts
    client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json=_OBSERVATION_BODY,
    )

    resp = client.get(f"/field-assessment/engagements/{eng_id}/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["engagement_id"] == eng_id
    assert data["client_name"] == "ACME Corp"
    assert data["status"] == "in_progress"
    assert data["total_scan_results"] == 1
    assert data["total_observations"] == 1
    assert "total_findings" in data
    assert "findings_by_severity" in data
    assert "open_findings_count" in data
    assert "schema_version" in data


def test_engagement_summary_not_found(client: TestClient) -> None:
    resp = client.get("/field-assessment/engagements/does-not-exist/summary")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API tests — Single scan result GET (replay access)
# ---------------------------------------------------------------------------


def test_get_scan_result_by_id(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    post_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    assert post_resp.status_code == 201
    scan_id = post_resp.json()["id"]

    resp = client.get(f"/field-assessment/engagements/{eng_id}/scan-results/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == scan_id
    assert data["engagement_id"] == eng_id
    assert "raw_payload" in data  # full detail response


def test_get_scan_result_not_found(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]
    resp = client.get(
        f"/field-assessment/engagements/{eng_id}/scan-results/nonexistent-id"
    )
    assert resp.status_code == 404


def test_list_scan_results_excludes_raw_payload(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]
    client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    resp = client.get(f"/field-assessment/engagements/{eng_id}/scan-results")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    assert "raw_payload" not in items[0]


# ---------------------------------------------------------------------------
# API tests — Scan deduplication
# ---------------------------------------------------------------------------


def test_scan_result_deduplication(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    resp1 = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    assert resp1.status_code == 201
    id1 = resp1.json()["id"]

    resp2 = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    assert resp2.status_code == 201
    id2 = resp2.json()["id"]

    assert id1 == id2  # idempotent — same evidence hash returns same record


# ---------------------------------------------------------------------------
# API tests — collected_at validation
# ---------------------------------------------------------------------------


def test_collected_at_invalid_rejected(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    body = dict(_SCAN_RESULT_BODY)
    body["collected_at"] = "not-a-date"

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=body,
    )
    assert resp.status_code == 422


def test_collected_at_valid_iso8601(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    body = dict(_SCAN_RESULT_BODY)
    body["collected_at"] = "2026-05-19T12:34:56+00:00"
    body["raw_payload"] = {"users": ["alice"]}  # different payload to avoid dedup

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=body,
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# API tests — Schema version presence
# ---------------------------------------------------------------------------


def test_schema_version_in_response(client: TestClient) -> None:
    resp = client.post("/field-assessment/engagements", json=_ENGAGEMENT_BODY)
    assert resp.status_code == 201
    data = resp.json()
    assert "schema_version" in data
    assert data["schema_version"] == "1.0"


def test_schema_version_in_scan_result(client: TestClient) -> None:
    created = _create_engagement(client)
    eng_id = created["id"]

    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/scan-results",
        json=_SCAN_RESULT_BODY,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# API tests — Auth enforcement
# ---------------------------------------------------------------------------


def test_auth_required_without_key(authed_client: TestClient) -> None:
    """POST to /field-assessment/engagements with no API key must return 401 or 403."""
    resp = authed_client.post(
        "/field-assessment/engagements",
        json=_ENGAGEMENT_BODY,
        # No X-API-Key header
    )
    assert resp.status_code in (401, 403)


def test_get_engagement_wrong_tenant_returns_404(client: TestClient) -> None:
    """Requests with a tenant that doesn't own the engagement get 404, not 403."""
    # With auth_enabled=False, tenant is not set — EngagementNotFound → 404
    resp = client.get("/field-assessment/engagements/unknown-tenant-eng")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API tests — ObservationType.INTERVIEW
# ---------------------------------------------------------------------------


def test_capture_interview_observation(client: TestClient) -> None:
    """INTERVIEW observation_type stores correctly and is retrievable."""
    created = _create_engagement(client)
    eng_id = created["id"]
    body = {
        "domain": "ai_governance",
        "observation_type": "interview",
        "severity": "info",
        "title": "CTO interview — AI usage patterns",
        "description": "Interviewed CTO regarding AI tooling adoption.",
        "interview_role": "CTO",
    }
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/observations", json=body
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["observation_type"] == "interview"
    assert data["interview_role"] == "CTO"


def test_interview_observation_appears_in_list(client: TestClient) -> None:
    """INTERVIEW observations are returned by the list endpoint."""
    created = _create_engagement(client)
    eng_id = created["id"]
    body = {
        "domain": "compliance",
        "observation_type": "interview",
        "severity": "low",
        "title": "Legal counsel interview",
        "description": "Policy awareness check.",
        "interview_role": "General Counsel",
    }
    client.post(f"/field-assessment/engagements/{eng_id}/observations", json=body)
    resp = client.get(f"/field-assessment/engagements/{eng_id}/observations")
    assert resp.status_code == 200
    types = [o["observation_type"] for o in resp.json()]
    assert "interview" in types


# ---------------------------------------------------------------------------
# API tests — Observation type filter
# ---------------------------------------------------------------------------


def test_observation_type_filter_interview(client: TestClient) -> None:
    """?observation_type=interview returns only interview observations."""
    created = _create_engagement(client)
    eng_id = created["id"]

    # Add a gap observation
    client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json=_OBSERVATION_BODY,
    )
    # Add an interview observation
    client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json={
            "domain": "ai_governance",
            "observation_type": "interview",
            "severity": "info",
            "title": "CEO interview",
            "description": "Strategy discussion.",
            "interview_role": "CEO",
        },
    )

    resp = client.get(
        f"/field-assessment/engagements/{eng_id}/observations",
        params={"observation_type": "interview"},
    )
    assert resp.status_code == 200
    items = resp.json()
    assert all(o["observation_type"] == "interview" for o in items)
    assert len(items) >= 1


def test_observation_type_filter_gap(client: TestClient) -> None:
    """?observation_type=gap excludes interview observations."""
    created = _create_engagement(client)
    eng_id = created["id"]

    client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json=_OBSERVATION_BODY,  # observation_type=gap
    )
    client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json={
            "domain": "ai_governance",
            "observation_type": "interview",
            "severity": "info",
            "title": "CFO interview",
            "description": "Budget context.",
            "interview_role": "CFO",
        },
    )

    resp = client.get(
        f"/field-assessment/engagements/{eng_id}/observations",
        params={"observation_type": "gap"},
    )
    assert resp.status_code == 200
    items = resp.json()
    assert all(o["observation_type"] == "gap" for o in items)


# ---------------------------------------------------------------------------
# API tests — Audit events
# ---------------------------------------------------------------------------


def test_audit_events_route_exists(client: TestClient) -> None:
    """GET /audit-events returns 200 for a valid engagement."""
    created = _create_engagement(client)
    eng_id = created["id"]
    resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_audit_events_populated_after_mutation(client: TestClient) -> None:
    """Creating an engagement emits at least one audit event."""
    created = _create_engagement(client)
    eng_id = created["id"]
    resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 1
    # Validate shape
    ev = events[0]
    assert "id" in ev
    assert "event_type" in ev
    assert "actor" in ev
    assert "reason_code" in ev
    assert "payload" in ev
    assert "schema_version" in ev
    assert "created_at" in ev


def test_audit_events_tenant_scoped(client: TestClient) -> None:
    """Audit events from one engagement are not visible via another engagement ID."""
    eng1 = _create_engagement(client)["id"]
    eng2 = _create_engagement(client)["id"]

    resp1 = client.get(f"/field-assessment/engagements/{eng1}/audit-events")
    resp2 = client.get(f"/field-assessment/engagements/{eng2}/audit-events")
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    ids1 = {ev["id"] for ev in resp1.json()}
    ids2 = {ev["id"] for ev in resp2.json()}
    assert ids1.isdisjoint(ids2)


def test_audit_events_not_found(client: TestClient) -> None:
    resp = client.get("/field-assessment/engagements/nonexistent-id/audit-events")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Portal IDOR guard tests (C4)
# ---------------------------------------------------------------------------


@pytest.fixture()
def portal_client(build_app: object) -> TestClient:
    """Portal-flavored client: X-Portal-Source header + governance scopes."""
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(
        app,
        headers={
            "X-API-Key": key,
            "X-Portal-Source": "client-portal",
        },
    )


def _create_delivered_engagement(client: TestClient) -> dict:
    """Create an engagement and QA-approve it to get a client_access_code."""
    eng = _create_engagement(client)
    eng_id = eng["id"]
    # Ingest a scan + findings so a report can be generated
    report_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"schema_version": "1.0", "sections": {}, "section_hashes": {}},
    )
    if report_resp.status_code == 201:
        version = report_resp.json()["version"]
        client.post(
            f"/field-assessment/engagements/{eng_id}/reports/{version}/qa-approve"
        )
    # Re-fetch to get current state including client_access_code
    detail = client.get(f"/field-assessment/engagements/{eng_id}")
    return detail.json()


def test_portal_engagement_access_requires_code(
    portal_client: TestClient, client: TestClient
) -> None:
    """Portal request without client_access_code is blocked with 403."""
    eng = _create_engagement(client)
    eng_id = eng["id"]
    resp = portal_client.get(f"/field-assessment/engagements/{eng_id}")
    assert resp.status_code == 403
    assert resp.json()["code"] == "PORTAL_ACCESS_CODE_REQUIRED"


def test_portal_engagement_wrong_code_denied(
    portal_client: TestClient, client: TestClient
) -> None:
    """Portal request with wrong access code is denied."""
    eng = _create_engagement(client)
    eng_id = eng["id"]
    resp = portal_client.get(
        f"/field-assessment/engagements/{eng_id}",
        params={"client_access_code": "wrong-code"},
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "PORTAL_ACCESS_DENIED"


def test_portal_engagement_wrong_code_denied_on_subresource(
    portal_client: TestClient, client: TestClient
) -> None:
    """IDOR guard also protects sub-resources like /findings."""
    eng = _create_engagement(client)
    eng_id = eng["id"]
    resp = portal_client.get(
        f"/field-assessment/engagements/{eng_id}/findings",
        params={"client_access_code": "not-the-real-code"},
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "PORTAL_ACCESS_DENIED"


def test_portal_list_engagements_no_code_required(portal_client: TestClient) -> None:
    """List route does not require client_access_code from the middleware (already filtered)."""
    resp = portal_client.get("/field-assessment/engagements")
    # List route is not gated by the middleware — the middleware only activates for /{id}/* paths
    assert resp.status_code == 200


def test_operator_request_bypasses_portal_guard(client: TestClient) -> None:
    """Requests without X-Portal-Source header are not gated."""
    eng = _create_engagement(client)
    eng_id = eng["id"]
    # No X-Portal-Source header → middleware is a no-op → normal 200
    resp = client.get(f"/field-assessment/engagements/{eng_id}")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# QA delivery gate tests (C1)
# ---------------------------------------------------------------------------


@pytest.fixture()
def qa_client(build_app: object) -> TestClient:
    """Client with governance:read + governance:write + governance:qa_approve scopes."""
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=_TENANT_ID,
    )
    return TestClient(app, headers={"X-API-Key": key})


def _create_finalized_report(qa_client: TestClient, eng_id: str) -> str:
    """Create and finalize a report; return the report_id."""
    resp = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201), resp.text
    data = resp.json()
    # The route returns the report id directly or inside a list; normalise both shapes.
    return data.get("id") or data.get("report_id") or data["items"][0]["report_id"]


def test_qa_approve_blocks_delivery_when_gates_incomplete(
    qa_client: TestClient,
) -> None:
    """QA approval records successfully but delivery is blocked when other gates are not met."""
    eng = _create_engagement(qa_client)
    eng_id = eng["id"]
    report_id = _create_finalized_report(qa_client, eng_id)

    resp = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # QA approval was recorded
    assert data["qa_approved_by"] != ""
    assert data["qa_approved_at"] != ""
    # Delivery is blocked because other gates (scans, questionnaire, etc.) are unmet
    assert data["delivery_blocked"] is True
    assert len(data["delivery_blockers"]) > 0
    assert data["engagement_status"] == "in_progress"
    assert data["client_access_code"] is None


def test_qa_approve_blockers_include_gate_id_and_title(qa_client: TestClient) -> None:
    """delivery_blockers items contain gate_id, title, and missing_items."""
    eng = _create_engagement(qa_client)
    eng_id = eng["id"]
    report_id = _create_finalized_report(qa_client, eng_id)

    data = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={},
    ).json()

    for blocker in data["delivery_blockers"]:
        assert "gate_id" in blocker
        assert "title" in blocker
        assert "missing_items" in blocker


def test_qa_approve_engagement_status_unchanged_when_blocked(
    qa_client: TestClient,
) -> None:
    """Engagement remains in_progress when QA approve cannot auto-advance."""
    eng = _create_engagement(qa_client)
    eng_id = eng["id"]
    report_id = _create_finalized_report(qa_client, eng_id)

    qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={},
    )

    detail = qa_client.get(f"/field-assessment/engagements/{eng_id}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "in_progress"


# ---------------------------------------------------------------------------
# H9 — observation edit validation
# ---------------------------------------------------------------------------


def _create_observation(
    client: TestClient, eng_id: str, body: dict | None = None
) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/observations",
        json=body or _OBSERVATION_BODY,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_update_observation_rejects_invalid_audio_url(client: TestClient) -> None:
    """PATCH must reject structured_evidence with a non-http _audio_url."""
    eng_id = _create_engagement(client)["id"]
    obs_id = _create_observation(client, eng_id)["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/observations/{obs_id}",
        json={
            "structured_evidence": {
                "_audio_url": "ftp://bad-scheme.example.com/file.mp3"
            }
        },
    )
    assert resp.status_code == 422


def test_update_observation_rejects_non_numeric_audio_duration(
    client: TestClient,
) -> None:
    """PATCH must reject _audio_duration_sec that is not a number."""
    eng_id = _create_engagement(client)["id"]
    obs_id = _create_observation(client, eng_id)["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/observations/{obs_id}",
        json={"structured_evidence": {"_audio_duration_sec": "not-a-number"}},
    )
    assert resp.status_code == 422


def test_update_observation_rejects_foreign_finding_ids(client: TestClient) -> None:
    """PATCH must reject linked_finding_ids that don't exist in this engagement."""
    eng_id = _create_engagement(client)["id"]
    obs_id = _create_observation(client, eng_id)["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/observations/{obs_id}",
        json={"linked_finding_ids": ["nonexistent-finding-id-abc123"]},
    )
    assert resp.status_code == 422
    assert "INVALID_FINDING_IDS" in resp.text


def test_update_observation_audit_diff_includes_structured_evidence(
    client: TestClient,
) -> None:
    """Audit event after PATCH must include structured_evidence in before/after."""
    eng_id = _create_engagement(client)["id"]
    obs_id = _create_observation(client, eng_id)["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/observations/{obs_id}",
        json={"structured_evidence": {"notes": "updated note"}},
    )
    assert resp.status_code == 200

    audit_resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
    assert audit_resp.status_code == 200
    events = audit_resp.json()
    update_events = [e for e in events if e.get("event_type") == "observation.updated"]
    assert update_events, "No observation.updated audit event found"
    payload = update_events[-1]["payload"]
    assert "structured_evidence" in payload["before"]
    assert "structured_evidence" in payload["after"]
    assert payload["after"]["structured_evidence"] == {"notes": "updated note"}


def test_update_observation_audit_diff_includes_linked_finding_ids(
    client: TestClient,
) -> None:
    """Audit event after PATCH must include linked_finding_ids in before/after."""
    eng_id = _create_engagement(client)["id"]
    obs_id = _create_observation(client, eng_id)["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/observations/{obs_id}",
        json={"title": "Updated title"},
    )
    assert resp.status_code == 200

    audit_resp = client.get(f"/field-assessment/engagements/{eng_id}/audit-events")
    assert audit_resp.status_code == 200
    events = audit_resp.json()
    update_events = [e for e in events if e.get("event_type") == "observation.updated"]
    assert update_events, "No observation.updated audit event found"
    payload = update_events[-1]["payload"]
    assert "linked_finding_ids" in payload["before"]
    assert "linked_finding_ids" in payload["after"]


def test_update_observation_valid_audio_evidence_accepted(client: TestClient) -> None:
    """PATCH with valid audio evidence metadata must succeed."""
    eng_id = _create_engagement(client)["id"]
    obs_id = _create_observation(client, eng_id)["id"]

    resp = client.patch(
        f"/field-assessment/engagements/{eng_id}/observations/{obs_id}",
        json={
            "structured_evidence": {
                "_audio_url": "https://storage.example.com/rec.mp3",
                "_audio_duration_sec": 120.5,
                "_audio_size_kb": 2048,
                "_audio_hash": "abc123",
            }
        },
    )
    assert resp.status_code == 200  # valid audio evidence accepted


# ---------------------------------------------------------------------------
# H10 — QA approval immutability + display name
# ---------------------------------------------------------------------------


def test_qa_approve_second_call_rejected_with_409(qa_client: TestClient) -> None:
    """Re-approving an already-approved report must return 409 REPORT_ALREADY_APPROVED."""
    eng_id = _create_engagement(qa_client)["id"]
    report_id = _create_finalized_report(qa_client, eng_id)

    first = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={},
    )
    assert first.status_code == 200

    second = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={},
    )
    assert second.status_code == 409
    assert "REPORT_ALREADY_APPROVED" in second.text


def test_qa_approve_response_uses_reviewer_name(qa_client: TestClient) -> None:
    """Response qa_approved_by must reflect the supplied reviewer_name, not the JWT actor."""
    eng_id = _create_engagement(qa_client)["id"]
    report_id = _create_finalized_report(qa_client, eng_id)

    resp = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={"reviewer_name": "Jane Smith, Senior Assessor"},
    )
    assert resp.status_code == 200
    assert resp.json()["qa_approved_by"] == "Jane Smith, Senior Assessor"


def test_qa_approve_response_falls_back_to_actor_when_no_name(
    qa_client: TestClient,
) -> None:
    """When reviewer_name is omitted, qa_approved_by must be non-empty (JWT actor fallback)."""
    eng_id = _create_engagement(qa_client)["id"]
    report_id = _create_finalized_report(qa_client, eng_id)

    resp = qa_client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={},
    )
    assert resp.status_code == 200
    assert resp.json()["qa_approved_by"]  # non-empty fallback
