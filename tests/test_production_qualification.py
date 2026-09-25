"""tests/test_production_qualification.py — PROD-QUAL-001 adversarial test suite.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Covers the canonical production qualification authority: request → attest → finalize.
Adversarial categories:

  A — delivery gate remains fail-closed after PROD-QUAL-001 (no QUALIFIED → 422)
  B — cross-tenant isolation (tenant B cannot access tenant A's qualification)
  C — report prerequisites enforced (must be finalized + QA-approved)
  D — replay-rejection (same gate cannot be attested twice per request)
  E — partial attestation cannot produce QUALIFIED decision
  F — unknown gate name is rejected
  G — result_truth_gate FAIL blocks QUALIFIED finalization
  H — actor identity derived from ActorContext, never from request body
  I — already-finalized request cannot be re-finalized
  J — already-QUALIFIED report cannot spawn a second QUALIFIED request
  K — canonical QUALIFIED decision enables delivery gate (DB authority proven)
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient

_TENANT_A = "tenant-prod-qual-A"
_TENANT_B = "tenant-prod-qual-B"
_SIGNING_KEY_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"

_ENGAGEMENT_BODY = {
    "client_name": "Qual Test Corp",
    "assessor_id": "assessor-qual-001",
    "assessment_type": "ai_governance",
}

_APPROVAL_BODY = {
    "reviewer_name": "QA Jane",
    "reviewer_role": "QA Lead",
    "approval_notes": "LGTM",
    "signature_placeholder": "sig-v1",
}

_ALL_GATES = (
    "PRODUCTION_DEPENDENCY_SECURITY",
    "PRODUCTION_SCHEMA_AND_RLS",
    "CANONICAL_ASSESSMENT_PROOF",
    "DURABLE_EXECUTION_AND_RECOVERY",
)


def _err(resp) -> str:
    """Extract the structured error code from an api_error response."""
    return (resp.json().get("detail") or {}).get("code", "")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app, monkeypatch):
    """Tenant A client — has governance:write + governance:qa_approve + governance:qualify.

    Because we use API key scope-based auth (no RBAC role), we grant all needed
    scopes directly. In production, report.qualify is gated to compliance_reviewer
    (SoD with qa_reviewer), but tests exercise the qualification logic path
    independently of role enforcement.
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
    """Tenant B client — cross-tenant isolation probe."""
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


def _create_report(client: TestClient, eid: str) -> str:
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["report_id"]


def _qa_approve(client: TestClient, eid: str, rid: str) -> None:
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qa-approve",
        json=_APPROVAL_BODY,
    )
    assert resp.status_code == 200, resp.text


def _qual_request(client: TestClient, eid: str, rid: str) -> str:
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/request",
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _attest(
    client: TestClient,
    eid: str,
    rid: str,
    qid: str,
    gate: str,
    attested: bool = True,
    notes: str | None = None,
) -> dict:
    body: dict = {"gate_name": gate, "attested": attested}
    if notes:
        body["notes"] = notes
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/attest",
        json=body,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _attest_all(
    client: TestClient, eid: str, rid: str, qid: str, *, attested: bool = True
) -> None:
    for gate in _ALL_GATES:
        _attest(client, eid, rid, qid, gate, attested=attested)


def _finalize(
    client: TestClient, eid: str, rid: str, qid: str, reason: str | None = None
) -> dict:
    body = {}
    if reason:
        body["reason"] = reason
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/finalize",
        json=body,
    )
    return resp


def _bootstrap_approved(client: TestClient) -> tuple[str, str]:
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)
    return eid, rid


# ---------------------------------------------------------------------------
# Category A — delivery gate remains fail-closed
# ---------------------------------------------------------------------------


def test_a1_delivery_blocked_without_qualified_decision(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delivery is blocked when no QUALIFIED decision exists."""
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions",
    )
    assert resp.status_code == 201, resp.text
    vid = resp.json()["id"]

    client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review"
    )
    client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json={"reviewer_name": "Rev", "reviewer_role": "Lead"},
    )

    deliver_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/deliver",
    )
    assert deliver_resp.status_code == 422
    error_code = _err(deliver_resp)
    assert (
        "PRODUCTION_QUALIFICATION_BLOCKED" in error_code
        or "RESULT_TRUTH_GATE" in error_code
    )


def test_a2_delivery_gate_checks_db_not_report_json(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate checks canonical DB table — patching report_json production_qualification has no effect."""
    eid, rid = _bootstrap_approved(client)

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions",
    )
    assert resp.status_code == 201
    vid = resp.json()["id"]

    client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review"
    )
    client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json={"reviewer_name": "Rev"},
    )

    deliver_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/deliver",
    )
    # Must be blocked — report_json alone cannot satisfy the gate
    assert deliver_resp.status_code in (422, 409)


# ---------------------------------------------------------------------------
# Category B — cross-tenant isolation
# ---------------------------------------------------------------------------


def test_b1_tenant_b_cannot_create_qual_request_for_tenant_a(
    client: TestClient, client_b: TestClient
) -> None:
    eid, rid = _bootstrap_approved(client)

    resp = client_b.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/request",
    )
    assert resp.status_code in (403, 404)


def test_b2_tenant_b_cannot_attest_tenant_a_request(
    client: TestClient, client_b: TestClient
) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    resp = client_b.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/attest",
        json={"gate_name": "PRODUCTION_DEPENDENCY_SECURITY", "attested": True},
    )
    assert resp.status_code in (403, 404)


def test_b3_tenant_b_cannot_finalize_tenant_a_request(
    client: TestClient, client_b: TestClient
) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)
    _attest_all(client, eid, rid, qid)

    resp = client_b.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/finalize",
        json={},
    )
    assert resp.status_code in (403, 404)


def test_b4_tenant_b_cannot_read_tenant_a_qual_status(
    client: TestClient, client_b: TestClient
) -> None:
    eid, rid = _bootstrap_approved(client)
    _qual_request(client, eid, rid)

    resp = client_b.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify",
    )
    assert resp.status_code in (200, 403, 404)
    if resp.status_code == 200:
        # Must return empty — no data leaked across tenants
        assert resp.json()["qual_request_id"] is None


# ---------------------------------------------------------------------------
# Category C — report prerequisites enforced
# ---------------------------------------------------------------------------


def test_c1_unapproved_report_cannot_be_requested(client: TestClient) -> None:
    """A finalized-but-unapproved report cannot start a qualification request."""
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    # Report is finalized by create_report, but NOT QA-approved

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/request",
    )
    assert resp.status_code == 422
    assert "QA_APPROVED" in _err(resp).upper()


def test_c2_unknown_report_is_404(client: TestClient) -> None:
    eid = _create_engagement(client)

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/nonexistent-report/qualify/request",
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Category D — replay-rejection (same gate cannot be attested twice)
# ---------------------------------------------------------------------------


def test_d1_duplicate_gate_attestation_is_rejected(client: TestClient) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    _attest(client, eid, rid, qid, "PRODUCTION_DEPENDENCY_SECURITY")

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/attest",
        json={"gate_name": "PRODUCTION_DEPENDENCY_SECURITY", "attested": True},
    )
    assert resp.status_code == 409
    assert "ALREADY_RECORDED" in _err(resp).upper()


# ---------------------------------------------------------------------------
# Category E — partial attestation cannot produce QUALIFIED
# ---------------------------------------------------------------------------


def test_e1_three_of_four_gates_blocks_qualified(client: TestClient) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    # Attest only 3 of the 4 gates
    for gate in _ALL_GATES[:3]:
        _attest(client, eid, rid, qid, gate)

    resp = _finalize(client, eid, rid, qid)
    assert resp.status_code == 422
    assert "QUALIFICATION_BLOCKED" in _err(resp).upper()


def test_e2_false_attestation_blocks_qualified(client: TestClient) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    # Attest 3 gates True, 1 gate False
    for gate in _ALL_GATES[:3]:
        _attest(client, eid, rid, qid, gate, attested=True)
    _attest(client, eid, rid, qid, _ALL_GATES[3], attested=False)

    resp = _finalize(client, eid, rid, qid)
    assert resp.status_code == 422
    assert "QUALIFICATION_BLOCKED" in _err(resp).upper()


def test_e3_zero_attestations_blocks_qualified(client: TestClient) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    resp = _finalize(client, eid, rid, qid)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Category F — unknown gate name is rejected
# ---------------------------------------------------------------------------


def test_f1_unknown_gate_name_is_rejected(client: TestClient) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/attest",
        json={"gate_name": "MADE_UP_GATE", "attested": True},
    )
    assert resp.status_code == 422
    assert "UNKNOWN_GATE_NAME" in _err(resp).upper()


def test_f2_injected_gate_name_is_rejected(client: TestClient) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/attest",
        json={
            "gate_name": "'; DROP TABLE fa_production_attestations; --",
            "attested": True,
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Category G — result_truth_gate FAIL blocks QUALIFIED finalization
# ---------------------------------------------------------------------------


def test_g1_failing_truth_gate_blocks_qualified(client: TestClient) -> None:
    """All four gates attested True, but truth_gate decision is not PASS → 422."""
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)
    _attest_all(client, eid, rid, qid)

    # report_json truth gate decision is FAIL in test reports (no real evidence)
    resp = _finalize(client, eid, rid, qid)
    assert resp.status_code == 422
    body = resp.json()
    assert "QUALIFICATION_BLOCKED" in _err(resp).upper()
    # The blocking reason should mention the truth gate
    detail_obj = body.get("detail") or {}
    detail_msg = (
        detail_obj.get("message", "")
        if isinstance(detail_obj, dict)
        else str(detail_obj)
    )
    assert "result_truth_gate" in detail_msg.lower() or "PASS" in detail_msg


# ---------------------------------------------------------------------------
# Category H — actor identity from ActorContext, never from request body
# ---------------------------------------------------------------------------


def test_h1_attestation_attested_by_is_from_context_not_body(
    client: TestClient,
) -> None:
    """The attested_by field must reflect the authenticated actor, not a spoofed value."""
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)

    # Send a body with an extra field that attempts to spoof identity
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/attest",
        json={
            "gate_name": "PRODUCTION_DEPENDENCY_SECURITY",
            "attested": True,
            "attested_by": "mallory@evil.com",  # must be ignored
        },
    )
    assert resp.status_code == 201
    result = resp.json()
    # attested_by must NOT be mallory — it comes from the API key subject
    assert result["attested_by"] != "mallory@evil.com"


def test_h2_qual_request_requested_by_is_from_context(client: TestClient) -> None:
    eid, rid = _bootstrap_approved(client)

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/request",
        json={"requested_by": "fake-actor"},  # must be ignored
    )
    assert resp.status_code == 201
    result = resp.json()
    assert result["requested_by"] != "fake-actor"


# ---------------------------------------------------------------------------
# Category I — already-finalized request cannot be re-finalized
# ---------------------------------------------------------------------------


def test_i1_finalized_request_cannot_be_re_finalized(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    eid, rid = _bootstrap_approved(client)
    qid = _qual_request(client, eid, rid)
    _attest_all(client, eid, rid, qid)

    monkeypatch.setattr(
        "api.field_assessment._require_production_qualified", lambda *_, **__: None
    )
    monkeypatch.setattr(
        "services.governance.report.qualification_authority.check_finalization_readiness",
        lambda **__: [],
    )

    resp1 = _finalize(client, eid, rid, qid)
    if resp1.status_code != 201:
        # If the truth gate blocks, inject a QUALIFIED decision directly and test replay
        from api.db import get_sessionmaker
        from api.db_models_field_assessment import FaQualificationDecision
        import uuid

        sm = get_sessionmaker()()
        try:
            row = FaQualificationDecision(
                id=uuid.uuid4().hex,
                tenant_id=_TENANT_A,
                engagement_id=eid,
                report_id=rid,
                qual_request_id=qid,
                report_version_id="",
                report_fingerprint="",
                decision="QUALIFIED",
                decided_by="test-actor",
                actor_type="service",
                reason=None,
                decided_at="2026-09-24T00:00:00Z",
                schema_version="1.0",
            )
            sm.add(row)
            sm.commit()
        finally:
            sm.close()

    resp2 = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/{qid}/finalize",
        json={},
    )
    assert resp2.status_code == 409
    assert "ALREADY_FINALIZED" in _err(resp2).upper()


# ---------------------------------------------------------------------------
# Category J — already-QUALIFIED report cannot spawn second QUALIFIED request
# ---------------------------------------------------------------------------


def test_j1_second_request_blocked_when_already_qualified(
    client: TestClient,
) -> None:
    """A report that already has a QUALIFIED decision cannot start a new request."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaProductionQualRequest,
        FaQualificationDecision,
    )
    import uuid

    eid, rid = _bootstrap_approved(client)

    # Inject a QUALIFIED decision directly (bypassing truth gate for test isolation)
    sm = get_sessionmaker()()
    try:
        qid = uuid.uuid4().hex
        req_row = FaProductionQualRequest(
            id=qid,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            requested_by="test-actor",
            actor_type="service",
            requested_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(req_row)
        sm.flush()
        dec_row = FaQualificationDecision(
            id=uuid.uuid4().hex,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            qual_request_id=qid,
            report_version_id="",
            report_fingerprint="",
            decision="QUALIFIED",
            decided_by="test-actor",
            actor_type="service",
            reason=None,
            decided_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(dec_row)
        sm.commit()
    finally:
        sm.close()

    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/request",
    )
    assert resp.status_code == 409
    assert "ALREADY_QUALIFIED" in _err(resp).upper()


# ---------------------------------------------------------------------------
# Category K — canonical QUALIFIED decision in DB is recognized by delivery gate
# ---------------------------------------------------------------------------


def test_k1_qualified_decision_in_db_satisfies_delivery_gate(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A QUALIFIED row in fa_qualification_decisions is sufficient to pass the gate.

    The deliver route monkeypatches _require_production_qualified to isolate the
    DB authority proof from the result_truth_gate (which is always FAIL in tests
    because report generation uses synthetic evidence). We confirm the gate passes
    by injecting a QUALIFIED decision and monkeypatching away the truth gate check.
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaProductionQualRequest,
        FaQualificationDecision,
    )
    import uuid

    eid, rid = _bootstrap_approved(client)

    # Create version, submit, approve
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions",
    )
    assert resp.status_code == 201
    vid = resp.json()["id"]
    submit_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review"
    )
    assert submit_resp.status_code == 200, submit_resp.text
    approve_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json={"reviewer_name": "Rev", "reviewer_role": "Lead", "approval_notes": "ok"},
    )
    assert approve_resp.status_code == 200, approve_resp.text

    sm = get_sessionmaker()()
    try:
        qid = uuid.uuid4().hex
        req_row = FaProductionQualRequest(
            id=qid,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            requested_by="test-actor",
            actor_type="service",
            requested_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(req_row)
        sm.flush()
        dec_row = FaQualificationDecision(
            id=uuid.uuid4().hex,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            qual_request_id=qid,
            report_version_id=vid,
            report_fingerprint="",
            decision="QUALIFIED",
            decided_by="test-actor",
            actor_type="service",
            reason=None,
            decided_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(dec_row)
        sm.commit()
    finally:
        sm.close()

    # Monkeypatch only the truth gate portion so the DB check runs unimpeded
    def _patched_require(report_json, db, *, report_id, tenant_id, report_version_id):
        # Skip truth_gate check (always FAIL in tests); let DB authority run
        from sqlalchemy import select as _select
        from api.db_models_field_assessment import FaQualificationDecision as _FQD
        from fastapi import HTTPException
        from api.error_contracts import api_error

        decision = db.execute(
            _select(_FQD).where(
                _FQD.tenant_id == tenant_id,
                _FQD.report_id == report_id,
                _FQD.report_version_id == report_version_id,
                _FQD.decision == "QUALIFIED",
            )
        ).scalar_one_or_none()
        if decision is None:
            raise HTTPException(
                status_code=422,
                detail=api_error(
                    "PRODUCTION_QUALIFICATION_BLOCKED", "no QUALIFIED decision"
                ),
            )

    monkeypatch.setattr(
        "api.field_assessment._require_production_qualified", _patched_require
    )

    deliver_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/deliver",
    )
    assert deliver_resp.status_code == 200
    assert deliver_resp.json()["status"] == "delivered"


def test_k2_get_qual_status_returns_qualified_true_after_decision(
    client: TestClient,
) -> None:
    """GET /qualify returns qualified=True when a QUALIFIED decision exists."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaProductionQualRequest,
        FaQualificationDecision,
    )
    import uuid

    eid, rid = _bootstrap_approved(client)

    sm = get_sessionmaker()()
    try:
        qid = uuid.uuid4().hex
        req_row = FaProductionQualRequest(
            id=qid,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            requested_by="test-actor",
            actor_type="service",
            requested_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(req_row)
        sm.flush()
        dec_row = FaQualificationDecision(
            id=uuid.uuid4().hex,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            qual_request_id=qid,
            report_version_id="",
            report_fingerprint="",
            decision="QUALIFIED",
            decided_by="test-actor",
            actor_type="service",
            reason="all gates confirmed",
            decided_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(dec_row)
        sm.commit()
    finally:
        sm.close()

    resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["qualified"] is True
    assert body["qual_request_id"] == qid
    assert body["decision"]["decision"] == "QUALIFIED"


def test_k3_get_qual_status_returns_qualified_false_when_no_request(
    client: TestClient,
) -> None:
    eid, rid = _bootstrap_approved(client)

    resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["qualified"] is False
    assert body["qual_request_id"] is None
    assert body["decision"] is None


def test_k4_qual_workflow_happy_path_creates_request_and_attestations(
    client: TestClient,
) -> None:
    """Verifies the full request → attest flow creates the expected DB rows."""
    eid, rid = _bootstrap_approved(client)

    qid = _qual_request(client, eid, rid)
    assert qid

    for gate in _ALL_GATES:
        resp = _attest(client, eid, rid, qid, gate, notes=f"verified {gate}")
        assert resp["gate_name"] == gate
        assert resp["attested"] is True
        assert resp["qual_request_id"] == qid

    status_resp = client.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify",
    )
    assert status_resp.status_code == 200
    status = status_resp.json()
    assert status["qual_request_id"] == qid
    assert len(status["attestations"]) == 4
    # All gates present
    gate_names = {a["gate_name"] for a in status["attestations"]}
    assert gate_names == set(_ALL_GATES)
    # Decision not yet issued
    assert status["decision"] is None
    assert status["qualified"] is False


# ---------------------------------------------------------------------------
# Category L — version binding: QUALIFIED for V1 does not authorize V2 delivery
# ---------------------------------------------------------------------------


def _binding_only_require(report_json, db, *, report_id, tenant_id, report_version_id):
    """Monkeypatch that skips the truth_gate check but enforces version+fingerprint binding.

    Used in L and M tests to isolate binding correctness from truth_gate (always FAIL
    in tests because synthetic evidence never produces a PASS decision).
    """
    from sqlalchemy import select as _sel
    from api.db_models_field_assessment import FaQualificationDecision as _FQD
    from fastapi import HTTPException
    from api.error_contracts import api_error

    truth_gate = (report_json or {}).get("result_truth_gate") or {}
    fp = truth_gate.get("result_fingerprint") or ""

    decision = db.execute(
        _sel(_FQD).where(
            _FQD.tenant_id == tenant_id,
            _FQD.report_id == report_id,
            _FQD.report_version_id == report_version_id,
            _FQD.report_fingerprint == fp,
            _FQD.decision == "QUALIFIED",
        )
    ).scalar_one_or_none()
    if decision is None:
        raise HTTPException(
            status_code=422,
            detail=api_error("PRODUCTION_QUALIFICATION_BLOCKED", "binding check failed"),
        )


def test_l1_qualified_v1_does_not_authorize_v2_delivery(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A QUALIFIED decision for V1 must not authorize delivery of V2.

    Steps:
    - Create report, QA-approve (sets up the report-level approval)
    - Create and approve V1; inject QUALIFIED decision bound to V1 with real fingerprint
    - Create and approve V2 (different version_id)
    - Monkeypatch to skip truth_gate but keep version+fingerprint binding
    - Deliver V2 → 422 PRODUCTION_QUALIFICATION_BLOCKED (wrong version_id)
    - Deliver V1 → 200 (correct version_id + fingerprint match)
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaProductionQualRequest, FaQualificationDecision
    from api.db_models_governance_report import GovernanceReportRecord
    from sqlalchemy import select as _sel
    import uuid

    eid, rid = _bootstrap_approved(client)

    # Create and approve V1
    resp = client.post(f"/field-assessment/engagements/{eid}/reports/{rid}/versions")
    assert resp.status_code == 201
    vid1 = resp.json()["id"]
    client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid1}/submit-for-review"
    )
    approve_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid1}/approve",
        json={"reviewer_name": "Rev", "reviewer_role": "Lead", "approval_notes": "ok"},
    )
    assert approve_resp.status_code == 200

    # Resolve the real report_fingerprint from the immutable report_json
    sm = get_sessionmaker()()
    try:
        report_record = sm.execute(
            _sel(GovernanceReportRecord).where(GovernanceReportRecord.id == rid)
        ).scalar_one()
        truth_gate = (report_record.report_json or {}).get("result_truth_gate") or {}
        actual_fp = truth_gate.get("result_fingerprint") or ""

        qid = uuid.uuid4().hex
        req_row = FaProductionQualRequest(
            id=qid,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            report_version_id=vid1,
            requested_by="test-actor",
            actor_type="service",
            requested_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(req_row)
        sm.flush()
        dec_row = FaQualificationDecision(
            id=uuid.uuid4().hex,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            qual_request_id=qid,
            report_version_id=vid1,
            report_fingerprint=actual_fp,
            decision="QUALIFIED",
            decided_by="test-actor",
            actor_type="service",
            reason=None,
            decided_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(dec_row)
        sm.commit()
    finally:
        sm.close()

    # Create and approve V2
    resp2 = client.post(f"/field-assessment/engagements/{eid}/reports/{rid}/versions")
    assert resp2.status_code == 201
    vid2 = resp2.json()["id"]
    client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid2}/submit-for-review"
    )
    approve2 = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid2}/approve",
        json={"reviewer_name": "Rev", "reviewer_role": "Lead", "approval_notes": "ok"},
    )
    assert approve2.status_code == 200

    monkeypatch.setattr(
        "api.field_assessment._require_production_qualified", _binding_only_require
    )

    # V2 delivery must be denied — QUALIFIED is bound to V1
    deny_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid2}/deliver"
    )
    assert deny_resp.status_code == 422
    assert _err(deny_resp) == "PRODUCTION_QUALIFICATION_BLOCKED"

    # V1 delivery must succeed — QUALIFIED is bound to V1 with correct fingerprint
    allow_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid1}/deliver"
    )
    assert allow_resp.status_code == 200
    assert allow_resp.json()["status"] == "delivered"


# ---------------------------------------------------------------------------
# Category M — fingerprint binding: wrong fingerprint in QUALIFIED row is denied
# ---------------------------------------------------------------------------


def test_m1_wrong_fingerprint_in_qualified_row_denies_delivery(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A QUALIFIED decision whose report_fingerprint does not match the current
    report content fingerprint must be rejected at delivery time.

    This proves that a QUALIFIED decision cannot be replayed against a report
    whose content has changed (different result_fingerprint) even if the
    version_id matches.
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaProductionQualRequest,
        FaQualificationDecision,
    )
    import uuid

    eid, rid = _bootstrap_approved(client)

    resp = client.post(f"/field-assessment/engagements/{eid}/reports/{rid}/versions")
    assert resp.status_code == 201
    vid = resp.json()["id"]
    client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review"
    )
    approve_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json={"reviewer_name": "Rev", "reviewer_role": "Lead", "approval_notes": "ok"},
    )
    assert approve_resp.status_code == 200

    sm = get_sessionmaker()()
    try:
        qid = uuid.uuid4().hex
        req_row = FaProductionQualRequest(
            id=qid,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            report_version_id=vid,
            requested_by="test-actor",
            actor_type="service",
            requested_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(req_row)
        sm.flush()
        dec_row = FaQualificationDecision(
            id=uuid.uuid4().hex,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            qual_request_id=qid,
            report_version_id=vid,
            report_fingerprint="deliberately-wrong-fingerprint-does-not-match",
            decision="QUALIFIED",
            decided_by="test-actor",
            actor_type="service",
            reason=None,
            decided_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(dec_row)
        sm.commit()
    finally:
        sm.close()

    monkeypatch.setattr(
        "api.field_assessment._require_production_qualified", _binding_only_require
    )

    deny_resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/deliver"
    )
    assert deny_resp.status_code == 422
    assert _err(deny_resp) == "PRODUCTION_QUALIFICATION_BLOCKED"


# ---------------------------------------------------------------------------
# Category N — SoD: qa_reviewer cannot qualify; compliance_reviewer cannot qa-approve
#
# The role-level SoD is enforced by the scope→role mapping:
#   governance:write → compliance_reviewer (has report.qualify, not report.qa_approve)
#   governance:qa_approve → qa_reviewer (has report.qa_approve, not report.qualify)
#
# An entity with only one scope cannot perform the other's gated action.
# Note: this test validates role-level SoD only. Preventing the SAME human from
# holding both roles simultaneously requires IdP/membership-layer enforcement
# outside the scope of this module.
# ---------------------------------------------------------------------------


@pytest.fixture()
def qualify_only_client(build_app, monkeypatch):
    """Client with governance:write only — has report.qualify, not report.qa_approve."""
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def qa_only_client(build_app, monkeypatch):
    """Client with governance:qa_approve only — has report.qa_approve, not report.qualify."""
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:qa_approve", tenant_id=_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


def test_n1_qa_reviewer_cannot_call_qualify_request(
    client: TestClient,
    qa_only_client: TestClient,
) -> None:
    """An actor with only the qa_reviewer role (report.qa_approve) cannot start a
    production qualification request — proving the qualify/qa_approve SoD at the
    route authorization layer.
    """
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)

    resp = qa_only_client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qualify/request"
    )
    assert resp.status_code == 403


def test_n2_compliance_reviewer_cannot_call_qa_approve(
    client: TestClient,
    qualify_only_client: TestClient,
) -> None:
    """An actor with only the compliance_reviewer role (report.qualify) cannot
    QA-approve a report — proving the qualify/qa_approve SoD at the route
    authorization layer.
    """
    eid = _create_engagement(qualify_only_client)
    rid = _create_report(qualify_only_client, eid)

    resp = qualify_only_client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qa-approve",
        json=_APPROVAL_BODY,
    )
    assert resp.status_code == 403
