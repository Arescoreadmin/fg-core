"""FINAL release gate cannot be bypassed — L14-SCAN-REPORT-PROOF-001 acceptance.

Drives the synthetic 14-finding engagement through every release-relevant
route: generate, export (download), QA approve, production qualification
(request → attest → finalize), versioned deliver and governed delivery —
including an out-of-band QUALIFIED decision row — and checks that the PDF is
rendered from the same persisted proof snapshot the release decision uses.
"""

from __future__ import annotations

import io
import re

import pytest
from fastapi.testclient import TestClient

from tests.test_report_proof import _synthetic as S

pypdf = pytest.importorskip("pypdf")
pytest.importorskip("reportlab")

_GATES = (
    "PRODUCTION_DEPENDENCY_SECURITY",
    "PRODUCTION_SCHEMA_AND_RLS",
    "CANONICAL_ASSESSMENT_PROOF",
    "DURABLE_EXECUTION_AND_RECOVERY",
)


@pytest.fixture()
def client(build_app, monkeypatch):
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", S.SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=S.TENANT,
    )
    return TestClient(app, headers={"X-API-Key": key})


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _nospace(text: str) -> str:
    return re.sub(r"\s+", "", text)


def test_synthetic_report_cannot_reach_final_through_any_route(client):
    from tests.test_governed_delivery import (
        _approve_version,
        _create_version,
        _governed_delivery,
        _inject_qualification,
        _submit,
    )

    eid = S.create_engagement(client)
    S.seed(eid)
    rep = S.generate_report(client, eid)
    rid, version = rep["report_id"], rep["version"]
    base = f"/field-assessment/engagements/{eid}/reports/{rid}"

    # QA approval is recorded, but cannot make a synthetic report final.
    qa = client.post(f"{base}/qa-approve", json={"reviewer_name": "QA"})
    assert qa.status_code == 200, qa.text
    assert (
        S.export(client, eid, version, "json").json()["report_state"]["state"]
        == "DRAFT_SYNTHETIC"
    )

    # Production qualification by a separate actor (SoD forbids the QA
    # approver): every gate attested, finalize still refused.
    from api.auth_scopes import mint_key

    qualifier = TestClient(
        client.app,
        headers={
            "X-API-Key": mint_key(
                "governance:read", "governance:write", tenant_id=S.TENANT
            )
        },
    )
    req = qualifier.post(f"{base}/qualify/request")
    assert req.status_code == 201, req.text
    qid = req.json().get("qual_request_id") or req.json().get("id")
    for gate in _GATES:
        at = qualifier.post(
            f"{base}/qualify/{qid}/attest", json={"gate_name": gate, "attested": True}
        )
        assert at.status_code == 201, at.text
    fin = qualifier.post(
        f"{base}/qualify/{qid}/finalize", json={"reason": "attempted bypass"}
    )
    assert fin.status_code == 422, fin.text
    assert "QUALIFICATION_BLOCKED" in fin.text

    # Version workflow reaches "approved"; both delivery routes refuse.
    vid = _create_version(client, eid, rid)
    _submit(client, eid, rid, vid)
    _approve_version(client, eid, rid, vid)
    direct = client.post(f"{base}/versions/{vid}/deliver")
    assert direct.status_code == 422, direct.text
    assert "REPORT_PROOF_BLOCKED" in direct.text and "SYNTHETIC_DATA" in direct.text
    gov = _governed_delivery(client, eid, rid, vid)
    assert gov.status_code == 422 and "REPORT_PROOF_BLOCKED" in gov.text

    # Out-of-band QUALIFIED decision row (simulated forgery): still refused,
    # and the marking still derives from the proof, not from that row.
    _inject_qualification(S.TENANT, eid, rid, vid)
    for resp in (
        client.post(f"{base}/versions/{vid}/deliver"),
        _governed_delivery(client, eid, rid, vid, idempotency_key="bypass-2"),
    ):
        assert resp.status_code == 422 and "REPORT_PROOF_BLOCKED" in resp.text
    state = S.export(client, eid, version, "json").json()["report_state"]
    assert state["state"] == "DRAFT_SYNTHETIC" and state["production_qualified"] is True
    pdf = S.export(client, eid, version, "pdf")
    assert pdf.headers["X-Report-State"] == "DRAFT_SYNTHETIC"
    for page in pypdf.PdfReader(io.BytesIO(pdf.content)).pages:
        assert "DRAFT — SYNTHETIC DATA — NOT VERIFIED" in _flat(
            page.extract_text() or ""
        )


def test_pdf_renders_the_same_proof_snapshot_the_release_decision_uses(client):
    from api.db import get_sessionmaker
    from api.db_models_governance_report import GovernanceReportRecord
    from services.field_assessment.report_proof import release_blockers_now

    eid = S.create_engagement(client)
    S.seed(eid)
    rep = S.generate_report(client, eid)
    pdf = S.export(client, eid, rep["version"], "pdf")
    js = S.export(client, eid, rep["version"], "json").json()
    text = _flat(
        "\n".join(
            p.extract_text() or ""
            for p in pypdf.PdfReader(io.BytesIO(pdf.content)).pages
        )
    )

    db = get_sessionmaker()()
    try:
        record = db.get(GovernanceReportRecord, rep["report_id"])
        stored = record.report_json
        decision_blockers = release_blockers_now(
            db, tenant_id=S.TENANT, engagement_id=eid, report_json=stored
        )
        manifest_hash = record.manifest_hash
    finally:
        db.close()

    proof = stored["report_proof"]
    # Same signed snapshot: manifest hash and proof fingerprint printed in the PDF.
    assert pdf.headers["X-Manifest-Hash"] == manifest_hash
    assert manifest_hash in _nospace(text)
    assert proof["proof_fingerprint"] in _nospace(text)
    assert js["report"]["report_proof"] == proof
    # Release decision and rendered verification block agree.
    assert decision_blockers == js["report_state"]["release_blockers"]
    for code in decision_blockers:
        assert code in _nospace(text)
    # Truth-gate fingerprint (which a QUALIFIED decision binds) covers this proof.
    from services.governance.report.result_truth_gate import evaluate_result_truth_gate

    projection = {
        **{k: stored[k] for k in ("tenant_id", "engagement_id")},
        "report_proof": proof,
    }
    a = evaluate_result_truth_gate(
        projection, tenant_id=S.TENANT, engagement_id=eid, raise_on_failure=False
    )
    b = evaluate_result_truth_gate(
        {**projection, "report_proof": {**proof, "proof_fingerprint": "0" * 64}},
        tenant_id=S.TENANT,
        engagement_id=eid,
        raise_on_failure=False,
    )
    assert a.result_fingerprint != b.result_fingerprint


def test_unfinished_job_prevents_full_coverage_through_routes(client):
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaScanJob

    eid = S.create_engagement(client)
    S.seed(eid)
    db = get_sessionmaker()()
    try:
        db.add(
            FaScanJob(
                id="running-job-0001",
                tenant_id=S.TENANT,
                engagement_id=eid,
                verified_target_ids="[]",
                scanner_type="dns_email",
                status="running",
                actor="synthetic-assessor",
                created_at=S.now_iso(),
            )
        )
        db.commit()
    finally:
        db.close()
    rep = S.generate_report(client, eid)
    proof = S.export(client, eid, rep["version"], "json").json()["report"][
        "report_proof"
    ]
    assert proof["coverage"]["unfinished_job_ids"] == ["running-job-0001"]
    assert proof["coverage"]["may_claim_full_coverage"] is False
    assert "SCAN_JOBS_IN_PROGRESS" in proof["release_blockers"]
