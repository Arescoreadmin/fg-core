"""Canonical release decision and evaluator performance — L14-ASSESSMENT-ASSURANCE-001."""

from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient

from tests._assurance_actors import reviewer
from tests.test_assessment_assurance.conftest import (
    QA_SUBJECT,
    code,
    export,
    human,
    qa_approve,
)
from tests.test_customer_zero_e2e import _northstar as N
from tests.test_report_proof import _synthetic as S

RELEASE_TENANT = "tenant-assurance-release"


@pytest.fixture()
def release(build_app, monkeypatch):
    from api.auth_scopes import mint_key

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", S.SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=RELEASE_TENANT,
    )
    author = TestClient(app, headers={"X-API-Key": key})
    qa = TestClient(app, headers={"X-API-Key": key, **reviewer(QA_SUBJECT)})
    eid = S.create_engagement(author, "Assurance Release Org (test fixture)")
    S.seed(
        eid,
        synthetic=False,
        tamper=False,
        failed_job=False,
        tenant=RELEASE_TENANT,
        proof_level="TEST_FIXTURE_ONLY",
    )
    rep = S.generate_report(author, eid)
    return {"author": author, "qa": qa, "eid": eid, "rep": rep}


def _version(c: TestClient, qa: TestClient, eid: str, rid: str) -> str:
    vid = c.post(f"/field-assessment/engagements/{eid}/reports/{rid}/versions").json()[
        "id"
    ]
    c.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review"
    )
    return vid


def test_final_requires_independent_human_qa_and_then_releases(release):
    from tests.test_governed_delivery import _governed_delivery, _inject_qualification

    c, qa, eid, rep = release["author"], release["qa"], release["eid"], release["rep"]
    rid = rep["report_id"]
    vid = _version(c, qa, eid, rid)
    assert qa_approve(qa, eid, rid).status_code == 200
    ok = qa.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json={"reviewer_name": "QA", "reviewer_role": "QA Lead"},
    )
    assert ok.status_code == 200, ok.text
    _inject_qualification(RELEASE_TENANT, eid, rid, vid)
    st = export(c, eid, rep["version"]).json()["report_state"]
    assert st["state"] == "FINAL" and st["independent_qa"] is True
    assert st["provenance"]["decision"] == "VERIFIED"
    # FINAL content is released content: a customer-role caller may read it.
    from api.auth_scopes import mint_key

    viewer = TestClient(
        c.app,
        headers={"X-API-Key": mint_key("governance:read", tenant_id=RELEASE_TENANT)},
    )
    v = export(viewer, eid, rep["version"], "pdf")
    assert v.status_code == 200 and v.headers["X-Report-State"] == "FINAL"
    delivered = _governed_delivery(c, eid, rid, vid, idempotency_key=uuid.uuid4().hex)
    assert delivered.status_code == 200, delivered.text


def test_legacy_service_approval_never_reaches_final(release):
    """A pre-existing API-key approval (no independent human) is not FINAL."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaReportQaDecision
    from api.db_models_governance_report import GovernanceReportRecord
    from tests.test_governed_delivery import _inject_qualification

    c, qa, eid, rep = release["author"], release["qa"], release["eid"], release["rep"]
    rid = rep["report_id"]
    vid = _version(c, qa, eid, rid)
    db = get_sessionmaker()()
    try:
        row = db.get(GovernanceReportRecord, rid)
        row.qa_approved_by, row.qa_approved_at = "legacy-key-prefix", N.now_iso()
        db.add(
            FaReportQaDecision(
                id=uuid.uuid4().hex,
                tenant_id=RELEASE_TENANT,
                engagement_id=eid,
                report_id=rid,
                report_version=1,
                qa_stage="governance",
                decision="approved",
                reviewer_id="legacy-key-prefix",
                actor_type="service",
                created_at=N.now_iso(),
            )
        )
        db.commit()
    finally:
        db.close()
    _inject_qualification(RELEASE_TENANT, eid, rid, vid)
    st = export(c, eid, rep["version"]).json()["report_state"]
    assert st["state"] == "DRAFT"
    assert "QA_INDEPENDENT_APPROVAL_MISSING" in st["release_blockers"]


def test_rejected_report_cannot_be_delivered(release):
    from tests.test_governed_delivery import _governed_delivery, _inject_qualification

    c, qa, eid, rep = release["author"], release["qa"], release["eid"], release["rep"]
    rid = rep["report_id"]
    vid = _version(c, qa, eid, rid)
    ok = qa.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json={"reviewer_name": "QA", "reviewer_role": "QA Lead"},
    )
    assert ok.status_code == 200
    # Governance-stage rejection after the version approval.
    rej = qa.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qa-reject",
        json={
            "reason_code": "COVERAGE_MISSTATED",
            "explanation": "Coverage claim is wrong.",
        },
    )
    assert rej.status_code == 200, rej.text
    _inject_qualification(RELEASE_TENANT, eid, rid, vid)
    d = _governed_delivery(c, eid, rid, vid, idempotency_key=uuid.uuid4().hex)
    assert d.status_code == 422 and code(d) == "REPORT_QA_REJECTED"
    deliver = c.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/deliver",
        json={"recipient_type": "operator_direct", "channel": "direct_download"},
    )
    assert deliver.status_code in (409, 422)
    assert export(c, eid, rep["version"]).json()["report_state"]["state"] == "REJECTED"


def test_synthetic_report_cannot_become_final(platform):
    from tests.test_customer_zero_e2e.test_customer_zero_journey import _engagement
    from tests.test_assessment_assurance.conftest import generate

    eid = _engagement(platform)
    N.seed_collection(eid, tamper=False)
    rep = generate(platform, eid)
    assert qa_approve(human(platform), eid, rep["report_id"]).status_code == 200
    st = export(platform.client("assessor"), eid, rep["version"]).json()["report_state"]
    assert st["state"] == "DRAFT_SYNTHETIC" and st["is_draft"]
    assert st["marking"] == "DRAFT — SYNTHETIC DATA — NOT VERIFIED"


# ── Performance: bounded, batched, no N+1 ────────────────────────────────────


def _bulk_evidence(tenant: str, eid: str, n: int) -> None:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaNormalizedFinding,
        FaScanEvidenceEnvelope,
        FaScanResult,
    )
    from services.field_assessment.evidence_integrity import compute_payload_digest

    hosts = [{"host": f"198.51.100.{i % 250}", "port": 1000 + i} for i in range(n)]
    db = get_sessionmaker()()
    try:
        sr = uuid.uuid4().hex
        db.add(
            FaScanResult(
                id=sr,
                tenant_id=tenant,
                engagement_id=eid,
                source_type="network_scan",
                collected_at=N.now_iso(),
                evidence_hash="0" * 64,
                raw_payload={"hosts": hosts},
                created_at=N.now_iso(),
            )
        )
        for i, h in enumerate(hosts):
            env = uuid.uuid4().hex
            db.add(
                FaScanEvidenceEnvelope(
                    id=env,
                    tenant_id=tenant,
                    engagement_id=eid,
                    scan_result_id=sr,
                    scanner_id="network_scan",
                    collected_at=N.now_iso(),
                    collection_status="COMPLETE",
                    source_type="network_scan",
                    source_id=f"h{i}",
                    observation_path=f"hosts[{i}]",
                    payload_digest=compute_payload_digest(h),
                    provenance_status="VERIFIED_INTEGRITY_ONLY",
                    created_at=N.now_iso(),
                    updated_at=N.now_iso(),
                )
            )
            db.add(
                FaNormalizedFinding(
                    id=uuid.uuid4().hex,
                    tenant_id=tenant,
                    engagement_id=eid,
                    finding_type="network.open_port",
                    findings_hash=uuid.uuid4().hex,
                    severity="medium",
                    title=f"Open port {h['port']}",
                    description="perf fixture",
                    source_attribution="network_scan",
                    evidence_envelope_id=env,
                    created_at=N.now_iso(),
                    updated_at=N.now_iso(),
                )
            )
        db.commit()
    finally:
        db.close()


@pytest.mark.parametrize("n", [14, 100, 500])
def test_provenance_evaluation_is_batched_and_bounded(build_app, n, record_property):
    from sqlalchemy import event

    from api.db import get_engine, get_sessionmaker
    from services.field_assessment.assessment_assurance import (
        evaluate_engagement_provenance,
    )

    build_app(auth_enabled=True)
    eid = f"perf-{n}"
    _bulk_evidence("tenant-perf", eid, n)
    statements: list[str] = []

    def _count(conn, cursor, statement, *a):
        statements.append(statement)

    engine = get_engine()
    event.listen(engine, "before_cursor_execute", _count)
    db = get_sessionmaker()()
    try:
        t0 = time.perf_counter()
        d = evaluate_engagement_provenance(
            db, tenant_id="tenant-perf", engagement_id=eid
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
    finally:
        db.close()
        event.remove(engine, "before_cursor_execute", _count)
    assert d.evidence_count == n and d.integrity_failure_count == 0
    assert d.findings_without_evidence == 0 and d.scope_violation_count == 0
    queries = len([s for s in statements if s.lstrip().upper().startswith("SELECT")])
    record_property("evaluation_ms", round(elapsed_ms, 1))
    record_property("select_queries", queries)
    print(f"\nPERF n={n} evaluation_ms={elapsed_ms:.1f} select_queries={queries}")
    # Constant query count (envelopes, scan results, findings, custody, legacy).
    assert queries <= 6, statements
    assert elapsed_ms < 5000
