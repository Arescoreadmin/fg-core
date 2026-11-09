"""Canonical QA rejection and rework — L14-ASSESSMENT-ASSURANCE-001."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from tests.test_assessment_assurance.conftest import (
    QA2_SUBJECT,
    QA_SUBJECT,
    code,
    export,
    gateway,
    generate,
    human,
    qa_approve,
    qa_reject,
)
from tests.test_customer_zero_e2e import _northstar as N


def _decisions(rid: str) -> list:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaReportQaDecision

    db = get_sessionmaker()()
    try:
        return list(
            db.execute(
                select(FaReportQaDecision).where(FaReportQaDecision.report_id == rid)
            ).scalars()
        )
    finally:
        db.close()


def test_authorized_rejection_is_recorded_and_audited(platform, northstar):
    """A tampered report cannot be approved — but it can be formally rejected."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaEngagementAuditEvent

    eid, rid = northstar["eid"], northstar["report"]["report_id"]
    resp = qa_reject(human(platform), eid, rid, reason_code="evidence_integrity")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (
        body["decision"] == "rejected" and body["reason_code"] == "EVIDENCE_INTEGRITY"
    )
    assert body["rejected_by"] == QA_SUBJECT and body["proof_fingerprint"]
    [dec] = _decisions(rid)
    assert (dec.decision, dec.actor_type, dec.qa_stage) == (
        "rejected",
        "human",
        "governance",
    )
    assert dec.reason.startswith("EVIDENCE_INTEGRITY: ")
    db = get_sessionmaker()()
    try:
        ev = db.execute(
            select(FaEngagementAuditEvent).where(
                FaEngagementAuditEvent.event_type == "report.qa_rejected"
            )
        ).scalar_one()
        assert ev.actor == QA_SUBJECT and ev.entity_id == rid
        assert ev.payload["rejection_reason_code"] == "EVIDENCE_INTEGRITY"
        assert ev.payload["proof_fingerprint"] == body["proof_fingerprint"]
    finally:
        db.close()


@pytest.mark.parametrize(
    "body,status,err",
    [
        ({"reason_code": "NOPE"}, 422, "INVALID_REJECTION_REASON"),
        ({"explanation": "short"}, 422, None),
        ({"explanation": "          x"}, 422, "REJECTION_EXPLANATION_REQUIRED"),
    ],
)
def test_rejection_requires_an_attributable_reason(
    platform, northstar_clean, body, status, err
):
    resp = qa_reject(
        human(platform),
        northstar_clean["eid"],
        northstar_clean["report"]["report_id"],
        **body,
    )
    assert resp.status_code == status
    if err:
        assert code(resp) == err


def test_unauthorized_rejection_is_denied(platform, northstar_clean):
    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    assert qa_reject(platform.client("assessor"), eid, rid).status_code == 403
    viewer = human(platform, "auth0|customer-exec", "client_executive")
    assert qa_reject(viewer, eid, rid).status_code == 403
    assert qa_reject(gateway(platform), eid, rid).status_code == 403  # API key


def test_rejected_report_cannot_be_approved_final_or_revived(platform, northstar_clean):
    eid, rep = northstar_clean["eid"], northstar_clean["report"]
    rid = rep["report_id"]
    assert qa_reject(human(platform), eid, rid).status_code == 200
    # Stale approval by a different independent reviewer.
    late = qa_approve(human(platform, QA2_SUBJECT), eid, rid)
    assert late.status_code == 409 and code(late) == "REPORT_QA_REJECTED"
    # Double rejection / replay.
    again = qa_reject(human(platform, QA2_SUBJECT), eid, rid)
    assert again.status_code == 409 and code(again) == "REPORT_QA_DECISION_REPLAY"
    # Revival through a new version of the same record.
    v = platform.client("assessor").post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions"
    )
    assert v.status_code == 409 and code(v) == "REPORT_QA_REJECTED"
    # Authoritative state; no request parameter changes it.
    for params in ({}, {"state": "FINAL"}, {"allow_draft": "true"}):
        r = platform.client("assessor").get(
            f"/field-assessment/engagements/{eid}/reports/{rep['version']}/export",
            params={"format": "json", **params},
        )
        st = r.json()["report_state"]
        assert st["state"] == "REJECTED" and st["is_draft"] and st["qa_rejected"]
    pdf = export(platform.client("assessor"), eid, rep["version"], "pdf")
    assert pdf.headers["X-Report-State"] == "REJECTED"
    assert "rejected" in pdf.headers["Content-Disposition"]
    assert pdf.content.startswith(b"%PDF")


def test_approved_report_cannot_be_rejected(platform, northstar_clean):
    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    assert qa_approve(human(platform), eid, rid).status_code == 200
    resp = qa_reject(human(platform, QA2_SUBJECT), eid, rid)
    assert resp.status_code == 409 and code(resp) == "REPORT_ALREADY_APPROVED"


def test_rework_creates_corrected_report_with_fresh_review(platform, northstar_clean):
    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    assessor = platform.client("assessor")
    vid = assessor.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions"
    ).json()["id"]
    assessor.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review"
    )
    rej = human(platform).post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/reject",
        json={
            "reason_code": "SEVERITY_INCORRECT",
            "explanation": "NSM-1 should be high.",
        },
    )
    assert rej.status_code == 200 and rej.json()["report_version_id"] == vid
    got = assessor.get(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}"
    ).json()
    assert got["status"] == "rejected"
    # Rejected version is immutable: approve / submit refused.
    approve = human(platform, QA2_SUBJECT).post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json={"reviewer_name": "x", "reviewer_role": "QA"},
    )
    assert approve.status_code == 409
    # Rework: corrected report → new record, new version linked to the rejection.
    fixed = generate(platform, eid)
    assert fixed["report_id"] != rid
    nv = assessor.post(
        f"/field-assessment/engagements/{eid}/reports/{fixed['report_id']}/versions"
    )
    assert nv.status_code == 201
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaReportVersion

    db = get_sessionmaker()()
    try:
        row = db.get(FaReportVersion, nv.json()["id"])
        assert row.parent_version_id == vid and row.approved_by is None
        assert db.get(FaReportVersion, vid).status == "rejected"  # history kept
    finally:
        db.close()
    # The old approval/rejection never transfers: the new record needs its own.
    st = export(assessor, eid, fixed["version"]).json()["report_state"]
    assert st["qa_approved"] is False and st["qa_rejected"] is False


def test_concurrent_approve_and_reject_resolve_to_one_decision(
    platform, northstar_clean, monkeypatch
):
    """Approval racing a rejection: the DB index (migration 0205) lets one win."""
    import api.field_assessment as fa

    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    assert qa_reject(human(platform), eid, rid).status_code == 200
    # Simulate the losing request having passed its pre-checks before the
    # rejection committed.
    monkeypatch.setattr(fa, "_refuse_if_qa_rejected", lambda *a, **k: None)
    real = fa._record_report_qa_decision

    def _race(db, **kw):  # skip the in-process replay read; rely on the DB index
        from api.db_models_field_assessment import FaReportQaDecision
        import uuid

        db.add(
            FaReportQaDecision(
                id=uuid.uuid4().hex,
                tenant_id=kw["tenant_id"],
                engagement_id=kw["engagement_id"],
                report_id=kw["report_id"],
                report_version_id=None,
                report_version=kw["report_version"],
                qa_stage=kw["qa_stage"],
                decision=kw["decision"],
                reviewer_id=kw["reviewer_id"],
                actor_type=kw["actor_type"],
                created_at=N.now_iso(),
            )
        )
        try:
            db.flush()
        except Exception as exc:
            db.rollback()
            from fastapi import HTTPException

            raise HTTPException(
                status_code=409, detail={"code": "REPORT_QA_DECISION_REPLAY"}
            ) from exc
        return real  # pragma: no cover

    monkeypatch.setattr(fa, "_record_report_qa_decision", _race)
    resp = qa_approve(human(platform, QA2_SUBJECT), eid, rid)
    assert resp.status_code == 409
    decisions = _decisions(rid)
    assert [d.decision for d in decisions] == ["rejected"]
    from api.db import get_sessionmaker
    from api.db_models_governance_report import GovernanceReportRecord

    db = get_sessionmaker()()
    try:
        assert db.get(GovernanceReportRecord, rid).qa_approved_by is None  # rolled back
    finally:
        db.close()


def test_governance_stage_unique_index_exists(platform, northstar_clean):
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaReportQaDecision
    from sqlalchemy.exc import IntegrityError
    import uuid

    rid = northstar_clean["report"]["report_id"]
    db = get_sessionmaker()()
    try:
        for decision in ("approved", "rejected"):
            db.add(
                FaReportQaDecision(
                    id=uuid.uuid4().hex,
                    tenant_id=N.TENANT,
                    engagement_id=northstar_clean["eid"],
                    report_id=rid,
                    report_version_id=None,
                    report_version=1,
                    qa_stage="governance",
                    decision=decision,
                    reviewer_id=QA_SUBJECT,
                    actor_type="human",
                    created_at=N.now_iso(),
                )
            )
        with pytest.raises(IntegrityError):
            db.flush()
    finally:
        db.rollback()
        db.close()
