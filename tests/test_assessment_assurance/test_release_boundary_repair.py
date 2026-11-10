"""L14-ASSURANCE-P1-REPAIR-001 — rejected reports at the transport boundary.

Codex P1 (#816): an AUTHORIZED governed delivery created before a QA
rejection could still be executed afterwards — ``governed_delivery_execute``
re-checked qualification, recipient and supersession but never the release
gate, so a rejected report's bytes were transported and recorded as
delivered.  These tests drive the real routes on the non-synthetic release
fixture (the canonical gate runs unpatched).
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from tests.test_assessment_assurance.conftest import RELEASE_TENANT, _version, code

_APPROVE = {"reviewer_name": "QA", "reviewer_role": "QA Lead"}


def _authorized_v1(release) -> tuple[TestClient, TestClient, str, str, str, str]:
    """V1 approved by an independent human, qualified, delivery AUTHORIZED."""
    from tests.test_governed_delivery import _inject_qualification

    c, qa, eid, rep = release["author"], release["qa"], release["eid"], release["rep"]
    rid = rep["report_id"]
    v1 = _version(c, qa, eid, rid)
    ok = qa.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v1}/approve",
        json=_APPROVE,
    )
    assert ok.status_code == 200, ok.text
    _inject_qualification(RELEASE_TENANT, eid, rid, v1)
    auth = c.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/governed-delivery",
        json={
            "report_version_id": v1,
            "recipient_type": "operator_direct",
            "channel": "direct_download",
            "idempotency_key": uuid.uuid4().hex,
        },
    )
    assert auth.status_code == 200, auth.text
    dr = auth.json()["receipt"]["delivery_request_id"]
    return c, qa, eid, rid, v1, dr


def _execute(c: TestClient, eid: str, rid: str, dr: str):
    return c.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/governed-delivery/{dr}/execute"
    )


def _delivered_events(rid: str) -> int:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt

    db = get_sessionmaker()()
    try:
        return (
            db.query(FaGovernedDeliveryAttempt)
            .filter(FaGovernedDeliveryAttempt.report_id == rid)
            .count()
        )
    finally:
        db.close()


def test_codex_sequence_rejected_v2_blocks_execution_of_v1_authorization(release):
    """Approve+qualify V1, authorize, then create and reject V2 of the same
    record; executing V1's earlier authorization must be refused."""
    c, qa, eid, rid, _v1, dr = _authorized_v1(release)
    v2 = _version(c, qa, eid, rid)
    rej = qa.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v2}/reject",
        json={
            "reason_code": "FINDING_INACCURATE",
            "explanation": "V2 misstates NSM-3.",
        },
    )
    assert rej.status_code == 200, rej.text
    before = _delivered_events(rid)
    resp = _execute(c, eid, rid, dr)
    assert resp.status_code == 422, (resp.status_code, resp.text[:300])
    assert code(resp) == "REPORT_QA_REJECTED"
    assert not resp.content.startswith(b"%PDF")
    assert _delivered_events(rid) == before  # no transport attempt recorded


def test_governance_stage_rejection_blocks_execution(release):
    c, qa, eid, rid, _v1, dr = _authorized_v1(release)
    rej = qa.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qa-reject",
        json={
            "reason_code": "COVERAGE_MISSTATED",
            "explanation": "Coverage claim is wrong.",
        },
    )
    assert rej.status_code == 200, rej.text
    resp = _execute(c, eid, rid, dr)
    assert resp.status_code == 422 and code(resp) == "REPORT_QA_REJECTED"


def test_evidence_change_after_authorization_blocks_execution(release):
    """The full release gate (not only rejection) runs at the transport boundary."""
    from tests.test_report_proof import _synthetic as S

    c, _qa, eid, rid, _v1, dr = _authorized_v1(release)
    S.tamper_host(S.persisted_scan_id(eid, "network_scan", tenant=RELEASE_TENANT))
    resp = _execute(c, eid, rid, dr)
    assert resp.status_code == 422
    assert code(resp) in ("REPORT_PROOF_BLOCKED", "ASSURANCE_RELEASE_BLOCKED")


def test_unrejected_authorization_still_executes(release):
    """Positive control: the repair must not block a legitimate release."""
    c, _qa, eid, rid, _v1, dr = _authorized_v1(release)
    resp = _execute(c, eid, rid, dr)
    assert resp.status_code == 200, resp.text[:300]
    assert resp.content.startswith(b"%PDF") or resp.content


@pytest.mark.parametrize("route", ["deliver", "governed-delivery"])
def test_other_delivery_routes_refuse_rejected_report(release, route):
    from tests.test_governed_delivery import _inject_qualification

    c, qa, eid, rep = release["author"], release["qa"], release["eid"], release["rep"]
    rid = rep["report_id"]
    v1 = _version(c, qa, eid, rid)
    assert (
        qa.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v1}/approve",
            json=_APPROVE,
        ).status_code
        == 200
    )
    _inject_qualification(RELEASE_TENANT, eid, rid, v1)
    assert (
        qa.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/qa-reject",
            json={
                "reason_code": "OTHER",
                "explanation": "Rejected after approval of V1.",
            },
        ).status_code
        == 200
    )
    if route == "deliver":
        resp = c.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{v1}/deliver",
            json={"recipient_type": "operator_direct", "channel": "direct_download"},
        )
    else:
        resp = c.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/governed-delivery",
            json={
                "report_version_id": v1,
                "recipient_type": "operator_direct",
                "channel": "direct_download",
                "idempotency_key": uuid.uuid4().hex,
            },
        )
    assert resp.status_code == 422 and code(resp) == "REPORT_QA_REJECTED", resp.text
