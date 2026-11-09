"""CZ-12B — separation of duties for every QA decision route and actor type."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.test_assessment_assurance.conftest import (
    QA2_SUBJECT,
    QA_SUBJECT,
    code,
    gateway,
    generate,
    human,
    qa_approve,
    qa_reject,
)
from tests.test_customer_zero_e2e import _northstar as N
from tests.test_customer_zero_e2e.test_customer_zero_journey import _engagement


def _legacy_key(*scopes: str, tenant: str = N.TENANT) -> str:
    from api.auth_scopes import mint_key

    return mint_key(*scopes, tenant_id=tenant)


def test_cz12b_dual_permission_api_key_cannot_self_approve(platform):
    """Exact PR #815 reproduction: generate then qa-approve with one key."""
    eid = _engagement(platform)
    N.seed_collection(eid, tamper=False)
    c = TestClient(
        platform.app,
        headers={
            "X-API-Key": _legacy_key(
                "governance:read", "governance:write", "governance:qa_approve"
            )
        },
    )
    rep = generate(platform, eid, c)
    resp = qa_approve(c, eid, rep["report_id"])
    assert resp.status_code == 403 and code(resp) == "HUMAN_REVIEWER_REQUIRED"
    assert qa_reject(c, eid, rep["report_id"]).status_code == 403


def test_alternate_api_key_cannot_evade_separation_of_duties(platform, northstar_clean):
    """A second key could be held by the same person: no key can attest."""
    other = TestClient(
        platform.app,
        headers={"X-API-Key": _legacy_key("governance:read", "governance:qa_approve")},
    )
    resp = qa_approve(
        other, northstar_clean["eid"], northstar_clean["report"]["report_id"]
    )
    assert resp.status_code == 403 and code(resp) == "HUMAN_REVIEWER_REQUIRED"
    # Canonical role-bound QA persona key (auditor → qa_reviewer) is also a key.
    persona = platform.client("qa_reviewer")
    resp = qa_approve(
        persona, northstar_clean["eid"], northstar_clean["report"]["report_id"]
    )
    assert resp.status_code == 403 and code(resp) == "HUMAN_REVIEWER_REQUIRED"


def test_platform_global_key_cannot_approve(platform, northstar_clean):
    admin = platform.admin()
    resp = qa_approve(
        admin, northstar_clean["eid"], northstar_clean["report"]["report_id"]
    )
    # Global platform key: tenant-unbound and an API key — never a reviewer.
    assert resp.status_code in (400, 401, 403), resp.text


def test_service_principal_is_not_a_reviewer():
    from api.actor_context import ActorContext
    from services.field_assessment.assessment_assurance import (
        AssuranceDenied,
        require_human_reviewer,
    )

    sp = ActorContext(
        subject="auth0|looks-human",
        email="",
        name="",
        permissions=frozenset({"report.qa_approve"}),
        roles=["qa_reviewer"],
        auth_source="oidc_auth0",
        tenant_id=N.TENANT,
        service_principal_id="psp-1",
    )
    with pytest.raises(AssuranceDenied) as exc:
        require_human_reviewer(sp)
    assert exc.value.code == "HUMAN_REVIEWER_REQUIRED"


def test_report_creator_promoted_to_qa_cannot_approve(platform):
    eid = _engagement(platform)
    N.seed_collection(eid, tamper=False)
    author = "auth0|northstar-assessor-human"
    rep = generate(platform, eid, human(platform, author, "assessor"))
    # As assessor the subject lacks QA permission …
    denied = qa_approve(human(platform, author, "assessor"), eid, rep["report_id"])
    assert denied.status_code == 403 and code(denied) == "PERMISSION_DENIED"
    # … and after a role switch / promotion it is still the author.
    resp = qa_approve(human(platform, author, "qa_reviewer"), eid, rep["report_id"])
    assert resp.status_code == 409 and code(resp) == "REPORT_QA_SELF_REVIEW"
    rej = qa_reject(human(platform, author, "qa_reviewer"), eid, rep["report_id"])
    assert rej.status_code == 409 and code(rej) == "REPORT_QA_SELF_REVIEW"


def test_caller_supplied_compiled_by_cannot_launder_authorship(platform):
    eid = _engagement(platform)
    N.seed_collection(eid, tamper=False)
    author = "auth0|northstar-assessor-human"
    r = human(platform, author, "assessor").post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment", "compiled_by": "someone else"},
    )
    assert r.status_code == 201, r.text
    resp = qa_approve(
        human(platform, author, "qa_reviewer"), eid, r.json()["report_id"]
    )
    assert resp.status_code == 409 and code(resp) == "REPORT_QA_SELF_REVIEW"


def test_reviewer_who_materially_modified_findings_cannot_approve(
    platform, northstar_clean
):
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaNormalizedFinding

    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    db = get_sessionmaker()()
    try:
        fid = (
            db.execute(
                select(FaNormalizedFinding.id).where(
                    FaNormalizedFinding.tenant_id == N.TENANT,
                    FaNormalizedFinding.engagement_id == eid,
                )
            )
            .scalars()
            .first()
        )
    finally:
        db.close()
    qa = human(platform, QA_SUBJECT)
    patched = qa.patch(
        f"/field-assessment/engagements/{eid}/findings/{fid}",
        json={
            "status": "false_positive",
            "notes": "reviewer edit",
            "owner_email": "qa@example.test",
        },
    )
    assert patched.status_code == 200, patched.text
    resp = qa_approve(qa, eid, rid)
    assert resp.status_code == 409 and code(resp) == "REPORT_QA_SELF_REVIEW"


def _bind(subjects: list[str]) -> None:
    """One canonical principal signed in through two identity providers."""
    from api.db import get_sessionmaker
    from api.db_models import TenantUser
    from api.db_models_principal import FgPrincipal

    db = get_sessionmaker()()
    try:
        p = FgPrincipal(id=str(uuid.uuid4()), display_name="Pat Example")
        db.add(p)
        db.flush()
        for i, s in enumerate(subjects):
            db.add(
                TenantUser(
                    id=uuid.uuid4().hex,
                    tenant_id=N.TENANT,
                    email=f"pat{i}@example.test",
                    display_name="Pat Example",
                    role="assessor",
                    identity_subject=s,
                    identity_binding_status="bound",
                    principal_id=p.id,
                )
            )
        db.commit()
    finally:
        db.close()


def test_same_principal_via_second_identity_provider_cannot_approve(platform):
    auth0, entra = "auth0|pat-example", "entra|7f3c-pat-example"
    _bind([auth0, entra])
    eid = _engagement(platform)
    N.seed_collection(eid, tamper=False)
    rep = generate(platform, eid, human(platform, auth0, "assessor"))
    resp = qa_approve(human(platform, entra, "qa_reviewer"), eid, rep["report_id"])
    assert resp.status_code == 409 and code(resp) == "REPORT_QA_SELF_REVIEW"


def test_cross_tenant_and_cross_engagement_reviewers_are_denied(
    platform, northstar_clean
):
    from tests.test_customer_zero_e2e.test_customer_zero_journey import provision

    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    provision(platform, None, N.OTHER_TENANT, "Contoso Other (synthetic)")
    foreign = human(platform, QA_SUBJECT, tenant_id=N.OTHER_TENANT)
    assert qa_approve(foreign, eid, rid).status_code == 404
    other_eid = (
        human(platform, "auth0|other-assessor", "assessor")
        .post(
            "/field-assessment/engagements",
            json={
                "client_name": "Unrelated (synthetic)",
                "assessor_id": "x",
                "assessment_type": "comprehensive",
            },
        )
        .json()["id"]
    )
    assert qa_approve(human(platform), other_eid, rid).status_code == 404


def test_independent_named_reviewer_can_approve(platform, northstar_clean):
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaEngagementAuditEvent,
        FaReportQaDecision,
    )

    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    resp = qa_approve(human(platform), eid, rid)
    assert resp.status_code == 200, resp.text
    assert resp.json()["qa_approved_by"] == QA_SUBJECT
    db = get_sessionmaker()()
    try:
        dec = db.execute(
            select(FaReportQaDecision).where(FaReportQaDecision.report_id == rid)
        ).scalar_one()
        assert (dec.decision, dec.actor_type, dec.reviewer_id) == (
            "approved",
            "human",
            QA_SUBJECT,
        )
        ev = db.execute(
            select(FaEngagementAuditEvent).where(
                FaEngagementAuditEvent.event_type == "report.qa_approved",
                FaEngagementAuditEvent.entity_id == rid,
            )
        ).scalar_one()
        assert ev.payload["independence"]["reviewer_subject"] == QA_SUBJECT
        assert ev.payload["provenance"]["decision"] == "VERIFIED"
        assert "X-API-Key" not in str(ev.payload)
    finally:
        db.close()
    # Replay / second reviewer: exactly one approval.
    again = qa_approve(human(platform, QA2_SUBJECT), eid, rid)
    assert again.status_code == 409 and code(again) == "REPORT_ALREADY_APPROVED"


def test_version_approval_requires_independent_human(platform, northstar_clean):
    eid, rid = northstar_clean["eid"], northstar_clean["report"]["report_id"]
    assessor = platform.client("assessor")
    vid = assessor.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions"
    ).json()["id"]
    body = {"reviewer_name": "x", "reviewer_role": "QA"}
    approve = (
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve"
    )
    # Stale state: a draft (not submitted) version cannot be approved.
    assert human(platform).post(approve, json=body).status_code == 409
    assessor.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review"
    )
    k = gateway(platform)
    assert k.post(approve, json=body).status_code == 403  # API key
    ok = human(platform).post(approve, json=body)
    assert ok.status_code == 200 and ok.json()["approved_by"] == QA_SUBJECT


def test_identity_resolution_failure_fails_closed(
    platform, northstar_clean, monkeypatch
):
    import services.field_assessment.assessment_assurance as A

    def _boom(*a, **k):
        raise A.AssuranceDenied(503, "QA_IDENTITY_RESOLUTION_UNAVAILABLE", "x")

    monkeypatch.setattr(A, "reviewer_identity_set", _boom)
    resp = qa_approve(
        human(platform), northstar_clean["eid"], northstar_clean["report"]["report_id"]
    )
    assert (
        resp.status_code == 503 and code(resp) == "QA_IDENTITY_RESOLUTION_UNAVAILABLE"
    )
