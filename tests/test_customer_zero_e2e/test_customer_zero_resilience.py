"""Customer-zero failure, recovery and idempotency — L14-CUSTOMER-ZERO-E2E-001.

Every case fails closed through the real routes; nothing is forced to succeed.
"""

from __future__ import annotations

import pytest

from tests.test_customer_zero_e2e import _northstar as N
from tests.test_customer_zero_e2e.test_customer_zero_journey import (
    PORTAL,
    _engagement,
    provision,
)

pytest.importorskip("reportlab")


def _counts(eid: str) -> tuple[int, int, int]:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaNormalizedFinding,
        FaScanEvidenceEnvelope,
        FaScanResult,
    )

    db = get_sessionmaker()()
    try:
        return (
            db.query(FaScanResult)
            .filter_by(tenant_id=N.TENANT, engagement_id=eid)
            .count(),
            db.query(FaNormalizedFinding)
            .filter_by(tenant_id=N.TENANT, engagement_id=eid)
            .count(),
            db.query(FaScanEvidenceEnvelope)
            .filter_by(tenant_id=N.TENANT, engagement_id=eid)
            .count(),
        )
    finally:
        db.close()


def test_repeated_seed_creates_no_duplicates(platform):
    provision(platform, None)
    eid = _engagement(platform)
    N.seed_collection(eid)
    first = _counts(eid)
    # Second full run: provisioning, engagement and collection are idempotent.
    provision(platform, None)
    assert _engagement(platform) == eid
    N.seed_collection(eid)
    assert _counts(eid) == first
    assert first[1] == 14


def test_provisioning_failures_fail_closed(platform):
    bad = platform.admin().post(
        "/admin/tenants", json={"tenant_id": "bad tenant!", "name": "x"}
    )
    assert bad.status_code == 422
    provision(platform, None)
    not_admin = platform.client("assessor").post(
        "/admin/tenants", json={"tenant_id": "synthetic-x", "name": "x"}
    )
    assert not_admin.status_code in (401, 403)
    unknown_role = platform.admin(N.TENANT).post(
        f"/admin/tenants/{N.TENANT}/credentials/{platform.credential_ids['assessor']}/role",
        json={"role": "superuser"},
    )
    assert unknown_role.status_code in (400, 422)


def test_engagement_creation_failures(platform):
    provision(platform, None)
    invalid = platform.client("assessor").post(
        "/field-assessment/engagements", json={"client_name": ""}
    )
    assert invalid.status_code == 422
    unauth = platform.client().post(
        "/field-assessment/engagements",
        json={
            "client_name": "x",
            "assessor_id": "x",
            "assessment_type": "comprehensive",
        },
    )
    assert unauth.status_code in (401, 403)


def test_report_generation_without_signing_authority_fails_closed(
    platform, monkeypatch
):
    provision(platform, None)
    eid = _engagement(platform)
    N.seed_collection(eid)
    import api.field_assessment as fa

    def _unavailable():
        raise ValueError("signing authority unavailable (simulated)")

    monkeypatch.setattr(fa, "_get_trust_binding_authority", _unavailable)
    resp = platform.client("assessor").post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code == 503
    assert "REPORT_SIGNING_KEY_MISSING" in resp.text
    monkeypatch.undo()


def test_corrupt_report_and_missing_artifacts(platform):
    from api.db import get_sessionmaker
    from api.db_models_governance_report import GovernanceReportRecord

    provision(platform, None)
    eid = _engagement(platform)
    N.seed_collection(eid)
    c = platform.client("assessor")
    rep = c.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    ).json()
    missing = c.get(
        f"/field-assessment/engagements/{eid}/reports/999/export",
        params={"format": "pdf"},
    )
    assert missing.status_code == 404
    db = get_sessionmaker()()
    try:
        row = db.get(GovernanceReportRecord, rep["report_id"])
        doc = dict(row.report_json)
        doc["report_proof"] = {**doc["report_proof"], "release_blockers": []}
        row.report_json = doc
        db.commit()
    finally:
        db.close()
    corrupt = c.get(
        f"/field-assessment/engagements/{eid}/reports/{rep['version']}/export",
        params={"format": "pdf"},
    )
    assert (
        corrupt.status_code == 403 and "REPORT_CONTENT_INTEGRITY_FAILED" in corrupt.text
    )


def test_revoked_portal_grant_loses_access(platform):
    provision(platform, None)
    eid = _engagement(platform)
    assessor = platform.client("assessor")
    grant = assessor.post(
        f"/field-assessment/engagements/{eid}/portal-grants", json={"ttl_days": 14}
    ).json()
    session = (
        platform.client("portal_bff")
        .post("/portal/authenticate", json={"secret": grant["raw_secret"]})
        .json()["session_id"]
    )
    cust = platform.client("portal_bff", **PORTAL, **{"X-FG-Portal-Session": session})
    assert cust.get(f"/field-assessment/engagements/{eid}/findings").status_code == 200
    revoke = assessor.delete(
        f"/field-assessment/engagements/{eid}/portal-grants/{grant['grant']['id']}"
    )
    assert revoke.status_code in (200, 204), revoke.text
    after = cust.get(f"/field-assessment/engagements/{eid}/findings")
    assert after.status_code == 403
    reauth = platform.client("portal_bff").post(
        "/portal/authenticate", json={"secret": grant["raw_secret"]}
    )
    assert reauth.status_code == 401


def test_request_correlation_id_is_echoed(platform):
    provision(platform, None)
    resp = platform.client(
        "assessor", **{"X-Request-ID": "cz-e2e-correlation-0001"}
    ).get("/field-assessment/engagements")
    assert resp.status_code == 200
    echoed = {k.lower(): v for k, v in resp.headers.items()}.get("x-request-id")
    assert echoed == "cz-e2e-correlation-0001", dict(resp.headers)
