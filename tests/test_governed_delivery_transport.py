"""tests/test_governed_delivery_transport.py — GOV-DELIVERY-TRANSPORT-001.

Adversarial test suite for the governed delivery transport authority.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

The tests here exercise the ``/governed-delivery/{id}/execute`` route that
binds a governed authorization to real transport-attempt evidence. They
enforce the non-negotiable invariants:

    authorization is not transport
    transport attempt is not provider acceptance
    provider acceptance is not delivery
    delivery is not receipt

Coverage:

    T1  — no AUTHORIZED authorization → 404/409
    T2  — empty fingerprint → 422
    T3  — stale qualification → 422 STALE_QUALIFICATION
    T4  — superseded report version → 422 SUPERSEDED_REPORT
    T5  — revoked recipient → 403
    T6  — cross-tenant probe → 404
    T7  — successful operator_direct happy path
    T8  — attempt row is append-only (UPDATE/DELETE raise)
    T9  — duplicate execute is idempotent (single attempt row)
    T10 — provider failure records FAILED, does not mark delivered
    T11 — portal_membership recipient returns 501 TRANSPORT_NOT_IMPLEMENTED
    T12 — attempt rows are tenant-isolated
    T13 — authorization creation route does not mark 'delivered'
    T14 — commit failure after SUCCEEDED row flush yields no artifact bytes
    T15 — response bytes hash matches the persisted attempt's artifact_sha256
    T16 — every X-FG-* response header matches the persisted attempt row
    T17 — no secret-bearing metadata appears in response headers
    T18 — non-ASCII actor subject does not permanently lock out the operator
"""

from __future__ import annotations

import os
import uuid

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient

_TENANT_A = "tenant-gov-del-tx-A"
_TENANT_B = "tenant-gov-del-tx-B"
_SIGNING_KEY_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"

_ENGAGEMENT_BODY = {
    "client_name": "Governed Delivery Transport Corp",
    "assessor_id": "assessor-gov-del-tx-001",
    "assessment_type": "ai_governance",
}

_APPROVAL_BODY = {
    "reviewer_name": "QA Reviewer",
    "reviewer_role": "QA Lead",
    "approval_notes": "LGTM",
    "signature_placeholder": "sig-v1",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app, monkeypatch):
    """Tenant A actor — governance:write + governance:qa_approve."""
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
    """Tenant B actor — cross-tenant isolation probe."""
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
# Helpers (deliberately duplicated from test_governed_delivery.py to keep this
# suite self-contained for the transport authority.)
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


def _create_version(client: TestClient, eid: str, rid: str) -> str:
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions",
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _submit(client: TestClient, eid: str, rid: str, vid: str) -> None:
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/submit-for-review",
    )
    assert resp.status_code == 200, resp.text


def _approve_version(client: TestClient, eid: str, rid: str, vid: str) -> None:
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
        json=_APPROVAL_BODY,
    )
    assert resp.status_code == 200, resp.text


def _bootstrap_approved_version(client: TestClient) -> tuple[str, str, str]:
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)
    vid = _create_version(client, eid, rid)
    _submit(client, eid, rid, vid)
    _approve_version(client, eid, rid, vid)
    return eid, rid, vid


def _get_report_fingerprint(rid: str) -> str:
    from api.db import get_sessionmaker
    from api.db_models_governance_report import GovernanceReportRecord
    from sqlalchemy import select as _sel

    sm = get_sessionmaker()()
    try:
        record = sm.execute(
            _sel(GovernanceReportRecord).where(GovernanceReportRecord.id == rid)
        ).scalar_one()
        truth_gate = (record.report_json or {}).get("result_truth_gate") or {}
        fp = truth_gate.get("result_fingerprint") or ""
        assert fp, f"Report {rid} has no result_fingerprint in truth_gate"
        return fp
    finally:
        sm.close()


def _inject_qualification(
    tenant_id: str,
    eid: str,
    rid: str,
    vid: str,
    report_fingerprint: str | None = None,
) -> str:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaProductionQualRequest,
        FaQualificationDecision,
    )

    if report_fingerprint is None:
        report_fingerprint = _get_report_fingerprint(rid)

    sm = get_sessionmaker()()
    try:
        qid = uuid.uuid4().hex
        dec_id = uuid.uuid4().hex
        req_row = FaProductionQualRequest(
            id=qid,
            tenant_id=tenant_id,
            engagement_id=eid,
            report_id=rid,
            requested_by="test-injector",
            actor_type="service",
            requested_at="2026-09-29T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(req_row)
        sm.flush()
        dec_row = FaQualificationDecision(
            id=dec_id,
            tenant_id=tenant_id,
            engagement_id=eid,
            report_id=rid,
            qual_request_id=qid,
            report_version_id=vid,
            report_fingerprint=report_fingerprint,
            decision="QUALIFIED",
            decided_by="test-injector",
            actor_type="service",
            reason=None,
            decided_at="2026-09-29T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(dec_row)
        sm.commit()
        return dec_id
    finally:
        sm.close()


def _monkeypatch_require_qualified(monkeypatch: pytest.MonkeyPatch) -> None:
    def _patched(report_json, db, *, report_id, tenant_id, report_version_id):
        from sqlalchemy import select as _select
        from api.db_models_field_assessment import FaQualificationDecision as _FQD
        from fastapi import HTTPException
        from api.error_contracts import api_error

        truth_gate = (report_json or {}).get("result_truth_gate") or {}
        fp = truth_gate.get("result_fingerprint") or ""
        decision = db.execute(
            _select(_FQD).where(
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
                detail=api_error(
                    "PRODUCTION_QUALIFICATION_BLOCKED", "no QUALIFIED decision"
                ),
            )

    monkeypatch.setattr("api.field_assessment._require_production_qualified", _patched)


def _authorize(
    client: TestClient,
    eid: str,
    rid: str,
    vid: str,
    *,
    recipient_type: str = "operator_direct",
    recipient_id: str | None = None,
    channel: str = "direct_download",
) -> dict:
    body: dict = {
        "report_version_id": vid,
        "recipient_type": recipient_type,
        "channel": channel,
    }
    if recipient_id is not None:
        body["recipient_id"] = recipient_id
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/governed-delivery",
        json=body,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _execute(client: TestClient, eid: str, rid: str, delivery_request_id: str):
    return client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}"
        f"/governed-delivery/{delivery_request_id}/execute",
    )


def _err(resp) -> str:
    return (resp.json().get("detail") or {}).get("code", "")


# ---------------------------------------------------------------------------
# T1 — no authorization → cannot transport
# ---------------------------------------------------------------------------


def test_t1_no_authorization_no_transport(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute on an unknown delivery_request_id → 404."""
    eid, rid, _vid = _bootstrap_approved_version(client)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _execute(client, eid, rid, uuid.uuid4().hex)
    assert resp.status_code == 404
    assert _err(resp) == "DELIVERY_REQUEST_NOT_FOUND"


# ---------------------------------------------------------------------------
# T2 — empty fingerprint boundary
# ---------------------------------------------------------------------------


def test_t2_empty_fingerprint_blocked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A delivery request with empty fingerprint cannot be executed → 422.

    This should be unreachable in normal flow (the authorization route
    requires a non-empty fingerprint), but the execute boundary must still
    fail closed if the row exists.
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaGovernedDeliveryAuthorization,
        FaGovernedDeliveryRequest,
    )

    eid, rid, vid = _bootstrap_approved_version(client)
    dec_id = _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    # Direct-insert a request+authorization with empty fingerprint.
    sm = get_sessionmaker()()
    try:
        req_id = uuid.uuid4().hex
        auth_id = uuid.uuid4().hex
        req = FaGovernedDeliveryRequest(
            id=req_id,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            report_id=rid,
            report_version_id=vid,
            report_fingerprint="",  # forced empty
            qualification_decision_id=dec_id,
            requested_by="injector",
            actor_type="service",
            recipient_type="operator_direct",
            recipient_id=None,
            channel="direct_download",
            idempotency_key=f"forced-empty-{uuid.uuid4().hex}",
            requested_at="2026-09-29T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(req)
        sm.flush()
        auth = FaGovernedDeliveryAuthorization(
            id=auth_id,
            tenant_id=_TENANT_A,
            engagement_id=eid,
            delivery_request_id=req_id,
            report_id=rid,
            report_version_id=vid,
            report_fingerprint="",
            qualification_decision_id=dec_id,
            recipient_type="operator_direct",
            recipient_id=None,
            channel="direct_download",
            authorized_by="injector",
            actor_type="service",
            outcome="AUTHORIZED",
            rejection_reason_code=None,
            authorized_at="2026-09-29T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(auth)
        sm.commit()
    finally:
        sm.close()

    resp = _execute(client, eid, rid, req_id)
    assert resp.status_code == 422
    assert _err(resp) == "MISSING_REPORT_FINGERPRINT"


# ---------------------------------------------------------------------------
# T3 — stale qualification
# ---------------------------------------------------------------------------


def test_t3_stale_qualification_blocked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delete the QUALIFIED decision after authorize → execute returns 422."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaQualificationDecision
    from sqlalchemy import delete as _delete

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    # Remove qualification row directly (simulating stale binding).
    sm = get_sessionmaker()()
    try:
        sm.execute(
            _delete(FaQualificationDecision).where(
                FaQualificationDecision.tenant_id == _TENANT_A,
                FaQualificationDecision.report_id == rid,
                FaQualificationDecision.report_version_id == vid,
            )
        )
        sm.commit()
    finally:
        sm.close()

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 422
    assert _err(resp) == "STALE_QUALIFICATION"


# ---------------------------------------------------------------------------
# T4 — superseded report version
# ---------------------------------------------------------------------------


def test_t4_superseded_report_blocked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the underlying report version disappears, execute fails."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaReportVersion
    from sqlalchemy import delete as _delete

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    # Hard-delete the report version to simulate a superseded/removed state.
    sm = get_sessionmaker()()
    try:
        sm.execute(
            _delete(FaReportVersion).where(
                FaReportVersion.tenant_id == _TENANT_A,
                FaReportVersion.id == vid,
            )
        )
        sm.commit()
    finally:
        sm.close()

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 422
    assert _err(resp) == "SUPERSEDED_REPORT"


# ---------------------------------------------------------------------------
# T5 — revoked recipient
# ---------------------------------------------------------------------------


def test_t5_revoked_recipient_blocked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revoke the recipient portal_grant between authorize and execute → 403."""
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrant

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    # Create an active portal_grant recipient.
    sm = get_sessionmaker()()
    try:
        grant_id = uuid.uuid4().hex
        sm.add(
            PortalGrant(
                id=grant_id,
                tenant_id=_TENANT_A,
                client_id="revoke-corp",
                engagement_id=eid,
                grant_hash="revoketesthash",
                created_by="test-actor",
                created_at="2026-09-29T00:00:00Z",
                expires_at="2027-09-29T00:00:00Z",
                status="active",
            )
        )
        sm.commit()
    finally:
        sm.close()

    auth = _authorize(
        client,
        eid,
        rid,
        vid,
        recipient_type="portal_grant",
        recipient_id=grant_id,
        channel="portal_grant",
    )
    request_id = auth["receipt"]["delivery_request_id"]

    # Revoke the grant.
    sm = get_sessionmaker()()
    try:
        row = sm.get(PortalGrant, grant_id)
        assert row is not None
        row.status = "revoked"
        sm.commit()
    finally:
        sm.close()

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code in (403, 404)


# ---------------------------------------------------------------------------
# T6 — cross-tenant probe
# ---------------------------------------------------------------------------


def test_t6_wrong_tenant_blocked(
    client: TestClient,
    client_b: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant B cannot execute a delivery_request created for tenant A → 404."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    # Tenant B probes the same route — no oracle: uniform 404.
    resp = _execute(client_b, eid, rid, request_id)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# T7 — successful operator_direct happy path
# ---------------------------------------------------------------------------


def test_t7_successful_operator_direct(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Happy path: authorize + execute serves artifact bytes with receipt headers.

    GOV-DELIVERY-TRANSPORT-001 correction: the /execute response body IS the
    artifact bytes (not a JSON receipt). The receipt metadata is surfaced via
    ``X-FG-*`` response headers so the operator can bind the received bytes
    to the attempt/authorization/request ids.
    """
    import hashlib as _hashlib

    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaGovernedDeliveryAttempt,
        FaReportVersion,
    )
    from sqlalchemy import select as _select

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 200, resp.text

    # Body is the actual artifact bytes.
    assert resp.content, "operator_direct /execute must return non-empty bytes"
    assert resp.headers["content-type"].startswith("application/json"), (
        f"unexpected content-type: {resp.headers['content-type']}"
    )

    # Receipt metadata surfaced in X-FG-* headers.
    assert resp.headers["x-fg-outcome"] == "SUCCEEDED"
    assert resp.headers["x-fg-transport-type"] == "operator_direct"
    assert resp.headers["x-fg-delivery-request-id"] == request_id
    attempt_id = resp.headers["x-fg-delivery-attempt-id"]
    assert attempt_id, "delivery attempt id header must be non-empty"
    sha_header = resp.headers["x-fg-artifact-sha256"]
    assert sha_header and len(sha_header) == 64
    # Header sha256 must actually match the served bytes.
    assert _hashlib.sha256(resp.content).hexdigest() == sha_header, (
        "artifact bytes must hash to the sha256 declared in the receipt header"
    )
    assert int(resp.headers["x-fg-artifact-bytes"]) == len(resp.content)

    # Attempt row exists.
    sm = get_sessionmaker()()
    try:
        row = sm.execute(
            _select(FaGovernedDeliveryAttempt).where(
                FaGovernedDeliveryAttempt.id == attempt_id,
            )
        ).scalar_one_or_none()
        assert row is not None
        assert row.outcome == "SUCCEEDED"
        assert row.tenant_id == _TENANT_A
        # Report version transitioned to 'delivered' after SUCCEEDED attempt.
        rv = sm.execute(
            _select(FaReportVersion).where(FaReportVersion.id == vid)
        ).scalar_one()
        assert rv.status == "delivered"
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T8 — attempt row is append-only
# ---------------------------------------------------------------------------


def test_t8_attempt_is_append_only(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Direct-ORM UPDATE/DELETE of an attempt row raises RuntimeError."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]
    exec_resp = _execute(client, eid, rid, request_id)
    assert exec_resp.status_code == 200
    attempt_id = exec_resp.headers["x-fg-delivery-attempt-id"]

    sm = get_sessionmaker()()
    try:
        row = sm.get(FaGovernedDeliveryAttempt, attempt_id)
        assert row is not None
        row.failure_code = "TAMPER"
        with pytest.raises(RuntimeError):
            sm.commit()
        sm.rollback()

        row2 = sm.get(FaGovernedDeliveryAttempt, attempt_id)
        assert row2 is not None
        sm.delete(row2)
        with pytest.raises(RuntimeError):
            sm.commit()
        sm.rollback()
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T9 — duplicate execute is idempotent
# ---------------------------------------------------------------------------


def test_t9_duplicate_execute_idempotent(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Second execute on a SUCCEEDED authorization → 409, bytes are NOT re-served.

    The transport authority serves the artifact bytes exactly once, at the
    moment the SUCCEEDED attempt row is written. A repeat call must return
    409 ``DELIVERY_ALREADY_EXECUTED`` (with a JSON error body) so the
    transport endpoint cannot be replayed as a post-hoc download.
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt
    from sqlalchemy import select as _select

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]
    auth_id = auth["receipt"]["delivery_authorization_id"]

    resp1 = _execute(client, eid, rid, request_id)
    assert resp1.status_code == 200, resp1.text
    winning_attempt_id = resp1.headers["x-fg-delivery-attempt-id"]

    resp2 = _execute(client, eid, rid, request_id)
    assert resp2.status_code == 409, resp2.text
    assert _err(resp2) == "DELIVERY_ALREADY_EXECUTED"
    # The 409 body must name the winning attempt so the caller can bind their
    # state; and must NOT re-serve the artifact bytes.
    detail = (resp2.json().get("detail") or {}).get("message", "")
    assert winning_attempt_id in detail

    sm = get_sessionmaker()()
    try:
        rows = (
            sm.execute(
                _select(FaGovernedDeliveryAttempt).where(
                    FaGovernedDeliveryAttempt.authorization_id == auth_id,
                    FaGovernedDeliveryAttempt.outcome == "SUCCEEDED",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].id == winning_attempt_id
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T10 — provider failure records FAILED, does not mark delivered
# ---------------------------------------------------------------------------


def test_t10_provider_failure_not_succeeded(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate a transport error → attempt row FAILED, version not delivered."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaGovernedDeliveryAttempt,
        FaReportVersion,
    )
    from sqlalchemy import select as _select

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]
    auth_id = auth["receipt"]["delivery_authorization_id"]

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated provider outage")

    monkeypatch.setattr(
        "api.field_assessment._render_operator_direct_artifact_bytes", _boom
    )

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 502
    assert _err(resp) == "DELIVERY_TRANSPORT_FAILED"

    sm = get_sessionmaker()()
    try:
        rows = (
            sm.execute(
                _select(FaGovernedDeliveryAttempt).where(
                    FaGovernedDeliveryAttempt.authorization_id == auth_id,
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].outcome == "FAILED"
        assert rows[0].failure_code == "ARTIFACT_RENDER_ERROR"
        # Report version is NOT delivered.
        rv = sm.execute(
            _select(FaReportVersion).where(FaReportVersion.id == vid)
        ).scalar_one()
        assert rv.status != "delivered"
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T11 — portal_membership recipient not yet implemented
# ---------------------------------------------------------------------------


def test_t11_portal_type_returns_not_implemented(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """portal_grant/portal_membership transport → 501 TRANSPORT_NOT_IMPLEMENTED."""
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrant

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    sm = get_sessionmaker()()
    try:
        grant_id = uuid.uuid4().hex
        sm.add(
            PortalGrant(
                id=grant_id,
                tenant_id=_TENANT_A,
                client_id="portal-corp",
                engagement_id=eid,
                grant_hash="portalhash",
                created_by="test-actor",
                created_at="2026-09-29T00:00:00Z",
                expires_at="2027-09-29T00:00:00Z",
                status="active",
            )
        )
        sm.commit()
    finally:
        sm.close()

    auth = _authorize(
        client,
        eid,
        rid,
        vid,
        recipient_type="portal_grant",
        recipient_id=grant_id,
        channel="portal_grant",
    )
    request_id = auth["receipt"]["delivery_request_id"]

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 501
    assert _err(resp) == "TRANSPORT_NOT_IMPLEMENTED"


# ---------------------------------------------------------------------------
# T12 — attempt rows are tenant-isolated
# ---------------------------------------------------------------------------


def test_t12_attempt_rls_tenant_isolation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attempt rows written for tenant A are not visible when filtering by tenant B."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt
    from sqlalchemy import select as _select

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]
    exec_resp = _execute(client, eid, rid, request_id)
    assert exec_resp.status_code == 200
    attempt_id = exec_resp.headers["x-fg-delivery-attempt-id"]

    sm = get_sessionmaker()()
    try:
        # Filter by tenant_B — must not see tenant_A's attempt row.
        found = sm.execute(
            _select(FaGovernedDeliveryAttempt).where(
                FaGovernedDeliveryAttempt.tenant_id == _TENANT_B,
                FaGovernedDeliveryAttempt.id == attempt_id,
            )
        ).scalar_one_or_none()
        assert found is None
        # Sanity: filter by tenant_A finds it.
        found_a = sm.execute(
            _select(FaGovernedDeliveryAttempt).where(
                FaGovernedDeliveryAttempt.tenant_id == _TENANT_A,
                FaGovernedDeliveryAttempt.id == attempt_id,
            )
        ).scalar_one_or_none()
        assert found_a is not None
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T13 — authorization route does not mark 'delivered'
# ---------------------------------------------------------------------------


def test_t13_authorization_required_not_attempt(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /governed-delivery does NOT set report_version.status='delivered'.

    Only the /execute endpoint may mark the version delivered, and only after
    a SUCCEEDED attempt row has been written.
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaReportVersion
    from sqlalchemy import select as _select

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth_resp = _authorize(client, eid, rid, vid)
    assert auth_resp["version"]["status"] == "approved"

    sm = get_sessionmaker()()
    try:
        rv = sm.execute(
            _select(FaReportVersion).where(FaReportVersion.id == vid)
        ).scalar_one()
        assert rv.status == "approved"
        assert rv.delivered_at in (None, "")
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T14 — commit failure after SUCCEEDED row flush yields no artifact bytes
# ---------------------------------------------------------------------------


def test_t14_commit_failure_no_bytes_returned(
    build_app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DB commit failure after the SUCCEEDED attempt row is flushed must
    NOT produce a 200 with artifact bytes, and must NOT leave a committed
    SUCCEEDED row behind.

    This is the critical epistemic invariant of GOV-DELIVERY-TRANSPORT-001:
    the operator can only observe a SUCCEEDED response after the attempt
    row is durably persisted. If persistence fails, the operator sees a
    5xx and the artifact bytes stay inside the process.
    """
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt
    from sqlalchemy import select as _select

    # Rebuild the test client with raise_server_exceptions=False so the
    # unhandled commit failure is observable as a 5xx response rather than
    # re-raised into the test frame.
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", _SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=_TENANT_A,
    )
    client_no_reraise = TestClient(
        app,
        headers={"X-API-Key": key},
        raise_server_exceptions=False,
    )

    eid, rid, vid = _bootstrap_approved_version(client_no_reraise)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client_no_reraise, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]
    auth_id = auth["receipt"]["delivery_authorization_id"]

    # Force the pre-response persistence path to fail after the attempt row
    # has been added+flushed by the route. Raising here proves that any
    # failure between the SUCCEEDED-row flush and the Response return
    # prevents bytes from escaping — the same guarantee a commit failure
    # provides, since db.commit() runs after this call.
    def _boom_audit(*args, **kwargs):
        raise RuntimeError("simulated commit-adjacent failure")

    monkeypatch.setattr("api.field_assessment.emit_engagement_audit_event", _boom_audit)

    resp = _execute(client_no_reraise, eid, rid, request_id)

    # Non-2xx: no artifact bytes were served to the operator.
    assert resp.status_code >= 500, resp.text
    assert "x-fg-artifact-sha256" not in resp.headers
    assert "x-fg-delivery-attempt-id" not in resp.headers

    # No SUCCEEDED row committed: the transaction rolled back on close.
    sm = get_sessionmaker()()
    try:
        rows = (
            sm.execute(
                _select(FaGovernedDeliveryAttempt).where(
                    FaGovernedDeliveryAttempt.authorization_id == auth_id,
                    FaGovernedDeliveryAttempt.outcome == "SUCCEEDED",
                )
            )
            .scalars()
            .all()
        )
        assert rows == [], (
            "no SUCCEEDED attempt row may persist when the pre-response "
            "commit path fails"
        )
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T15 — response bytes hash matches the persisted attempt row
# ---------------------------------------------------------------------------


def test_t15_response_bytes_hash_matches_persisted_attempt(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sha256(response.content) MUST equal the persisted attempt's
    artifact_sha256 — the same bytes hashed for the row are the bytes
    returned to the operator.
    """
    import hashlib as _hashlib

    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt
    from sqlalchemy import select as _select

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 200, resp.text

    body_sha = _hashlib.sha256(resp.content).hexdigest()
    attempt_id = resp.headers["x-fg-delivery-attempt-id"]

    sm = get_sessionmaker()()
    try:
        row = sm.execute(
            _select(FaGovernedDeliveryAttempt).where(
                FaGovernedDeliveryAttempt.id == attempt_id,
            )
        ).scalar_one()
        assert row.artifact_sha256 == body_sha, (
            "sha256(response.content) must equal the persisted attempt "
            "row's artifact_sha256; a divergence proves the served bytes "
            "are not the bytes that were hashed and committed."
        )
        assert row.artifact_bytes_length == len(resp.content)
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# T16 — every X-FG-* response header matches the persisted attempt row
# ---------------------------------------------------------------------------


def test_t16_response_headers_match_persisted_attempt(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every X-FG-* metadata header on the SUCCEEDED response must be a
    byte-exact projection of the persisted attempt row + request id.
    Divergence would let a caller be misled about what was actually
    written to the append-only ledger.
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt
    from sqlalchemy import select as _select

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 200, resp.text

    attempt_id = resp.headers["x-fg-delivery-attempt-id"]

    sm = get_sessionmaker()()
    try:
        row = sm.execute(
            _select(FaGovernedDeliveryAttempt).where(
                FaGovernedDeliveryAttempt.id == attempt_id,
            )
        ).scalar_one()
    finally:
        sm.close()

    assert resp.headers["x-fg-delivery-attempt-id"] == row.id
    assert resp.headers["x-fg-delivery-authorization-id"] == row.authorization_id
    assert resp.headers["x-fg-delivery-request-id"] == request_id
    assert resp.headers["x-fg-tenant-id"] == row.tenant_id
    assert resp.headers["x-fg-engagement-id"] == row.engagement_id
    assert resp.headers["x-fg-report-id"] == row.report_id
    assert resp.headers["x-fg-report-version-id"] == row.report_version_id
    assert resp.headers["x-fg-report-fingerprint"] == row.report_fingerprint
    assert resp.headers["x-fg-recipient-type"] == row.recipient_type
    assert resp.headers["x-fg-channel"] == row.channel
    assert resp.headers["x-fg-transport-type"] == row.transport_type
    assert resp.headers["x-fg-artifact-sha256"] == (row.artifact_sha256 or "")
    assert int(resp.headers["x-fg-artifact-bytes"]) == (row.artifact_bytes_length or 0)
    assert resp.headers["x-fg-attempted-by"] == row.attempted_by
    assert resp.headers["x-fg-attempted-at"] == row.attempted_at
    assert resp.headers["x-fg-outcome"] == row.outcome
    assert resp.headers["x-fg-schema-version"] == "1.0"


# ---------------------------------------------------------------------------
# T17 — no secret-bearing metadata appears in response headers
# ---------------------------------------------------------------------------


def test_t17_no_secret_bearing_headers(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The X-FG-* header envelope MUST NOT contain names hinting at
    secrets, tokens, keys, credentials, or private material. The
    transport endpoint is a delivery boundary; headers must be
    non-sensitive metadata only.
    """
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 200, resp.text

    # Tokens that must never appear in an X-FG-* header name or value.
    # 'authorization' is deliberately excluded from name-scan because the
    # transport row's parent record is literally the delivery
    # ``authorization_id`` — the forbidden concept is the HTTP
    # ``Authorization`` header / bearer credential, not the noun in a
    # governance authority id. Value-scan still applies (a credential
    # would carry hex/token noise, not the substring 'authorization').
    _forbidden_tokens = (
        "secret",
        "password",
        "passwd",
        "credential",
        "private-key",
        "privatekey",
        "api-key",
        "apikey",
        "bearer",
        "cookie",
        "jwt",
        "signing-key",
        "session-key",
        "session_key",
    )
    fg_headers = {
        name.lower(): value
        for name, value in resp.headers.items()
        if name.lower().startswith("x-fg-")
    }
    assert fg_headers, "expected X-FG-* headers on SUCCEEDED transport"
    for name, value in fg_headers.items():
        for forbidden in _forbidden_tokens:
            assert forbidden not in name, (
                f"header name '{name}' contains forbidden token '{forbidden}'"
            )
            # Values are IDs, fingerprints, hex SHA-256, byte counts, timestamps,
            # actor subjects — none should embed a credential-like keyword.
            assert forbidden not in value.lower(), (
                f"header value for '{name}' contains forbidden token '{forbidden}'"
            )


# ---------------------------------------------------------------------------
# T18 — non-ASCII actor subject does not permanently lock out the operator
# ---------------------------------------------------------------------------


def test_t18_non_ascii_actor_subject_does_not_lock_out(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR #729 bot-review P1 repair.

    An OIDC ``sub`` claim may legitimately contain non-Latin-1 Unicode
    characters. Before the header-safety repair, ``_ascii_safe_header``
    did not exist and headers were constructed AFTER ``db.commit()``:
    Starlette would raise ``UnicodeEncodeError`` while serializing the
    response, but the SUCCEEDED attempt row had already been persisted.
    Every subsequent ``/execute`` call would then return
    ``409 DELIVERY_ALREADY_EXECUTED`` — a permanent lock-out from the
    artifact.

    This test proves the invariant:
      1. A transport executed by an actor whose subject contains a
         non-ASCII character returns 200 (not 500).
      2. The ``x-fg-attempted-by`` response header contains only
         ASCII characters (non-ASCII byte replaced with ``?``).
      3. The SUCCEEDED attempt row is persisted with the *original*
         Unicode subject preserved for audit.
      4. A second call returns 409 (idempotent), confirming the
         first call actually delivered the bytes rather than
         leaving the authority in a corrupted "committed but never
         served" state.
    """
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt
    from sqlalchemy import select as _select

    non_ascii_subject = "operätor-sub-001"
    assert not non_ascii_subject.isascii(), (
        "test fixture must actually contain non-ASCII to be meaningful"
    )

    # Patch the canonical actor resolver so the /execute route reads
    # our non-Latin-1 subject. The bootstrap/authorize steps run before
    # the patch is installed, so they still use the mint_key subject.
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    auth = _authorize(client, eid, rid, vid)
    request_id = auth["receipt"]["delivery_request_id"]

    # Only override the actor subject at the moment of /execute so that
    # the earlier authorization step still uses the real credential
    # subject. This mirrors production: the same actor may authorize
    # and later execute, but the subject value we care about here is
    # the one persisted into the attempt row's ``attempted_by`` column.
    monkeypatch.setattr(
        "api.field_assessment._actor_from_context",
        lambda actor_ctx: non_ascii_subject,
    )

    resp = _execute(client, eid, rid, request_id)
    assert resp.status_code == 200, (
        f"non-ASCII subject must not 500 the /execute response: {resp.status_code} {resp.text}"
    )

    # (2) Response header is ASCII-safe.
    attempted_by_header = resp.headers["x-fg-attempted-by"]
    assert attempted_by_header.isascii(), (
        f"x-fg-attempted-by must be ASCII-only, got: {attempted_by_header!r}"
    )
    assert "?" in attempted_by_header, (
        "non-ASCII char must be replaced with '?' in the projected header, "
        f"got: {attempted_by_header!r}"
    )
    # Prefix and suffix are preserved.
    assert attempted_by_header.startswith("oper"), attempted_by_header
    assert attempted_by_header.endswith("tor-sub-001"), attempted_by_header

    # (3) Persisted attempt row keeps the ORIGINAL Unicode subject.
    attempt_id = resp.headers["x-fg-delivery-attempt-id"]
    sm = get_sessionmaker()()
    try:
        row = sm.execute(
            _select(FaGovernedDeliveryAttempt).where(
                FaGovernedDeliveryAttempt.id == attempt_id,
            )
        ).scalar_one()
    finally:
        sm.close()
    assert row.outcome == "SUCCEEDED"
    assert row.attempted_by == non_ascii_subject, (
        "audit column must preserve the original Unicode subject; "
        f"got {row.attempted_by!r}"
    )

    # (4) A second /execute returns 409 (not 500), confirming the
    # first call really did land the transport rather than trapping
    # the authority in a permanent inconsistent state.
    second = _execute(client, eid, rid, request_id)
    assert second.status_code == 409, (
        f"second call must be idempotent 409, got {second.status_code} {second.text}"
    )
    assert _err(second) == "DELIVERY_ALREADY_EXECUTED", _err(second)
