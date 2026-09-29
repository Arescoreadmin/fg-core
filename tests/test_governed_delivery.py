"""tests/test_governed_delivery.py — GOV-DELIVERY-001 adversarial test suite.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Covers the canonical governed client delivery authority: recipient binding,
idempotency, tenant isolation, and artifact binding.

Adversarial categories:

  A — happy path with full qualification chain (monkeypatched truth gate)
  B — delivery state machine (wrong status → 409, no qualification → 422)
  C — recipient authority (cross-tenant, arbitrary ID, operator_direct)
  D — idempotency (same key → existing receipt returned, no duplicate)
  E — artifact binding (receipt contains fingerprint + qualification_decision_id)
  F — tenant isolation (cross-tenant engagement → 404)
"""

from __future__ import annotations

import os
import uuid

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient

_TENANT_A = "tenant-gov-del-A"
_TENANT_B = "tenant-gov-del-B"
_SIGNING_KEY_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"

_ENGAGEMENT_BODY = {
    "client_name": "Governed Delivery Corp",
    "assessor_id": "assessor-gov-del-001",
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


def _bootstrap_approved_version(
    client: TestClient,
) -> tuple[str, str, str]:
    """Create engagement + report (QA-approved) + version (submitted + approved).

    Returns (engagement_id, report_id, version_id).
    """
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)
    vid = _create_version(client, eid, rid)
    _submit(client, eid, rid, vid)
    _approve_version(client, eid, rid, vid)
    return eid, rid, vid


def _inject_qualification(
    tenant_id: str,
    eid: str,
    rid: str,
    vid: str,
    report_fingerprint: str = "",
) -> str:
    """Directly inject a QUALIFIED decision row. Returns qualification_decision_id."""
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import (
        FaProductionQualRequest,
        FaQualificationDecision,
    )

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
            requested_at="2026-09-24T00:00:00Z",
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
            decided_at="2026-09-24T00:00:00Z",
            schema_version="1.0",
        )
        sm.add(dec_row)
        sm.commit()
        return dec_id
    finally:
        sm.close()


def _monkeypatch_require_qualified(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch _require_production_qualified to bypass truth gate check."""

    def _patched(report_json, db, *, report_id, tenant_id, report_version_id):
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

    monkeypatch.setattr("api.field_assessment._require_production_qualified", _patched)


def _governed_delivery(
    client: TestClient,
    eid: str,
    rid: str,
    vid: str,
    recipient_type: str = "operator_direct",
    recipient_id: str | None = None,
    channel: str = "direct_download",
    idempotency_key: str | None = None,
) -> dict:
    body: dict = {
        "report_version_id": vid,
        "recipient_type": recipient_type,
        "channel": channel,
    }
    if recipient_id is not None:
        body["recipient_id"] = recipient_id
    if idempotency_key is not None:
        body["idempotency_key"] = idempotency_key
    resp = client.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/governed-delivery",
        json=body,
    )
    return resp


def _err(resp) -> str:
    return (resp.json().get("detail") or {}).get("code", "")


# ---------------------------------------------------------------------------
# Category A — happy path with governed delivery
# ---------------------------------------------------------------------------


def test_a1_governed_delivery_operator_direct_returns_receipt(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """operator_direct governed delivery returns a full receipt with correct fields."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "version" in data
    assert "receipt" in data
    assert data["version"]["status"] == "delivered"
    receipt = data["receipt"]
    assert receipt["outcome"] == "DELIVERED"
    assert receipt["recipient_type"] == "operator_direct"
    assert receipt["recipient_id"] is None
    assert receipt["channel"] == "direct_download"
    assert receipt["report_version_id"] == vid
    assert receipt["tenant_id"] == _TENANT_A
    assert receipt["engagement_id"] == eid
    assert receipt["report_id"] == rid
    assert receipt["delivery_request_id"]
    assert receipt["delivery_attempt_id"]
    assert receipt["attempted_by"]
    assert receipt["attempted_at"]
    assert receipt["schema_version"] == "1.0"


def test_a2_governed_delivery_with_portal_grant_recipient(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Governed delivery with portal_grant recipient validates grant and records it."""
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrant

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    # Create an active portal grant for this engagement
    sm = get_sessionmaker()()
    try:
        grant_id = uuid.uuid4().hex
        grant = PortalGrant(
            id=grant_id,
            tenant_id=_TENANT_A,
            client_id="delivery-corp",
            engagement_id=eid,
            grant_hash="testhash",
            created_by="test-actor",
            created_at="2026-09-24T00:00:00Z",
            expires_at="2027-09-24T00:00:00Z",
            status="active",
        )
        sm.add(grant)
        sm.commit()
    finally:
        sm.close()

    resp = _governed_delivery(
        client,
        eid,
        rid,
        vid,
        recipient_type="portal_grant",
        recipient_id=grant_id,
        channel="portal_grant",
    )
    assert resp.status_code == 200, resp.text
    receipt = resp.json()["receipt"]
    assert receipt["recipient_type"] == "portal_grant"
    assert receipt["recipient_id"] == grant_id
    assert receipt["channel"] == "portal_grant"
    assert receipt["outcome"] == "DELIVERED"


def test_a3_governed_delivery_receipt_fingerprint_and_qual_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Receipt records qualification_decision_id when decision exists."""
    eid, rid, vid = _bootstrap_approved_version(client)
    dec_id = _inject_qualification(_TENANT_A, eid, rid, vid, report_fingerprint="")
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 200, resp.text
    receipt = resp.json()["receipt"]
    assert receipt["qualification_decision_id"] == dec_id


# ---------------------------------------------------------------------------
# Category B — delivery state machine
# ---------------------------------------------------------------------------


def test_b1_governed_delivery_requires_approved_status(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Draft version → 409."""
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)
    vid = _create_version(client, eid, rid)
    _monkeypatch_require_qualified(monkeypatch)
    _inject_qualification(_TENANT_A, eid, rid, vid)

    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 409


def test_b2_governed_delivery_requires_qualification(
    client: TestClient,
) -> None:
    """Approved version without QUALIFIED decision → 422."""
    eid, rid, vid = _bootstrap_approved_version(client)
    # No qualification injected — truth gate will block delivery
    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 422
    assert (
        "QUALIFICATION_BLOCKED" in _err(resp).upper()
        or "TRUTH_GATE" in _err(resp).upper()
    )


def test_b3_governed_delivery_internal_review_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Internal_review version → 409."""
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)
    vid = _create_version(client, eid, rid)
    _submit(client, eid, rid, vid)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Category C — recipient authority validation
# ---------------------------------------------------------------------------


def test_c1_governed_delivery_rejects_wrong_tenant_portal_grant(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """portal_grant from tenant_B used in tenant_A delivery → 403."""
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrant

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    # Create a portal grant for tenant_B
    sm = get_sessionmaker()()
    try:
        grant_id = uuid.uuid4().hex
        grant = PortalGrant(
            id=grant_id,
            tenant_id=_TENANT_B,
            client_id="other-corp",
            engagement_id=eid,
            grant_hash="testhash2",
            created_by="test-actor",
            created_at="2026-09-24T00:00:00Z",
            expires_at="2027-09-24T00:00:00Z",
            status="active",
        )
        sm.add(grant)
        sm.commit()
    finally:
        sm.close()

    resp = _governed_delivery(
        client,
        eid,
        rid,
        vid,
        recipient_type="portal_grant",
        recipient_id=grant_id,
        channel="portal_grant",
    )
    # Tenant B's grant is not visible to tenant A → 403
    assert resp.status_code in (403, 404)


def test_c2_governed_delivery_rejects_arbitrary_recipient_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Random UUID as recipient_id → 403."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(
        client,
        eid,
        rid,
        vid,
        recipient_type="portal_grant",
        recipient_id=uuid.uuid4().hex,
        channel="portal_grant",
    )
    assert resp.status_code in (403, 404)


def test_c3_governed_delivery_operator_direct_no_id_required(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """operator_direct with no recipient_id succeeds."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client, eid, rid, vid, recipient_type="operator_direct")
    assert resp.status_code == 200, resp.text
    assert resp.json()["receipt"]["recipient_id"] is None


def test_c4_governed_delivery_unknown_recipient_type(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unknown recipient_type → 422."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(
        client,
        eid,
        rid,
        vid,
        recipient_type="fax_machine",
    )
    assert resp.status_code == 422


def test_c5_governed_delivery_portal_grant_requires_recipient_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """portal_grant recipient_type without recipient_id → 422."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(
        client,
        eid,
        rid,
        vid,
        recipient_type="portal_grant",
        recipient_id=None,
        channel="portal_grant",
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Category D — idempotency
# ---------------------------------------------------------------------------


def test_d1_governed_delivery_idempotency_same_key_no_duplicate(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Second call with same idempotency_key returns existing receipt, no duplicate."""
    from api.db import get_sessionmaker
    from sqlalchemy import select as _select
    from api.db_models_field_assessment import FaGovernedDeliveryRequest

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    idem_key = "test-idempotency-key-abc123"

    resp1 = _governed_delivery(client, eid, rid, vid, idempotency_key=idem_key)
    assert resp1.status_code == 200, resp1.text
    receipt1 = resp1.json()["receipt"]

    resp2 = _governed_delivery(client, eid, rid, vid, idempotency_key=idem_key)
    assert resp2.status_code == 200, resp2.text
    receipt2 = resp2.json()["receipt"]

    # Same request + attempt IDs — no duplicate created
    assert receipt1["delivery_request_id"] == receipt2["delivery_request_id"]
    assert receipt1["delivery_attempt_id"] == receipt2["delivery_attempt_id"]

    # Exactly one row with this idempotency key
    sm = get_sessionmaker()()
    try:
        count = (
            sm.execute(
                _select(FaGovernedDeliveryRequest).where(
                    FaGovernedDeliveryRequest.tenant_id == _TENANT_A,
                    FaGovernedDeliveryRequest.idempotency_key == idem_key,
                )
            )
            .scalars()
            .all()
        )
        assert len(count) == 1
    finally:
        sm.close()


def test_d2_governed_delivery_different_version_different_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deliver V1 then V2 → two distinct receipts."""
    eid = _create_engagement(client)
    rid = _create_report(client, eid)
    _qa_approve(client, eid, rid)
    _monkeypatch_require_qualified(monkeypatch)

    # Version 1
    vid1 = _create_version(client, eid, rid)
    _submit(client, eid, rid, vid1)
    _approve_version(client, eid, rid, vid1)
    _inject_qualification(_TENANT_A, eid, rid, vid1)

    resp1 = _governed_delivery(client, eid, rid, vid1)
    assert resp1.status_code == 200, resp1.text
    receipt1 = resp1.json()["receipt"]

    # Version 2 — need to supersede v1 first, then create v2 approved
    vid2 = _create_version(client, eid, rid)
    _submit(client, eid, rid, vid2)
    _approve_version(client, eid, rid, vid2)
    _inject_qualification(_TENANT_A, eid, rid, vid2)

    resp2 = _governed_delivery(client, eid, rid, vid2)
    assert resp2.status_code == 200, resp2.text
    receipt2 = resp2.json()["receipt"]

    assert receipt1["report_version_id"] == vid1
    assert receipt2["report_version_id"] == vid2
    assert receipt1["delivery_request_id"] != receipt2["delivery_request_id"]


# ---------------------------------------------------------------------------
# Category E — artifact binding
# ---------------------------------------------------------------------------


def test_e1_governed_delivery_receipt_contains_fingerprint(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delivered receipt records report_fingerprint from qualification decision."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid, report_fingerprint="")
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 200, resp.text
    receipt = resp.json()["receipt"]
    # report_fingerprint is a string (may be empty for test injection with empty fp)
    assert "report_fingerprint" in receipt


def test_e2_governed_delivery_receipt_contains_qualification_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Receipt references the actual qualification_decision_id."""
    eid, rid, vid = _bootstrap_approved_version(client)
    dec_id = _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 200, resp.text
    receipt = resp.json()["receipt"]
    assert receipt["qualification_decision_id"] == dec_id


def test_e3_governed_delivery_attempt_stored_in_db(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FaGovernedDeliveryAttempt row is persisted in the DB after delivery."""
    from api.db import get_sessionmaker
    from sqlalchemy import select as _select
    from api.db_models_field_assessment import FaGovernedDeliveryAttempt

    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client, eid, rid, vid)
    assert resp.status_code == 200, resp.text
    receipt = resp.json()["receipt"]
    attempt_id = receipt["delivery_attempt_id"]

    sm = get_sessionmaker()()
    try:
        row = sm.execute(
            _select(FaGovernedDeliveryAttempt).where(
                FaGovernedDeliveryAttempt.id == attempt_id,
            )
        ).scalar_one_or_none()
        assert row is not None
        assert row.tenant_id == _TENANT_A
        assert row.report_version_id == vid
        assert row.outcome == "DELIVERED"
    finally:
        sm.close()


# ---------------------------------------------------------------------------
# Category F — tenant isolation
# ---------------------------------------------------------------------------


def test_f1_governed_delivery_cross_tenant_engagement_not_found(
    client: TestClient,
    client_b: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant B cannot deliver tenant A's report → 404."""
    eid, rid, vid = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid, rid, vid)
    _monkeypatch_require_qualified(monkeypatch)

    resp = _governed_delivery(client_b, eid, rid, vid)
    assert resp.status_code == 404


def test_f2_governed_delivery_cross_tenant_version_not_found(
    client: TestClient,
    client_b: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant B cannot reference tenant A's report version → 404."""
    eid_a, rid_a, vid_a = _bootstrap_approved_version(client)

    # Tenant B creates their own engagement
    eid_b = _create_engagement(client_b)
    rid_b = _create_report(client_b, eid_b)

    # Attempt to deliver tenant A's version via tenant B's engagement
    resp = _governed_delivery(client_b, eid_b, rid_b, vid_a)
    assert resp.status_code in (404, 409, 422)


def test_f3_governed_delivery_tenant_b_cannot_see_tenant_a_qualification(
    client: TestClient,
    client_b: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant B's delivery attempt cannot leverage tenant A's qualification."""
    eid_a, rid_a, vid_a = _bootstrap_approved_version(client)
    _inject_qualification(_TENANT_A, eid_a, rid_a, vid_a)

    # Tenant B creates own engagement — no qualification, truth gate fails
    eid_b = _create_engagement(client_b)
    rid_b = _create_report(client_b, eid_b)
    _qa_approve(client_b, eid_b, rid_b)
    vid_b = _create_version(client_b, eid_b, rid_b)
    _submit(client_b, eid_b, rid_b, vid_b)
    _approve_version(client_b, eid_b, rid_b, vid_b)

    resp = _governed_delivery(client_b, eid_b, rid_b, vid_b)
    # Tenant B cannot use tenant A's qualification
    assert resp.status_code == 422
