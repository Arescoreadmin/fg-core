"""
tests/test_stripe_sdk_regression_001.py — Stripe SDK 15.x event deserialization regression.

Root cause of L14-STRIPE-WEBHOOK-EVENT-CONVERSION incident:
  stripe.Webhook.construct_event() in SDK ≥15.x returns a stripe.Event (StripeObject).
  Calling dict(event) raises KeyError: 0 — StripeObject.__iter__ is integer-indexed.
  Calling event.to_dict() returns a proper plain Python dict.

Regression coverage:
  SDK-01. event.to_dict() returns a plain Python dict (real construct_event, no mock)
  SDK-02. dict(event) raises KeyError: 0 — documents the production defect
  SDK-03. Nested checkout metadata fully preserved through to_dict()
  SDK-04. Signed checkout webhook through endpoint returns 200 (real HMAC, no construct_event mock)
  SDK-05. Foreign session on unpaid assessment → 400 STRIPE_SESSION_ID_MISMATCH
  SDK-06. Already-paid assessment replay → 200 idempotent (no second confirmation)
  SDK-07. Missing STRIPE_WEBHOOK_SECRET → 503 (no payment mutation)
  SDK-08. Wrong HMAC on otherwise-valid payload → 400 STRIPE_WEBHOOK_SIGNATURE_INVALID

Tests SDK-01 through SDK-03 call the real stripe.Webhook.construct_event without mocking
the SDK layer.  They are the definitive automated regression for the conversion defect.

Tests SDK-04 through SDK-08 use the real Stripe HMAC verification path and mock only
the DB layer.  No live Stripe API calls are made in any test.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.db_models import AssessmentRecord
from api.stripe_webhooks import (
    STRIPE_SESSION_ID_MISMATCH,
    STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED,
    STRIPE_WEBHOOK_SIGNATURE_INVALID,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_SDK_TEST_SECRET = "whsec_sdk_regression_test_secret_001"
_TENANT_ID = "tenant-sdk-regression-001"
_ASSESSMENT_ID = "sdk-aaaa-bbbb-cccc-ddddeeeeeeee"
_SESSION_ID = "cs_test_sdk_regression_001"
_EVENT_ID = "evt_sdk_regression_001"
_AMOUNT = 29900  # $299.00


def _make_sdk_sig(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Build a Stripe-compatible v1 HMAC signature."""
    ts = timestamp if timestamp is not None else int(time.time())
    mac = hmac.new(
        secret.encode(), f"{ts}.{payload.decode()}".encode(), hashlib.sha256
    ).hexdigest()
    return f"t={ts},v1={mac}"


def _canonical_checkout_payload(
    event_id: str = _EVENT_ID,
    session_id: str = _SESSION_ID,
    tenant_id: str = _TENANT_ID,
    assessment_id: str = _ASSESSMENT_ID,
    amount_total: int = _AMOUNT,
    payment_status: str = "paid",
) -> bytes:
    """Build a Stripe-valid checkout.session.completed payload.

    The 'object': 'event' field is required by stripe.Webhook.construct_event
    in SDK 15.x — its absence raises AttributeError before signature verification.
    """
    return json.dumps(
        {
            "id": event_id,
            "object": "event",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": session_id,
                    "object": "checkout.session",
                    "payment_status": payment_status,
                    "amount_total": amount_total,
                    "currency": "usd",
                    "metadata": {
                        "assessment_id": assessment_id,
                        "tenant_id": tenant_id,
                        "payment_purpose": "assessment_initial",
                    },
                }
            },
        }
    ).encode()


def _make_assessment_rec(
    payment_status: str = "unpaid",
    stripe_session_id: str | None = _SESSION_ID,
    expected_amount_cents: int | None = _AMOUNT,
) -> MagicMock:
    rec = MagicMock()
    rec.id = _ASSESSMENT_ID
    rec.tenant_id = _TENANT_ID
    rec.payment_status = payment_status
    rec.stripe_session_id = stripe_session_id
    rec.expected_amount_cents = expected_amount_cents
    return rec


def _make_db_mock(mock_rec: MagicMock) -> MagicMock:
    """Return a db session mock that dispatches AssessmentRecord vs StripeEvent queries."""
    db = MagicMock()

    def _query_dispatch(model_class):
        q = MagicMock()
        if model_class is AssessmentRecord:
            q.filter.return_value.with_for_update.return_value.first.return_value = (
                mock_rec
            )
        else:
            # StripeEvent query — no pre-existing event
            q.filter.return_value.with_for_update.return_value.first.return_value = None
        return q

    db.query.side_effect = _query_dispatch
    return db


# ---------------------------------------------------------------------------
# SDK-01 — event.to_dict() returns a plain Python dict (real construct_event)
# ---------------------------------------------------------------------------


def test_sdk_01_to_dict_returns_plain_dict():
    """event.to_dict() returns a plain Python dict — no mock on construct_event.

    This is the definitive regression for L14-STRIPE-WEBHOOK-EVENT-CONVERSION.
    If the Stripe SDK changes the return type or removes to_dict(), this fails.
    """
    raw = _canonical_checkout_payload()
    sig = _make_sdk_sig(raw, _SDK_TEST_SECRET)

    import stripe

    event = stripe.Webhook.construct_event(
        payload=raw, sig_header=sig, secret=_SDK_TEST_SECRET
    )
    result = event.to_dict()

    assert isinstance(result, dict), (
        f"event.to_dict() must return a plain dict; got {type(result).__name__}"
    )
    assert result.get("id") == _EVENT_ID
    assert result.get("type") == "checkout.session.completed"


# ---------------------------------------------------------------------------
# SDK-02 — dict(event) raises — documents the original production defect
# ---------------------------------------------------------------------------


def test_sdk_02_dict_raises_regression():
    """dict(event) raises KeyError: 0 on a real StripeObject from SDK 15.x.

    This documents the exact production defect.  If a future SDK version changes
    this behavior, this test will fail and the to_dict() fix should be re-evaluated.
    """
    raw = _canonical_checkout_payload()
    sig = _make_sdk_sig(raw, _SDK_TEST_SECRET)

    import stripe

    event = stripe.Webhook.construct_event(
        payload=raw, sig_header=sig, secret=_SDK_TEST_SECRET
    )

    with pytest.raises((KeyError, TypeError)):
        dict(event)


# ---------------------------------------------------------------------------
# SDK-03 — Nested checkout metadata fully preserved through to_dict()
# ---------------------------------------------------------------------------


def test_sdk_03_nested_metadata_preserved():
    """to_dict() preserves nested session metadata — the access pattern used by
    _validate_payment_binding and the webhook handler's metadata extraction."""
    raw = _canonical_checkout_payload(
        tenant_id="tenant-nested-check",
        assessment_id="assessment-nested-check",
        amount_total=49900,
    )
    sig = _make_sdk_sig(raw, _SDK_TEST_SECRET)

    import stripe

    event = stripe.Webhook.construct_event(
        payload=raw, sig_header=sig, secret=_SDK_TEST_SECRET
    )
    d = event.to_dict()

    session = d.get("data", {}).get("object", {})
    metadata = session.get("metadata", {})

    assert metadata.get("tenant_id") == "tenant-nested-check"
    assert metadata.get("assessment_id") == "assessment-nested-check"
    assert metadata.get("payment_purpose") == "assessment_initial"
    assert session.get("amount_total") == 49900
    assert session.get("currency") == "usd"


# ---------------------------------------------------------------------------
# SDK-04 — Full signed checkout webhook through endpoint (real HMAC, no SDK mock)
# ---------------------------------------------------------------------------


def test_sdk_04_real_hmac_signed_webhook_endpoint(monkeypatch):
    """Full signed checkout webhook through endpoint returns 200.

    construct_event is NOT mocked — this exercises the real SDK deserialization
    path and proves event.to_dict() works end-to-end in the FastAPI handler.
    Only the DB layer and audit helper are mocked.
    """
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SDK_TEST_SECRET)

    from api.main import build_app

    _app = build_app(auth_enabled=False)

    mock_rec = _make_assessment_rec()
    db = _make_db_mock(mock_rec)

    with (
        patch("api.stripe_webhooks.get_sessionmaker") as mock_sm,
        patch("api.stripe_webhooks._audit_payment_confirmed"),
    ):
        sm_instance = MagicMock()
        sm_instance.return_value = db
        mock_sm.return_value = sm_instance

        raw = _canonical_checkout_payload()
        sig = _make_sdk_sig(raw, _SDK_TEST_SECRET)

        with TestClient(_app, raise_server_exceptions=False) as c:
            resp = c.post(
                "/ingest/assessment/webhooks/stripe",
                content=raw,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": sig,
                },
            )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"received": True}
    # Payment state must have been set to paid
    assert mock_rec.payment_status == "paid"


# ---------------------------------------------------------------------------
# SDK-05 — Foreign session on unpaid assessment → 400 STRIPE_SESSION_ID_MISMATCH
# ---------------------------------------------------------------------------


def test_sdk_05_foreign_session_unpaid_rejected(monkeypatch):
    """Foreign Stripe session against an unpaid assessment is rejected.

    The assessment record's stripe_session_id is 'cs_test_ORIGINAL'; the
    incoming event carries 'cs_test_FOREIGN'.  The binding check must reject
    this and return STRIPE_SESSION_ID_MISMATCH without changing payment state.
    """
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SDK_TEST_SECRET)

    from api.main import build_app

    _app = build_app(auth_enabled=False)

    # DB record bound to a different session
    mock_rec = _make_assessment_rec(stripe_session_id="cs_test_ORIGINAL_BOUND")
    # Incoming event carries a foreign session
    foreign_session_id = "cs_test_FOREIGN_SESSION"
    db = _make_db_mock(mock_rec)

    raw = _canonical_checkout_payload(session_id=foreign_session_id)
    sig = _make_sdk_sig(raw, _SDK_TEST_SECRET)

    with (
        patch("api.stripe_webhooks.get_sessionmaker") as mock_sm,
        patch("api.stripe_webhooks._audit_binding_rejection"),
    ):
        sm_instance = MagicMock()
        sm_instance.return_value = db
        mock_sm.return_value = sm_instance

        with TestClient(_app, raise_server_exceptions=False) as c:
            resp = c.post(
                "/ingest/assessment/webhooks/stripe",
                content=raw,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": sig,
                },
            )

    assert resp.status_code == 400, resp.text
    assert STRIPE_SESSION_ID_MISMATCH in resp.text
    # Payment state must remain unpaid
    assert mock_rec.payment_status == "unpaid"


# ---------------------------------------------------------------------------
# SDK-06 — Already-paid assessment replay → 200 idempotent
# ---------------------------------------------------------------------------


def test_sdk_06_already_paid_replay_idempotent(monkeypatch):
    """Replaying the original signed event for an already-paid assessment returns 200.

    The idempotency guard fires before binding validation — no second state
    transition, no error.
    """
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SDK_TEST_SECRET)

    from api.main import build_app

    _app = build_app(auth_enabled=False)

    mock_rec = _make_assessment_rec(payment_status="paid")
    db = _make_db_mock(mock_rec)

    raw = _canonical_checkout_payload()
    sig = _make_sdk_sig(raw, _SDK_TEST_SECRET)

    with patch("api.stripe_webhooks.get_sessionmaker") as mock_sm:
        sm_instance = MagicMock()
        sm_instance.return_value = db
        mock_sm.return_value = sm_instance

        with TestClient(_app, raise_server_exceptions=False) as c:
            resp = c.post(
                "/ingest/assessment/webhooks/stripe",
                content=raw,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": sig,
                },
            )

    assert resp.status_code == 200, resp.text
    # payment_status must remain paid, not change back or raise
    assert mock_rec.payment_status == "paid"
    # No commit on the already-paid path
    db.commit.assert_not_called()


# ---------------------------------------------------------------------------
# SDK-07 — Missing STRIPE_WEBHOOK_SECRET → 503 (no payment mutation)
# ---------------------------------------------------------------------------


def test_sdk_07_missing_webhook_secret_no_mutation(monkeypatch):
    """Absent STRIPE_WEBHOOK_SECRET returns 503 — payment state never touched."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "")

    from api.main import build_app

    _app = build_app(auth_enabled=False)

    mock_rec = _make_assessment_rec()
    db = _make_db_mock(mock_rec)

    raw = _canonical_checkout_payload()
    # Signature is irrelevant — secret check fires first
    sig = _make_sdk_sig(raw, _SDK_TEST_SECRET)

    with patch("api.stripe_webhooks.get_sessionmaker") as mock_sm:
        sm_instance = MagicMock()
        sm_instance.return_value = db
        mock_sm.return_value = sm_instance

        with TestClient(_app, raise_server_exceptions=False) as c:
            resp = c.post(
                "/ingest/assessment/webhooks/stripe",
                content=raw,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": sig,
                },
            )

    assert resp.status_code == 503, resp.text
    assert STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED in resp.text
    assert mock_rec.payment_status == "unpaid"
    db.commit.assert_not_called()


# ---------------------------------------------------------------------------
# SDK-08 — Wrong HMAC → 400 STRIPE_WEBHOOK_SIGNATURE_INVALID (no mutation)
# ---------------------------------------------------------------------------


def test_sdk_08_wrong_hmac_rejected(monkeypatch):
    """Payload signed with the wrong secret is rejected — payment state never touched."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SDK_TEST_SECRET)

    from api.main import build_app

    _app = build_app(auth_enabled=False)

    mock_rec = _make_assessment_rec()
    db = _make_db_mock(mock_rec)

    raw = _canonical_checkout_payload()
    # Signed with the wrong secret
    wrong_sig = _make_sdk_sig(raw, "whsec_WRONG_SECRET_000000000000000")

    with patch("api.stripe_webhooks.get_sessionmaker") as mock_sm:
        sm_instance = MagicMock()
        sm_instance.return_value = db
        mock_sm.return_value = sm_instance

        with TestClient(_app, raise_server_exceptions=False) as c:
            resp = c.post(
                "/ingest/assessment/webhooks/stripe",
                content=raw,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": wrong_sig,
                },
            )

    assert resp.status_code == 400, resp.text
    assert STRIPE_WEBHOOK_SIGNATURE_INVALID in resp.text
    assert mock_rec.payment_status == "unpaid"
    db.commit.assert_not_called()
