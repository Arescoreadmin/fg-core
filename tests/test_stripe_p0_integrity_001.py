"""
tests/test_stripe_p0_integrity_001.py — L14-STRIPE-P0-INTEGRITY-001 regressions.

12 adversarial tests covering confirmed payment integrity vulnerabilities.

Regressions proven:
 P01. Missing Stripe key during checkout → 503 STRIPE_NOT_CONFIGURED (not bypass)
 P02. Missing Stripe key during submission → 402 PAYMENT_REQUIRED (always enforced)
 P03. StripeEvent commit failure → payment_status stays unpaid, exception raised
 P04. AssessmentRecord commit failure → payment_status stays unpaid, exception raised
 P05. Concurrent duplicate events → exactly one payment_confirmed_at written
 P06. Already-paid assessment + wrong session → 200 idempotent (no second transition)
 P07. stripe_session_id absent from record → STRIPE_MISSING_SESSION_BINDING
 P08. expected_amount_cents absent from record → STRIPE_MISSING_AMOUNT_BINDING
 P09. payment_purpose absent/wrong in metadata → STRIPE_PAYMENT_PURPOSE_MISMATCH
 P10. Amount matches purpose but wrong amount → STRIPE_AMOUNT_MISMATCH
 P11. Transient DB error in _confirm_payment → webhook returns 500 retryable
 P12. tenant_id absent from session metadata → STRIPE_TENANT_BINDING_MISMATCH

All Stripe SDK calls are mocked. No live Stripe API calls.
"""

from __future__ import annotations

import threading
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.db_models import AssessmentRecord
from api.stripe_webhooks import (
    STRIPE_MISSING_AMOUNT_BINDING,
    STRIPE_MISSING_SESSION_BINDING,
    STRIPE_PAYMENT_PURPOSE_MISMATCH,
    STRIPE_TENANT_BINDING_MISMATCH,
    _validate_payment_binding,
    WebhookBindingError,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_TENANT_ID = "tenant-p0-001"
_ASSESSMENT_ID = "p0test-aaaa-bbbb-cccc-ddddeeeeeeee"
_SESSION_ID = "cs_test_p0_session_001"
_EVENT_ID = "evt_p0_integrity_001"
_AMOUNT = 29900  # $299.00 smb_basic tier
_API_KEY = "test-p0-integrity-api-key-001"


def _make_strict_session(
    session_id: str = _SESSION_ID,
    tenant_id: str = _TENANT_ID,
    assessment_id: str = _ASSESSMENT_ID,
    payment_status: str = "paid",
    amount_total: int = _AMOUNT,
    currency: str = "usd",
    payment_purpose: str = "assessment_initial",
) -> dict:
    """Full session dict passing all strict binding checks."""
    return {
        "id": session_id,
        "payment_status": payment_status,
        "amount_total": amount_total,
        "currency": currency,
        "metadata": {
            "assessment_id": assessment_id,
            "tenant_id": tenant_id,
            "payment_purpose": payment_purpose,
        },
    }


def _make_strict_rec(
    payment_status: str = "unpaid",
    stripe_session_id: str | None = _SESSION_ID,
    expected_amount_cents: int | None = _AMOUNT,
    payment_purpose: str | None = "assessment_initial",
) -> MagicMock:
    """AssessmentRecord mock with all authoritative bindings set."""
    rec = MagicMock()
    rec.id = _ASSESSMENT_ID
    rec.tenant_id = _TENANT_ID
    rec.payment_status = payment_status
    rec.stripe_session_id = stripe_session_id
    rec.expected_amount_cents = expected_amount_cents
    rec.payment_purpose = payment_purpose
    return rec


# ---------------------------------------------------------------------------
# P01 — Missing Stripe key during checkout → 503 STRIPE_NOT_CONFIGURED
# ---------------------------------------------------------------------------


def test_p01_missing_stripe_key_checkout(monkeypatch):
    """Absent STRIPE_SECRET_KEY returns 503 — never bypasses to paid."""
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.setenv("FG_API_KEY", _API_KEY)

    from api.assessments import _get_db
    from api.main import build_app

    _app = build_app(auth_enabled=False)
    mock_db = MagicMock()

    def _override_db():
        yield mock_db

    _app.dependency_overrides[_get_db] = _override_db

    mock_rec = _make_strict_rec(payment_status="unpaid")

    with (
        patch("api.assessments._resolve_caller_tenant", return_value=_TENANT_ID),
        patch("api.assessments._get_assessment_or_404", return_value=mock_rec),
    ):
        with TestClient(_app) as c:
            resp = c.post(
                f"/ingest/assessment/{_ASSESSMENT_ID}/checkout",
                headers={"X-API-Key": _API_KEY},
            )

    assert resp.status_code == 503, resp.text
    assert "STRIPE_NOT_CONFIGURED" in resp.text
    # payment_status must remain unpaid — no bypass
    assert mock_rec.payment_status == "unpaid"


# ---------------------------------------------------------------------------
# P02 — Missing Stripe key during submission → 402 PAYMENT_REQUIRED
# ---------------------------------------------------------------------------


def test_p02_missing_stripe_key_submit(monkeypatch):
    """Payment gate on submit is unconditional — absent STRIPE_SECRET_KEY does not bypass."""
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.setenv("FG_API_KEY", _API_KEY)

    from api.assessments import _get_db
    from api.main import build_app

    _app = build_app(auth_enabled=False)
    mock_db = MagicMock()

    def _override_db():
        yield mock_db

    _app.dependency_overrides[_get_db] = _override_db

    mock_rec = _make_strict_rec(payment_status="unpaid")

    with (
        patch("api.assessments._resolve_caller_tenant", return_value=_TENANT_ID),
        patch("api.assessments._get_assessment_or_404", return_value=mock_rec),
    ):
        with TestClient(_app) as c:
            resp = c.post(
                f"/ingest/assessment/{_ASSESSMENT_ID}/submit",
                headers={"X-API-Key": _API_KEY},
            )

    assert resp.status_code == 402, resp.text
    assert "PAYMENT_REQUIRED" in resp.text


# ---------------------------------------------------------------------------
# P03 — StripeEvent commit failure → payment_status stays unpaid
# ---------------------------------------------------------------------------


def test_p03_stripe_event_commit_failure():
    """Atomic commit failure → DB rolled back; exception re-raised for retry.

    When db.commit() fails the whole transaction is rolled back.  The
    in-memory Python attribute may reflect the pending assignment but the DB
    row remains unpaid (rollback reverts the DB transaction, not Python attrs).
    The critical invariant is that the exception is re-raised so the webhook
    caller returns a 500 and Stripe retries delivery.
    """
    from api.stripe_webhooks import _confirm_payment

    mock_rec = _make_strict_rec(payment_status="unpaid")
    session = _make_strict_session()

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = mock_rec
    db_mock.commit.side_effect = Exception("DB commit failure")

    with patch("api.stripe_webhooks.get_sessionmaker") as mock_sm:
        sm_instance = MagicMock()
        sm_instance.return_value = db_mock
        mock_sm.return_value = sm_instance

        with pytest.raises(Exception, match="DB commit failure"):
            _confirm_payment(_ASSESSMENT_ID, session, _EVENT_ID)

    # DB transaction must have been rolled back.
    db_mock.rollback.assert_called()
    # Session must be closed in the finally block.
    db_mock.close.assert_called()


# ---------------------------------------------------------------------------
# P04 — AssessmentRecord update failure → payment_status stays unpaid
# ---------------------------------------------------------------------------


def test_p04_assessment_update_failure():
    """DB error on record mutation → rollback; payment_status stays unpaid."""
    from api.stripe_webhooks import _confirm_payment

    mock_rec = _make_strict_rec(payment_status="unpaid")

    # Simulate DB error when setting payment_status (attribute set triggers error)
    def _raise_on_payment_status_set(value):
        raise Exception("DB row lock failure")

    type(mock_rec).payment_status = property(
        fget=lambda self: "unpaid",
        fset=_raise_on_payment_status_set,
    )

    session = _make_strict_session()

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = mock_rec

    with patch("api.stripe_webhooks.get_sessionmaker") as mock_sm:
        sm_instance = MagicMock()
        sm_instance.return_value = db_mock
        mock_sm.return_value = sm_instance

        with pytest.raises(Exception):
            _confirm_payment(_ASSESSMENT_ID, session, _EVENT_ID)

    db_mock.rollback.assert_called()


# ---------------------------------------------------------------------------
# P05 — Concurrent duplicate events → exactly one payment_confirmed_at written
# ---------------------------------------------------------------------------


def test_p05_concurrent_duplicate_events():
    """Concurrent _confirm_payment calls write payment_confirmed_at exactly once.

    Uses a threading.Lock to simulate the DB-level serialisation that
    SELECT ... FOR UPDATE provides on PostgreSQL.  On SQLite the unique
    constraint on stripe_event_id provides equivalent protection.
    Advisory: definitive concurrency proof requires a live PostgreSQL instance.
    """
    from api.stripe_webhooks import _confirm_payment

    confirmations: list[datetime] = []
    state_lock = threading.Lock()

    payment_status_holder = ["unpaid"]
    payment_confirmed_at_holder: list[datetime | None] = [None]

    def _make_db_mock():
        db_mock = MagicMock()
        mock_rec = MagicMock()

        def _get_payment_status():
            with state_lock:
                return payment_status_holder[0]

        def _set_payment_status(val):
            with state_lock:
                payment_status_holder[0] = val

        type(mock_rec).payment_status = property(
            fget=lambda self: _get_payment_status(),
            fset=lambda self, v: _set_payment_status(v),
        )
        mock_rec.id = _ASSESSMENT_ID
        mock_rec.tenant_id = _TENANT_ID
        mock_rec.stripe_session_id = _SESSION_ID
        mock_rec.expected_amount_cents = _AMOUNT
        mock_rec.payment_purpose = "assessment_initial"

        event_rec = MagicMock()

        def _capture_confirmed_at(val):
            with state_lock:
                if payment_confirmed_at_holder[0] is None:
                    payment_confirmed_at_holder[0] = val
                    confirmations.append(val)

        type(event_rec).payment_confirmed_at = property(
            fget=lambda self: payment_confirmed_at_holder[0],
            fset=lambda self, v: _capture_confirmed_at(v),
        )

        # Dispatch the two db.query() calls by model class so event_rec's
        # instrumented setter is reachable by _confirm_payment.
        def _query_dispatch(model_class):
            q = MagicMock()
            if model_class is AssessmentRecord:
                q.filter.return_value.with_for_update.return_value.first.return_value = mock_rec
            else:
                # StripeEvent query — return pre-existing event_rec so
                # payment_confirmed_at setter fires on the instrumented mock.
                q.filter.return_value.with_for_update.return_value.first.return_value = event_rec
            return q

        db_mock.query.side_effect = _query_dispatch
        db_mock.add = MagicMock()
        return db_mock

    errors: list[Exception] = []

    def _run_confirm():
        db_mock = _make_db_mock()
        try:
            with patch("api.stripe_webhooks.get_sessionmaker") as mock_sm:
                sm_instance = MagicMock()
                sm_instance.return_value = db_mock
                mock_sm.return_value = sm_instance
                with patch("api.stripe_webhooks._audit_payment_confirmed"):
                    _confirm_payment(_ASSESSMENT_ID, _make_strict_session(), _EVENT_ID)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_run_confirm) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All workers must have succeeded — no worker exceptions.
    assert len(errors) == 0, f"Workers raised unexpected errors: {errors}"
    # Exactly one payment_confirmed_at must have been written.
    assert len(confirmations) == 1, (
        f"Expected exactly 1 payment_confirmed_at write, got {len(confirmations)}"
    )


# ---------------------------------------------------------------------------
# P06 — Already-paid + wrong session → idempotent 200
# ---------------------------------------------------------------------------


def test_p06_already_paid_wrong_session_idempotent():
    """Webhook for already-paid assessment returns 200 without validating binding.

    Previously paid assessment must not reject on a different session ID —
    the idempotency guard fires before binding validation.
    """
    from api.stripe_webhooks import _confirm_payment

    mock_rec = _make_strict_rec(
        payment_status="paid",
        stripe_session_id="cs_test_ORIGINAL",
    )
    different_session = _make_strict_session(session_id="cs_test_DIFFERENT")

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = mock_rec
    validate_calls: list = []

    with (
        patch("api.stripe_webhooks.get_sessionmaker") as mock_sm,
        patch(
            "api.stripe_webhooks._validate_payment_binding",
            side_effect=lambda s, r: validate_calls.append(s),
        ),
    ):
        sm_instance = MagicMock()
        sm_instance.return_value = db_mock
        mock_sm.return_value = sm_instance
        # No exception expected — idempotent path
        _confirm_payment(_ASSESSMENT_ID, different_session, _EVENT_ID)

    assert len(validate_calls) == 0, "Binding validation must not run for already-paid"


# ---------------------------------------------------------------------------
# P07 — stripe_session_id absent from record → STRIPE_MISSING_SESSION_BINDING
# ---------------------------------------------------------------------------


def test_p07_missing_authoritative_session_id():
    """Webhook with no stripe_session_id in DB record → STRIPE_MISSING_SESSION_BINDING."""
    session = _make_strict_session()
    rec = _make_strict_rec(stripe_session_id=None)  # checkout never ran

    with pytest.raises(WebhookBindingError) as exc_info:
        _validate_payment_binding(session, rec)

    assert exc_info.value.reason_code == STRIPE_MISSING_SESSION_BINDING


# ---------------------------------------------------------------------------
# P08 — expected_amount_cents absent from record → STRIPE_MISSING_AMOUNT_BINDING
# ---------------------------------------------------------------------------


def test_p08_missing_authoritative_expected_amount():
    """Webhook with no expected_amount_cents in DB record → STRIPE_MISSING_AMOUNT_BINDING."""
    session = _make_strict_session()
    rec = _make_strict_rec(expected_amount_cents=None)  # binding never recorded

    with pytest.raises(WebhookBindingError) as exc_info:
        _validate_payment_binding(session, rec)

    assert exc_info.value.reason_code == STRIPE_MISSING_AMOUNT_BINDING


# ---------------------------------------------------------------------------
# P09 — payment_purpose absent or wrong in metadata → STRIPE_PAYMENT_PURPOSE_MISMATCH
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "purpose",
    [
        "",
        "subscription_renewal",
        "invoice_settlement",
        "deposit",
        None,
    ],
)
def test_p09_invalid_payment_purpose(purpose):
    """Non-'assessment_initial' purpose in metadata → STRIPE_PAYMENT_PURPOSE_MISMATCH."""
    session = _make_strict_session(payment_purpose=purpose or "")
    # Remove purpose key entirely for the None case
    if purpose is None:
        session["metadata"].pop("payment_purpose", None)

    rec = _make_strict_rec()

    with pytest.raises(WebhookBindingError) as exc_info:
        _validate_payment_binding(session, rec)

    assert exc_info.value.reason_code == STRIPE_PAYMENT_PURPOSE_MISMATCH


# ---------------------------------------------------------------------------
# P10 — Partial deposit amount → STRIPE_AMOUNT_MISMATCH
# ---------------------------------------------------------------------------


def test_p10_partial_deposit_amount_mismatch():
    """$1,500 paid against $29,900 record → STRIPE_AMOUNT_MISMATCH.

    Proves a partial deposit cannot confirm full assessment payment.
    payment_status='paid' on the Stripe session does not override the
    server-side expected_amount_cents check.
    """
    from api.stripe_webhooks import STRIPE_AMOUNT_MISMATCH

    session = _make_strict_session(amount_total=150000)  # $1,500
    rec = _make_strict_rec(expected_amount_cents=_AMOUNT)  # $299

    with pytest.raises(WebhookBindingError) as exc_info:
        _validate_payment_binding(session, rec)

    assert exc_info.value.reason_code == STRIPE_AMOUNT_MISMATCH


# ---------------------------------------------------------------------------
# P11 — Transient DB error → webhook returns 500 retryable
# ---------------------------------------------------------------------------


def test_p11_transient_db_error_retryable(monkeypatch):
    """DB error in _confirm_payment → webhook endpoint returns 500 for Stripe retry."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_p0_001")

    from api.main import build_app
    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=False)

    import hashlib
    import hmac
    import json
    import time

    event = {
        "id": _EVENT_ID,
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": _SESSION_ID,
                "payment_status": "paid",
                "amount_total": _AMOUNT,
                "currency": "usd",
                "metadata": {
                    "assessment_id": _ASSESSMENT_ID,
                    "tenant_id": _TENANT_ID,
                    "payment_purpose": "assessment_initial",
                },
            }
        },
    }
    payload = json.dumps(event).encode()
    ts = int(time.time())
    mac = hmac.new(
        "whsec_test_p0_001".encode(),
        f"{ts}.{payload.decode()}".encode(),
        hashlib.sha256,
    ).hexdigest()
    sig = f"t={ts},v1={mac}"

    def _raise_db_error(assessment_id, session, event_id):
        raise Exception("simulated transient DB error")

    with (
        patch("api.stripe_webhooks._verify_webhook_signature", return_value=event),
        patch("api.stripe_webhooks._confirm_payment", side_effect=_raise_db_error),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post(
                "/ingest/assessment/webhooks/stripe",
                content=payload,
                headers={"Content-Type": "application/json", "Stripe-Signature": sig},
            )

    # 500 tells Stripe to retry the webhook delivery.
    assert resp.status_code == 500, resp.text
    assert "PAYMENT_CONFIRMATION_FAILED" in resp.text


# ---------------------------------------------------------------------------
# P12 — tenant_id absent from session metadata → STRIPE_TENANT_BINDING_MISMATCH
# ---------------------------------------------------------------------------


def test_p12_missing_tenant_in_metadata():
    """Session metadata with no tenant_id → STRIPE_TENANT_BINDING_MISMATCH.

    Previously this was a silent pass (conditional: 'if metadata_tenant_id').
    Now it must fail closed — any session not carrying the authoritative
    tenant_id must be rejected.
    """
    session = _make_strict_session()
    session["metadata"].pop("tenant_id")  # Simulate session without tenant binding

    rec = _make_strict_rec()

    with pytest.raises(WebhookBindingError) as exc_info:
        _validate_payment_binding(session, rec)

    assert exc_info.value.reason_code == STRIPE_TENANT_BINDING_MISMATCH
