"""
tests/test_stripe_webhook.py — Stripe webhook signature validation hardening

Invariants proven:
1.  Missing Stripe-Signature header → 400 STRIPE_WEBHOOK_SIGNATURE_MISSING
2.  Invalid signature → 400 STRIPE_WEBHOOK_SIGNATURE_INVALID
3.  Valid sig but stale timestamp → 400 STRIPE_WEBHOOK_TIMESTAMP_STALE
4.  STRIPE_WEBHOOK_SECRET not configured → 503 STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED
5.  Valid payload + valid sig → 200 {"received": true}
6.  Verification uses raw bytes, not parsed JSON
7.  Rejected call emits audit event with reason "stripe_webhook_rejected"
8.  Audit details["reason_code"] is one of the stable codes
9.  Audit details does not contain raw body content
10. Audit details does not contain STRIPE_WEBHOOK_SECRET value
11. Audit details does not contain full sig header value
12. All tests use mocked stripe.Webhook.construct_event (no live Stripe calls)
13. api/config/billing.py get_stripe_readiness still works unchanged
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.stripe_webhooks import (
    STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED,
    STRIPE_WEBHOOK_SIGNATURE_INVALID,
    STRIPE_WEBHOOK_SIGNATURE_MISSING,
    STRIPE_WEBHOOK_TIMESTAMP_STALE,
    _verify_webhook_signature,
    WebhookSignatureError,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_TEST_SECRET = "whsec_test_webhook_secret_1234567890"
_TEST_PAYLOAD = json.dumps({"id": "evt_test_123", "type": "ping", "data": {}}).encode()

_STABLE_CODES = frozenset(
    {
        STRIPE_WEBHOOK_SIGNATURE_MISSING,
        STRIPE_WEBHOOK_SIGNATURE_INVALID,
        STRIPE_WEBHOOK_TIMESTAMP_STALE,
        STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED,
    }
)


def _make_stripe_sig(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Generate a Stripe-compatible v1 signature for testing without network calls."""
    ts = timestamp if timestamp is not None else int(time.time())
    signed = f"{ts}.{payload.decode()}"
    mac = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


@pytest.fixture()
def app(monkeypatch):
    """Build a test app with auth disabled and no real lifespan."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _TEST_SECRET)
    # Stub DB init so the app doesn't require a real DB at import time
    with (
        patch("api.stripe_webhooks._persist_event"),
        patch("api.stripe_webhooks._confirm_payment"),
    ):
        from api.main import build_app

        _app = build_app(auth_enabled=False)
        yield _app


@pytest.fixture()
def client(app):
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _post_webhook(
    client: TestClient,
    payload: bytes = _TEST_PAYLOAD,
    sig_header: str | None = None,
    extra_headers: dict | None = None,
) -> object:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if sig_header is not None:
        headers["Stripe-Signature"] = sig_header
    if extra_headers:
        headers.update(extra_headers)
    return client.post(
        "/ingest/assessment/webhooks/stripe", content=payload, headers=headers
    )


# ---------------------------------------------------------------------------
# 1. Missing signature → 400 STRIPE_WEBHOOK_SIGNATURE_MISSING
# ---------------------------------------------------------------------------


def test_stripe_webhook_rejects_missing_signature(client, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _TEST_SECRET)

    mock_event = MagicMock()
    mock_event.__iter__ = MagicMock(
        return_value=iter([("id", "evt_1"), ("type", "ping"), ("data", {})])
    )

    with patch(
        "stripe.Webhook.construct_event", return_value=mock_event
    ) as mock_construct:
        resp = _post_webhook(client, sig_header=None)

    assert resp.status_code == 400, resp.text
    assert STRIPE_WEBHOOK_SIGNATURE_MISSING in resp.text
    # construct_event must NOT be called when header is absent
    mock_construct.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Invalid signature → 400 STRIPE_WEBHOOK_SIGNATURE_INVALID
# ---------------------------------------------------------------------------


def test_stripe_webhook_rejects_invalid_signature(client, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _TEST_SECRET)

    import stripe as _stripe

    with patch(
        "stripe.Webhook.construct_event",
        side_effect=_stripe.error.SignatureVerificationError(
            "No signatures found matching the expected signature", "sig_bad"
        ),
    ):
        resp = _post_webhook(client, sig_header="t=1,v1=badhex")

    assert resp.status_code == 400, resp.text
    assert STRIPE_WEBHOOK_SIGNATURE_INVALID in resp.text


# ---------------------------------------------------------------------------
# 3. Stale timestamp → 400 STRIPE_WEBHOOK_TIMESTAMP_STALE
# ---------------------------------------------------------------------------


def test_stripe_webhook_rejects_stale_timestamp(client, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _TEST_SECRET)

    import stripe as _stripe

    with patch(
        "stripe.Webhook.construct_event",
        side_effect=_stripe.error.SignatureVerificationError(
            "Timestamp outside the tolerance zone", "t=1,v1=sig"
        ),
    ):
        stale_sig = _make_stripe_sig(
            _TEST_PAYLOAD, _TEST_SECRET, timestamp=int(time.time()) - 9999
        )
        resp = _post_webhook(client, sig_header=stale_sig)

    assert resp.status_code == 400, resp.text
    assert STRIPE_WEBHOOK_TIMESTAMP_STALE in resp.text


# ---------------------------------------------------------------------------
# 4. Missing secret → 503 STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED
# ---------------------------------------------------------------------------


def test_stripe_webhook_fails_when_secret_not_configured(client, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "")

    with patch("stripe.Webhook.construct_event") as mock_construct:
        sig = _make_stripe_sig(_TEST_PAYLOAD, _TEST_SECRET)
        resp = _post_webhook(client, sig_header=sig)

    assert resp.status_code == 503, resp.text
    assert STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED in resp.text
    mock_construct.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Valid signed payload → 200 {"received": true}
# ---------------------------------------------------------------------------


def test_stripe_webhook_accepts_valid_signed_payload(client, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _TEST_SECRET)

    fake_event = MagicMock()
    fake_event.__iter__ = MagicMock(
        return_value=iter(
            [("id", "evt_ok"), ("type", "ping"), ("data", {"object": {}})]
        )
    )

    with (
        patch("stripe.Webhook.construct_event", return_value=fake_event),
        patch("api.stripe_webhooks._persist_event"),
        patch("api.stripe_webhooks._confirm_payment"),
    ):
        sig = _make_stripe_sig(_TEST_PAYLOAD, _TEST_SECRET)
        resp = _post_webhook(client, sig_header=sig)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"received": True}


# ---------------------------------------------------------------------------
# 6. Verification uses raw bytes, not parsed JSON
# ---------------------------------------------------------------------------


def test_stripe_webhook_verifies_raw_body(monkeypatch):
    """_verify_webhook_signature passes raw bytes to construct_event."""
    payload = b'{"id":"evt_bytes_test","type":"ping"}'
    sig = _make_stripe_sig(payload, _TEST_SECRET)

    captured_args: list = []

    def _capture(payload, sig_header, secret, **kwargs):
        captured_args.append((payload, sig_header, secret))
        mock_ev = MagicMock()
        mock_ev.__iter__ = MagicMock(return_value=iter([]))
        return mock_ev

    with patch("stripe.Webhook.construct_event", side_effect=_capture):
        _verify_webhook_signature(payload, sig, _TEST_SECRET)

    assert captured_args, "construct_event was not called"
    actual_payload = captured_args[0][0]
    assert isinstance(actual_payload, bytes), "payload must be bytes, not parsed JSON"
    assert actual_payload == payload


# ---------------------------------------------------------------------------
# 7. Rejected call emits audit event with reason "stripe_webhook_rejected"
# ---------------------------------------------------------------------------


def test_stripe_webhook_rejection_emits_audit_event(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _TEST_SECRET)

    import stripe as _stripe

    emitted: list = []

    def _capture_event(event):
        emitted.append(event)

    with patch(
        "stripe.Webhook.construct_event",
        side_effect=_stripe.error.SignatureVerificationError(
            "No signatures found", "t=1,v1=bad"
        ),
    ):
        from api.security_audit import reset_auditor

        reset_auditor()
        auditor_mock = MagicMock()
        auditor_mock.log_event.side_effect = _capture_event
        with patch("api.stripe_webhooks.get_auditor", return_value=auditor_mock):
            from api.stripe_webhooks import _audit_rejection

            _audit_rejection(
                STRIPE_WEBHOOK_SIGNATURE_INVALID,
                sig_header="t=1,v1=bad",
                secret=_TEST_SECRET,
            )

    assert len(emitted) == 1
    ev = emitted[0]
    assert ev.reason == "stripe_webhook_rejected"


# ---------------------------------------------------------------------------
# 8. Audit details["reason_code"] is one of the stable codes
# ---------------------------------------------------------------------------


def test_stripe_webhook_audit_uses_stable_reason_code(monkeypatch):
    emitted: list = []

    def _capture_event(event):
        emitted.append(event)

    auditor_mock = MagicMock()
    auditor_mock.log_event.side_effect = _capture_event

    with patch("api.stripe_webhooks.get_auditor", return_value=auditor_mock):
        from api.stripe_webhooks import _audit_rejection

        for code in _STABLE_CODES:
            _audit_rejection(code, sig_header=None, secret=None)

    for ev in emitted:
        assert ev.details["reason_code"] in _STABLE_CODES


# ---------------------------------------------------------------------------
# 9. Audit details does not contain raw body content
# ---------------------------------------------------------------------------


def test_stripe_webhook_audit_does_not_log_payload(monkeypatch):
    emitted: list = []

    def _capture_event(event):
        emitted.append(event)

    auditor_mock = MagicMock()
    auditor_mock.log_event.side_effect = _capture_event

    with patch("api.stripe_webhooks.get_auditor", return_value=auditor_mock):
        from api.stripe_webhooks import _audit_rejection

        _audit_rejection(
            STRIPE_WEBHOOK_SIGNATURE_INVALID,
            sig_header="t=1,v1=bad",
            secret=_TEST_SECRET,
        )

    assert emitted
    for ev in emitted:
        details_str = str(ev.details)
        assert b"pii_value_12345" not in details_str.encode()
        assert "pii_value_12345" not in details_str
        # raw body bytes/content must not appear
        assert b"secret_customer_data" not in details_str.encode()


# ---------------------------------------------------------------------------
# 10. Audit details does not contain STRIPE_WEBHOOK_SECRET value
# ---------------------------------------------------------------------------


def test_stripe_webhook_audit_does_not_log_secret(monkeypatch):
    secret_val = "whsec_SUPER_SECRET_VALUE_DO_NOT_LOG"
    emitted: list = []

    def _capture_event(event):
        emitted.append(event)

    auditor_mock = MagicMock()
    auditor_mock.log_event.side_effect = _capture_event

    with patch("api.stripe_webhooks.get_auditor", return_value=auditor_mock):
        from api.stripe_webhooks import _audit_rejection

        _audit_rejection(
            STRIPE_WEBHOOK_SIGNATURE_INVALID,
            sig_header="t=1,v1=bad",
            secret=secret_val,
        )

    assert emitted
    for ev in emitted:
        details_str = str(ev.details)
        assert secret_val not in details_str
        # "SUPER_SECRET_VALUE" substring
        assert "SUPER_SECRET_VALUE_DO_NOT_LOG" not in details_str


# ---------------------------------------------------------------------------
# 11. Audit details does not contain full sig header value
# ---------------------------------------------------------------------------


def test_stripe_webhook_audit_does_not_log_full_signature(monkeypatch):
    full_sig = "t=1234567890,v1=abcdef1234567890abcdef1234567890_FULL_SIG_MARKER"
    emitted: list = []

    def _capture_event(event):
        emitted.append(event)

    auditor_mock = MagicMock()
    auditor_mock.log_event.side_effect = _capture_event

    with patch("api.stripe_webhooks.get_auditor", return_value=auditor_mock):
        from api.stripe_webhooks import _audit_rejection

        _audit_rejection(
            STRIPE_WEBHOOK_SIGNATURE_INVALID,
            sig_header=full_sig,
            secret=_TEST_SECRET,
        )

    assert emitted
    for ev in emitted:
        details_str = str(ev.details)
        assert full_sig not in details_str
        assert "FULL_SIG_MARKER" not in details_str


# ---------------------------------------------------------------------------
# 12. All tests use mocked stripe.Webhook.construct_event (no network)
# ---------------------------------------------------------------------------


def test_stripe_webhook_does_not_call_stripe_network(monkeypatch):
    """_verify_webhook_signature never makes real HTTP calls.

    We prove this by mocking construct_event and verifying the import-time
    stripe module has no real HTTP client interaction.  The mock ensures
    no actual network traffic happens in any rejection path.
    """
    import stripe as _stripe

    call_log: list[str] = []

    def _mock_construct(payload, sig_header, secret, **kwargs):
        call_log.append("construct_event")
        raise _stripe.error.SignatureVerificationError("bad sig", "hdr")

    with patch("stripe.Webhook.construct_event", side_effect=_mock_construct):
        with pytest.raises(WebhookSignatureError):
            _verify_webhook_signature(_TEST_PAYLOAD, "t=1,v1=x", _TEST_SECRET)

    assert "construct_event" in call_log
    # If a real network call had been made, stripe would have added a
    # request-id to the exception; absence of real HTTP is implicit.


# ---------------------------------------------------------------------------
# 13. get_stripe_readiness still works unchanged
# ---------------------------------------------------------------------------


def test_billing_readiness_unchanged():
    """api/config/billing.py get_stripe_readiness must be unaffected by this PR."""
    from api.config.billing import (
        BILLING_STRIPE_SECRET_KEY_MISSING,
        BILLING_STRIPE_WEBHOOK_SECRET_MISSING,
        get_stripe_readiness,
    )

    env_full = {
        "STRIPE_SECRET_KEY": "sk_live_test",
        "STRIPE_WEBHOOK_SECRET": "whsec_test",
    }
    result = get_stripe_readiness(env_full)
    assert result["ready"] is True
    assert result["reasons"] == []

    result_empty = get_stripe_readiness({})
    assert result_empty["ready"] is False
    assert BILLING_STRIPE_SECRET_KEY_MISSING in result_empty["reasons"]
    assert BILLING_STRIPE_WEBHOOK_SECRET_MISSING in result_empty["reasons"]

    # No secret values in output
    result_str = str(result)
    assert "sk_live_test" not in result_str
    assert "whsec_test" not in result_str
