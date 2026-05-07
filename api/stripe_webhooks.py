"""
api/stripe_webhooks.py — Stripe payment webhook handler.

Receives checkout.session.completed and marks the linked assessment as paid.
Signature verification is ALWAYS required — unsigned requests are rejected with
a 400 error and an audit event.  The STRIPE_WEBHOOK_SECRET env var must be
present and non-blank; if it is missing, the endpoint returns 503 rather than
silently accepting unsigned payloads.

Stable rejection reason codes:
  STRIPE_WEBHOOK_SIGNATURE_MISSING       — Stripe-Signature header absent
  STRIPE_WEBHOOK_SIGNATURE_INVALID       — header present but signature bad
  STRIPE_WEBHOOK_TIMESTAMP_STALE        — signature valid but timestamp stale
  STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED  — STRIPE_WEBHOOK_SECRET not set (503)
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, Request

from api.db import get_sessionmaker
from api.db_models import AssessmentRecord, StripeEvent
from api.security_audit import AuditEvent, EventType, Severity, get_auditor

log = logging.getLogger("frostgate.stripe")

router = APIRouter(prefix="/ingest/assessment", tags=["stripe"])

# ---------------------------------------------------------------------------
# Stable error codes — never change the string values once deployed.
# ---------------------------------------------------------------------------

STRIPE_WEBHOOK_SIGNATURE_MISSING = "STRIPE_WEBHOOK_SIGNATURE_MISSING"
STRIPE_WEBHOOK_SIGNATURE_INVALID = "STRIPE_WEBHOOK_SIGNATURE_INVALID"
STRIPE_WEBHOOK_TIMESTAMP_STALE = "STRIPE_WEBHOOK_TIMESTAMP_STALE"
STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED = "STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED"


# ---------------------------------------------------------------------------
# Custom exception types
# ---------------------------------------------------------------------------


class WebhookConfigError(Exception):
    """Raised when the webhook secret is not configured."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class WebhookSignatureError(Exception):
    """Raised when signature verification fails."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _get_webhook_secret() -> str:
    """Return STRIPE_WEBHOOK_SECRET from environment."""
    return (os.environ.get("STRIPE_WEBHOOK_SECRET") or "").strip()


def _verify_webhook_signature(
    raw_body: bytes,
    sig_header: str | None,
    secret: str | None,
) -> object:
    """Verify a Stripe webhook signature.

    Args:
        raw_body:   Raw request bytes (not parsed JSON).
        sig_header: Value of the Stripe-Signature header, or None if absent.
        secret:     STRIPE_WEBHOOK_SECRET value.

    Returns:
        A stripe.Event object on success.

    Raises:
        WebhookConfigError:    STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED when secret absent.
        WebhookSignatureError: STRIPE_WEBHOOK_SIGNATURE_MISSING when header absent.
        WebhookSignatureError: STRIPE_WEBHOOK_TIMESTAMP_STALE or
                               STRIPE_WEBHOOK_SIGNATURE_INVALID on bad sig.
    """
    if not secret:
        raise WebhookConfigError(STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED)
    if not sig_header:
        raise WebhookSignatureError(STRIPE_WEBHOOK_SIGNATURE_MISSING)

    import stripe  # noqa: PLC0415 — lazy import; only when configured

    try:
        event = stripe.Webhook.construct_event(
            payload=raw_body,
            sig_header=sig_header,
            secret=secret,
        )
        return event
    except stripe.error.SignatureVerificationError as exc:
        if "timestamp" in str(exc).lower():
            raise WebhookSignatureError(STRIPE_WEBHOOK_TIMESTAMP_STALE) from exc
        raise WebhookSignatureError(STRIPE_WEBHOOK_SIGNATURE_INVALID) from exc


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------


def _audit_rejection(
    reason_code: str,
    sig_header: str | None,
    secret: str | None,
) -> None:
    """Emit a security audit event for a rejected webhook.

    Never logs raw_body, the sig_header value, or the secret value.
    """
    try:
        get_auditor().log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                success=False,
                severity=Severity.WARNING,
                tenant_id="stripe",
                reason="stripe_webhook_rejected",
                details={
                    "reason_code": reason_code,
                    "signature_present": sig_header is not None,
                    "secret_configured": bool(secret),
                },
            )
        )
    except Exception:
        log.warning("stripe.webhook_audit_failed reason_code=%s", reason_code)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    raw_body = await request.body()
    sig_header = request.headers.get("Stripe-Signature")
    secret = _get_webhook_secret()

    try:
        event = _verify_webhook_signature(raw_body, sig_header, secret)
    except WebhookConfigError as exc:
        _audit_rejection(exc.reason_code, sig_header, secret)
        raise HTTPException(
            status_code=503,
            detail=exc.reason_code,
        )
    except WebhookSignatureError as exc:
        _audit_rejection(exc.reason_code, sig_header, secret)
        raise HTTPException(
            status_code=400,
            detail=exc.reason_code,
        )

    event_dict = dict(event)
    _persist_event(event_dict)

    if event_dict.get("type") == "checkout.session.completed":
        session = event_dict.get("data", {}).get("object", {})
        assessment_id = session.get("metadata", {}).get("assessment_id")
        if assessment_id:
            _confirm_payment(assessment_id, session.get("id", ""))

    return {"received": True}


# ---------------------------------------------------------------------------
# DB helpers (unchanged from original)
# ---------------------------------------------------------------------------


def _confirm_payment(assessment_id: str, stripe_session_id: str) -> None:
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        rec = (
            db.query(AssessmentRecord)
            .filter(AssessmentRecord.id == assessment_id)
            .first()
        )
        if rec and rec.payment_status != "paid":
            rec.payment_status = "paid"
            rec.stripe_session_id = stripe_session_id
            db.commit()
            log.info("assessment.payment_confirmed assessment_id=%s", assessment_id)
    except Exception as exc:
        log.error(
            "stripe.confirm_payment_failed assessment_id=%s error=%s",
            assessment_id,
            exc,
        )
        db.rollback()
    finally:
        db.close()


def _persist_event(event: dict) -> None:
    event_id = event.get("id", "")
    if not event_id:
        return
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        exists = (
            db.query(StripeEvent)
            .filter(StripeEvent.stripe_event_id == event_id)
            .first()
        )
        if not exists:
            db.add(
                StripeEvent(
                    stripe_event_id=event_id,
                    event_type=event.get("type", ""),
                    payload=event,
                )
            )
            db.commit()
    except Exception as exc:
        log.warning("stripe.persist_event_failed event_id=%s error=%s", event_id, exc)
        db.rollback()
    finally:
        db.close()
