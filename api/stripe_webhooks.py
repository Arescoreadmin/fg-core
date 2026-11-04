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
  STRIPE_PAYMENT_NOT_PAID               — payment_status != 'paid' on session
  STRIPE_TENANT_BINDING_MISMATCH        — session tenant_id doesn't match record
  STRIPE_AMOUNT_MISMATCH                — amount_total != expected_amount_cents
  STRIPE_CURRENCY_MISMATCH              — currency != 'usd'
  STRIPE_ASSESSMENT_NOT_FOUND           — assessment_id not in DB
  STRIPE_SESSION_ID_MISMATCH            — session.id != record.stripe_session_id
  STRIPE_INVOICE_NOT_FOUND              — invoice_id not in DB
"""

from __future__ import annotations

import logging
import os
from typing import Any

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
STRIPE_PAYMENT_NOT_PAID = "STRIPE_PAYMENT_NOT_PAID"
STRIPE_TENANT_BINDING_MISMATCH = "STRIPE_TENANT_BINDING_MISMATCH"
STRIPE_AMOUNT_MISMATCH = "STRIPE_AMOUNT_MISMATCH"
STRIPE_CURRENCY_MISMATCH = "STRIPE_CURRENCY_MISMATCH"
STRIPE_ASSESSMENT_NOT_FOUND = "STRIPE_ASSESSMENT_NOT_FOUND"
STRIPE_SESSION_ID_MISMATCH = "STRIPE_SESSION_ID_MISMATCH"
STRIPE_INVOICE_NOT_FOUND = "STRIPE_INVOICE_NOT_FOUND"

# Required currency for all assessments.
_REQUIRED_CURRENCY = "usd"


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


class WebhookBindingError(Exception):
    """Raised when server-side binding validation fails."""

    def __init__(self, reason_code: str, details: dict | None = None) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.details: dict = details or {}


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
) -> dict:
    """Verify a Stripe webhook signature.

    Args:
        raw_body:   Raw request bytes (not parsed JSON).
        sig_header: Value of the Stripe-Signature header, or None if absent.
        secret:     STRIPE_WEBHOOK_SECRET value.

    Returns:
        The stripe.Event as a dict on success.

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
        return dict(event)
    except stripe.error.SignatureVerificationError as exc:
        _msg = str(exc).lower()
        if "outside the tolerance zone" in _msg or "timestamp outside" in _msg:
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


def _audit_binding_rejection(reason_code: str, details: dict) -> None:
    """Emit a security audit event for a binding validation failure.

    Never logs amounts that could expose customer data, only structural fields.
    """
    try:
        safe_details = {
            "reason_code": reason_code,
            "assessment_id": details.get("assessment_id"),
            "tenant_id": details.get("tenant_id"),
            "event_type": details.get("event_type"),
        }
        get_auditor().log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                success=False,
                severity=Severity.WARNING,
                tenant_id=details.get("tenant_id", "stripe"),
                reason="stripe_payment_binding_rejected",
                details=safe_details,
            )
        )
    except Exception:
        log.warning("stripe.binding_audit_failed reason_code=%s", reason_code)


def _audit_payment_confirmed(assessment_id: str, tenant_id: str, event_id: str) -> None:
    """Emit an audit event when a payment is successfully confirmed."""
    try:
        get_auditor().log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                success=True,
                severity=Severity.INFO,
                tenant_id=tenant_id,
                reason="stripe_payment_confirmed",
                details={
                    "assessment_id": assessment_id,
                    "stripe_event_id": event_id,
                },
            )
        )
    except Exception:
        log.warning("stripe.payment_audit_failed assessment_id=%s", assessment_id)


# ---------------------------------------------------------------------------
# Server-side binding validation
# ---------------------------------------------------------------------------


def _validate_payment_binding(
    session: dict[str, Any],
    rec: AssessmentRecord,
) -> None:
    """Validate Stripe session against authoritative DB record.

    Checks:
      1. payment_status == 'paid' on the Stripe session
      2. currency == 'usd'
      3. tenant_id from session metadata matches record.tenant_id
      4. stripe_session_id matches record (if already set)
      5. expected_amount_cents matches session amount_total (if set on record)

    Raises:
        WebhookBindingError with stable reason code on any mismatch.
    """
    assessment_id = rec.id
    tenant_id = rec.tenant_id

    # 1. Confirm payment is actually paid
    if session.get("payment_status") != "paid":
        raise WebhookBindingError(
            STRIPE_PAYMENT_NOT_PAID,
            {
                "assessment_id": assessment_id,
                "tenant_id": tenant_id,
                "event_type": "checkout.session.completed",
            },
        )

    # 2. Currency must be usd
    if session.get("currency") != _REQUIRED_CURRENCY:
        raise WebhookBindingError(
            STRIPE_CURRENCY_MISMATCH,
            {
                "assessment_id": assessment_id,
                "tenant_id": tenant_id,
                "event_type": "checkout.session.completed",
            },
        )

    # 3. Tenant binding — session metadata must match DB record
    metadata_tenant_id = session.get("metadata", {}).get("tenant_id")
    if metadata_tenant_id and metadata_tenant_id != tenant_id:
        raise WebhookBindingError(
            STRIPE_TENANT_BINDING_MISMATCH,
            {
                "assessment_id": assessment_id,
                "tenant_id": tenant_id,
                "event_type": "checkout.session.completed",
            },
        )

    # 4. Session ID must match if already recorded server-side
    session_id = session.get("id", "")
    if rec.stripe_session_id and rec.stripe_session_id != session_id:
        raise WebhookBindingError(
            STRIPE_SESSION_ID_MISMATCH,
            {
                "assessment_id": assessment_id,
                "tenant_id": tenant_id,
                "event_type": "checkout.session.completed",
            },
        )

    # 5. Amount must match expected (if recorded server-side)
    if rec.expected_amount_cents is not None:
        amount_total = session.get("amount_total")
        if amount_total != rec.expected_amount_cents:
            raise WebhookBindingError(
                STRIPE_AMOUNT_MISMATCH,
                {
                    "assessment_id": assessment_id,
                    "tenant_id": tenant_id,
                    "event_type": "checkout.session.completed",
                },
            )


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

    _persist_event(event)

    if event.get("type") == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        assessment_id = session.get("metadata", {}).get("assessment_id")
        if assessment_id:
            try:
                _confirm_payment(assessment_id, session, event.get("id", ""))
            except WebhookBindingError as exc:
                _audit_binding_rejection(exc.reason_code, exc.details)
                raise HTTPException(
                    status_code=400,
                    detail=exc.reason_code,
                ) from exc

    return {"received": True}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _confirm_payment(
    assessment_id: str,
    session: dict[str, Any],
    event_id: str,
) -> None:
    """Confirm an assessment payment after server-side binding validation.

    Validates:
      - Assessment exists in DB
      - payment_status == 'paid' on the Stripe session object
      - currency == 'usd'
      - tenant_id metadata matches DB record (if present in metadata)
      - stripe_session_id matches DB record (if already set)
      - expected_amount_cents matches session amount_total (if set on record)

    Then atomically transitions payment_status → 'paid' and writes audit entry.
    Idempotent: if already 'paid', returns without error.
    """
    stripe_session_id = session.get("id", "")
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        rec = (
            db.query(AssessmentRecord)
            .filter(AssessmentRecord.id == assessment_id)
            .first()
        )
        if rec is None:
            raise WebhookBindingError(
                STRIPE_ASSESSMENT_NOT_FOUND,
                {
                    "assessment_id": assessment_id,
                    "tenant_id": "unknown",
                    "event_type": "checkout.session.completed",
                },
            )

        # Idempotent — already confirmed
        if rec.payment_status == "paid":
            return

        # Validate binding server-side — raises WebhookBindingError on failure
        _validate_payment_binding(session, rec)

        rec.payment_status = "paid"
        rec.stripe_session_id = stripe_session_id
        db.commit()
        log.info("assessment.payment_confirmed assessment_id=%s", assessment_id)
        _audit_payment_confirmed(assessment_id, rec.tenant_id, event_id)
    except WebhookBindingError:
        db.rollback()
        raise
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
