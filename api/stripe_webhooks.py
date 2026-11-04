"""
api/stripe_webhooks.py — Stripe payment webhook handler.

Receives checkout.session.completed and marks the linked assessment as paid.
Signature verification is ALWAYS required — unsigned requests are rejected with
a 400 error and an audit event.  The STRIPE_WEBHOOK_SECRET env var must be
present and non-blank; if it is missing, the endpoint returns 503 rather than
silently accepting unsigned payloads.

Payment confirmation is ATOMIC: the StripeEvent record and the
AssessmentRecord.payment_status update are committed in a single DB transaction.
If either write fails the entire transaction is rolled back and payment_status
remains unpaid.  The external SecurityAuditLog entry is best-effort after
commit and does not affect payment authority.

Stable rejection reason codes:
  STRIPE_WEBHOOK_SIGNATURE_MISSING       — Stripe-Signature header absent
  STRIPE_WEBHOOK_SIGNATURE_INVALID       — header present but signature bad
  STRIPE_WEBHOOK_TIMESTAMP_STALE        — signature valid but timestamp stale
  STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED  — STRIPE_WEBHOOK_SECRET not set (503)
  STRIPE_PAYMENT_NOT_PAID               — payment_status != 'paid' on session
  STRIPE_TENANT_BINDING_MISMATCH        — tenant_id absent or mismatched
  STRIPE_AMOUNT_MISMATCH                — amount_total != expected_amount_cents
  STRIPE_MISSING_AMOUNT_BINDING         — expected_amount_cents not set on record
  STRIPE_CURRENCY_MISMATCH              — currency != 'usd'
  STRIPE_ASSESSMENT_NOT_FOUND           — assessment_id not in DB
  STRIPE_SESSION_ID_MISMATCH            — session.id != record.stripe_session_id
  STRIPE_MISSING_SESSION_BINDING        — stripe_session_id not set on record
  STRIPE_PAYMENT_PURPOSE_MISMATCH       — payment_purpose != 'assessment_initial'
  STRIPE_INVOICE_NOT_FOUND              — invoice_id not in DB
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
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
STRIPE_MISSING_AMOUNT_BINDING = "STRIPE_MISSING_AMOUNT_BINDING"
STRIPE_CURRENCY_MISMATCH = "STRIPE_CURRENCY_MISMATCH"
STRIPE_ASSESSMENT_NOT_FOUND = "STRIPE_ASSESSMENT_NOT_FOUND"
STRIPE_SESSION_ID_MISMATCH = "STRIPE_SESSION_ID_MISMATCH"
STRIPE_MISSING_SESSION_BINDING = "STRIPE_MISSING_SESSION_BINDING"
STRIPE_PAYMENT_PURPOSE_MISMATCH = "STRIPE_PAYMENT_PURPOSE_MISMATCH"
STRIPE_INVOICE_NOT_FOUND = "STRIPE_INVOICE_NOT_FOUND"

# Required values for all assessment payments — never accept variations.
_REQUIRED_CURRENCY = "usd"
_REQUIRED_PAYMENT_PURPOSE = "assessment_initial"


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

    All checks are strict and unconditional — missing server-side bindings
    fail closed rather than passing.  Every check that was optional in the
    previous implementation is now required.

    Checks (in order):
      1. payment_status == 'paid' on the Stripe session
      2. currency == 'usd'
      3. tenant_id present in session metadata AND matches record.tenant_id
      4. stripe_session_id set on record AND matches session.id
      5. expected_amount_cents set on record AND matches session amount_total
      6. payment_purpose in session metadata == 'assessment_initial'

    Raises:
        WebhookBindingError with stable reason code on any failure.
    """
    assessment_id = rec.id
    tenant_id = rec.tenant_id

    def _err(code: str) -> WebhookBindingError:
        return WebhookBindingError(
            code,
            {
                "assessment_id": assessment_id,
                "tenant_id": tenant_id,
                "event_type": "checkout.session.completed",
            },
        )

    # 1. Confirm payment is actually paid
    if session.get("payment_status") != "paid":
        raise _err(STRIPE_PAYMENT_NOT_PAID)

    # 2. Currency must be usd
    if session.get("currency") != _REQUIRED_CURRENCY:
        raise _err(STRIPE_CURRENCY_MISMATCH)

    # 3. Tenant binding — metadata must carry tenant_id AND it must match.
    # Absent tenant_id in metadata is not a pass — it means the session was
    # created outside the authoritative checkout path.
    metadata = session.get("metadata") or {}
    metadata_tenant_id = (metadata.get("tenant_id") or "").strip()
    if not metadata_tenant_id or metadata_tenant_id != tenant_id:
        raise _err(STRIPE_TENANT_BINDING_MISMATCH)

    # 4. Session ID — must be set on record (checkout wrote it) and must match.
    # An unset stripe_session_id means the checkout endpoint was never called;
    # do not confirm payment for a session we never issued.
    session_id = (session.get("id") or "").strip()
    if not rec.stripe_session_id:
        raise _err(STRIPE_MISSING_SESSION_BINDING)
    if rec.stripe_session_id != session_id:
        raise _err(STRIPE_SESSION_ID_MISMATCH)

    # 5. Amount — must be set on record and must match exactly.
    if rec.expected_amount_cents is None:
        raise _err(STRIPE_MISSING_AMOUNT_BINDING)
    if session.get("amount_total") != rec.expected_amount_cents:
        raise _err(STRIPE_AMOUNT_MISMATCH)

    # 6. Payment purpose — session metadata must declare 'assessment_initial'.
    # Subscription renewals, refunds, or other events must not confirm
    # an assessment payment.
    metadata_purpose = (metadata.get("payment_purpose") or "").strip()
    if metadata_purpose != _REQUIRED_PAYMENT_PURPOSE:
        raise _err(STRIPE_PAYMENT_PURPOSE_MISMATCH)


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

    if event.get("type") == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        assessment_id = (session.get("metadata") or {}).get("assessment_id")
        if assessment_id:
            try:
                # _confirm_payment writes the StripeEvent atomically —
                # _persist_event is not called separately for checkout events.
                _confirm_payment(assessment_id, session, event.get("id", ""))
            except WebhookBindingError as exc:
                _audit_binding_rejection(exc.reason_code, exc.details)
                raise HTTPException(
                    status_code=400,
                    detail=exc.reason_code,
                ) from exc
            except Exception:
                # DB or unexpected error — return 500 so Stripe retries.
                raise HTTPException(
                    status_code=500, detail="PAYMENT_CONFIRMATION_FAILED"
                )
    else:
        # Non-checkout events: persist for observability only.
        _persist_event(event)

    return {"received": True}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _confirm_payment(
    assessment_id: str,
    session: dict[str, Any],
    event_id: str,
) -> None:
    """Confirm an assessment payment atomically.

    Atomicity guarantee: AssessmentRecord.payment_status and the StripeEvent
    record (which is the durable payment audit anchor) are updated in a single
    DB transaction.  If either write fails, the entire transaction is rolled
    back and payment_status remains unpaid.  The external SecurityAuditLog
    entry is written as best-effort AFTER commit and does not affect payment
    authority.

    Concurrency: AssessmentRecord is locked FOR UPDATE at the start.  On
    PostgreSQL this serializes concurrent webhook deliveries for the same
    assessment — the second delivery sees payment_status='paid' and returns
    idempotently.  On SQLite the hint is ignored but the unique constraint on
    stripe_event_id still prevents double-confirmation.

    Idempotent: if payment_status is already 'paid', returns without error.
    """
    stripe_session_id = (session.get("id") or "").strip()
    now = datetime.now(timezone.utc)

    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    confirmed_tenant_id: str | None = None
    try:
        # Lock the row to serialise concurrent webhook deliveries.
        rec = (
            db.query(AssessmentRecord)
            .filter(AssessmentRecord.id == assessment_id)
            .with_for_update()
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

        # Idempotent — already confirmed (safe under concurrent delivery).
        if rec.payment_status == "paid":
            return

        # Full binding validation — all checks strict, no optional skips.
        _validate_payment_binding(session, rec)

        confirmed_tenant_id = rec.tenant_id

        # Update payment state.
        rec.payment_status = "paid"
        rec.stripe_session_id = stripe_session_id

        # Write or update the StripeEvent in the SAME transaction.
        # This record is the durable payment audit anchor; it commits
        # atomically with payment_status so they cannot diverge.
        event_record = (
            db.query(StripeEvent)
            .filter(StripeEvent.stripe_event_id == event_id)
            .with_for_update()
            .first()
        )
        if event_record is None:
            event_record = StripeEvent(
                stripe_event_id=event_id,
                event_type="checkout.session.completed",
                payload=session,
            )
            db.add(event_record)

        event_record.payment_confirmed_at = now

        # Single commit — payment state and audit record are atomic.
        db.commit()
        log.info("assessment.payment_confirmed assessment_id=%s", assessment_id)

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
        # Re-raise so the webhook handler returns a retryable 500.
        raise
    finally:
        db.close()

    # Best-effort SecurityAuditLog — after commit, non-correctness-critical.
    if confirmed_tenant_id:
        _audit_payment_confirmed(assessment_id, confirmed_tenant_id, event_id)


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
