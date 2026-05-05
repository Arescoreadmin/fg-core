"""
api/stripe_webhooks.py — Stripe payment webhook handler.

Receives checkout.session.completed and marks the linked assessment as paid.
Signature verification is active when STRIPE_WEBHOOK_SECRET is set.
In dev (no secret), any POST is accepted — never deploy without the secret.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from api.db import get_sessionmaker
from api.db_models import AssessmentRecord, StripeEvent

log = logging.getLogger("frostgate.stripe")

router = APIRouter(prefix="/assessment", tags=["stripe"])

_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()

    if _WEBHOOK_SECRET:
        try:
            import stripe  # noqa: PLC0415 — lazy, only when configured
            sig = request.headers.get("stripe-signature", "")
            event = dict(
                stripe.Webhook.construct_event(payload, sig, _WEBHOOK_SECRET)
            )
        except Exception as exc:
            log.warning("stripe.webhook_sig_failed error=%s", exc)
            raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    else:
        event = json.loads(payload)

    _persist_event(event)

    if event.get("type") == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        assessment_id = session.get("metadata", {}).get("assessment_id")
        if assessment_id:
            _confirm_payment(assessment_id, session.get("id", ""))

    return {"received": True}


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
