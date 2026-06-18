"""services/billing/metering.py — Usage event recording with idempotency (P1.5).

record_usage_event is the single write path for usage. It validates the meter,
enforces idempotency, appends a BillingEventLedger entry, and optionally
reports to the provider (fail-open on provider errors).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from api.db_models_billing import BillingEventLedger, UsageEvent, UsageMeter
from api.db_models_subscriptions import SubscriptionItem

log = logging.getLogger("frostgate.billing.metering")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _compute_event_hash(
    prev_hash: str,
    tenant_id: str,
    event_type: str,
    entity_id: str,
    occurred_at: datetime,
    actor: str,
) -> str:
    payload = (
        f"{prev_hash}|{tenant_id}|{event_type}|{entity_id}"
        f"|{occurred_at.isoformat()}|{actor}"
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _get_prev_hash(db: Session, tenant_id: str) -> str:
    """Return the event_hash of the most recent ledger entry for this tenant."""
    row = (
        db.query(BillingEventLedger)
        .filter(BillingEventLedger.tenant_id == tenant_id)
        .order_by(BillingEventLedger.occurred_at.desc())
        .first()
    )
    return row.event_hash if row is not None else "GENESIS"


def _append_ledger_entry(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    entity_type: str,
    entity_id: str,
    provider: str = "system",
    old_state: str | None = None,
    new_state: str | None = None,
    actor: str = "system",
    reason: str | None = None,
) -> BillingEventLedger:
    occurred_at = _utcnow()
    prev_hash = _get_prev_hash(db, tenant_id)
    event_hash = _compute_event_hash(
        prev_hash, tenant_id, event_type, entity_id, occurred_at, actor
    )
    entry = BillingEventLedger(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        provider=provider,
        old_state=old_state,
        new_state=new_state,
        actor=actor,
        reason=reason,
        occurred_at=occurred_at,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(entry)
    db.flush()
    return entry


def record_usage_event(
    db: Session,
    tenant_id: str,
    meter_code: str,
    quantity: str,
    idempotency_key: str,
    *,
    subscription_item_id: str | None = None,
    source: str = "api",
    occurred_at: datetime | None = None,
    metadata_json: dict | None = None,
    provider=None,
) -> UsageEvent:
    """Record a usage event with idempotency and optional provider reporting.

    Returns the existing record if (tenant_id, idempotency_key) already exists,
    so callers can safely retry without double-counting.
    """
    meter = db.query(UsageMeter).filter(UsageMeter.meter_code == meter_code).first()
    if meter is None:
        raise ValueError(f"Unknown meter_code: {meter_code!r}")
    if meter.active != "1":
        raise ValueError(f"Meter {meter_code!r} is not active")

    existing = (
        db.query(UsageEvent)
        .filter(
            UsageEvent.tenant_id == tenant_id,
            UsageEvent.idempotency_key == idempotency_key,
        )
        .first()
    )
    if existing is not None:
        return existing

    if subscription_item_id is not None:
        item = (
            db.query(SubscriptionItem)
            .filter(
                SubscriptionItem.id == subscription_item_id,
                SubscriptionItem.tenant_id == tenant_id,
            )
            .first()
        )
        if item is None:
            raise ValueError(
                f"subscription_item_id {subscription_item_id!r} not found for tenant"
            )

    evt = UsageEvent(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        subscription_item_id=subscription_item_id,
        meter_code=meter_code,
        quantity=quantity,
        idempotency_key=idempotency_key,
        source=source,
        occurred_at=occurred_at or _utcnow(),
        metadata_json=metadata_json or {},
        billing_status="pending",
    )
    db.add(evt)
    db.flush()

    _append_ledger_entry(
        db,
        tenant_id=tenant_id,
        event_type="usage_recorded",
        entity_type="usage_event",
        entity_id=evt.id,
        new_state="pending",
    )

    if provider is not None:
        from services.billing.provider import NullBillingProvider  # noqa: PLC0415

        if not isinstance(provider, NullBillingProvider):
            try:
                result = provider.report_usage(
                    "",
                    meter_code,
                    quantity,
                    idempotency_key,
                )
                provider_event_id = result.get("id")
                # Use core SQL to bypass the ORM append-only guard for authorized transitions
                db.execute(
                    update(UsageEvent)
                    .where(UsageEvent.id == evt.id)
                    .values(
                        billing_status="reported",
                        provider_event_id=provider_event_id,
                    )
                )
                db.expire(evt)
            except Exception as exc:
                log.warning(
                    "billing.report_usage_failed meter=%s error=%s",
                    meter_code,
                    exc,
                )

    return evt
