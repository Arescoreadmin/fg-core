"""api/billing_v2.py — Billing Integration Layer API (P1.5).

15 routes — provider-agnostic billing bridge. Billing observes and monetizes
commercial state; it NEVER grants or revokes entitlements.

Routes:
  POST   /admin/billing/accounts                               admin:write
  GET    /admin/billing/accounts/{account_id}                  admin:read
  GET    /admin/tenants/{tenant_id}/billing/account            admin:read
  PATCH  /admin/billing/accounts/{account_id}                  admin:write
  POST   /admin/billing/subscription-links                     admin:write
  GET    /admin/billing/subscription-links/{link_id}           admin:read
  GET    /admin/tenants/{tenant_id}/billing/subscription-links admin:read
  POST   /admin/billing/subscription-links/{link_id}/sync      admin:write
  POST   /admin/billing/meters                                 admin:write
  GET    /admin/billing/meters                                 admin:read
  PATCH  /admin/billing/meters/{meter_code}                    admin:write
  POST   /billing/usage/events                                 (require_bound_tenant)
  GET    /admin/tenants/{tenant_id}/billing/usage              admin:read
  POST   /billing/webhooks/stripe                              (public, sig-verified)
  GET    /admin/billing/explain                                admin:read + bound_tenant
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models_billing import BillingEventLedger, BillingSubscriptionLink
from api.observability.metrics import (
    BILLING_WEBHOOK_REPLAY_TOTAL,
    BILLING_WEBHOOKS_TOTAL,
)
from services.billing.engine import BillingEngine
from services.billing.models import (
    BillingAccountResponse,
    BillingExplainResponse,
    BillingSubscriptionLinkResponse,
    CreateBillingAccountRequest,
    CreateBillingSubscriptionLinkRequest,
    CreateUsageMeterRequest,
    RecordUsageEventRequest,
    UpdateBillingAccountRequest,
    UpdateUsageMeterRequest,
    UsageEventResponse,
    UsageMeterResponse,
)
from services.billing.metering import _append_ledger_entry
from services.billing.provider import BillingProvider, NullBillingProvider
from services.billing.stripe_provider import ProviderNotConfiguredError, StripeProvider

log = logging.getLogger("frostgate.billing.api")

router = APIRouter(tags=["billing"])
_engine = BillingEngine()

# Stripe webhook event types that affect subscription link sync_status
_SUBSCRIPTION_UPDATED_TYPES = frozenset(
    {
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.payment_failed",
        "invoice.payment_succeeded",
    }
)

_SYNC_STATUS_MAP = {
    "customer.subscription.updated": "synced",
    "customer.subscription.deleted": "disabled",
    "invoice.payment_failed": "failed",
    "invoice.payment_succeeded": "synced",
}


# ---------------------------------------------------------------------------
# Billing accounts
# ---------------------------------------------------------------------------


@router.post(
    "/admin/billing/accounts",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=BillingAccountResponse,
)
def create_billing_account(
    tenant_id: str,
    body: CreateBillingAccountRequest,
    request: Request,
) -> BillingAccountResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        try:
            account = _engine.create_billing_account(
                db,
                tenant_id=tenant_id,
                provider=body.provider,
                billing_email=body.billing_email,
                billing_status=body.billing_status,
                metadata_json=body.metadata_json,
                provider_customer_id=body.provider_customer_id,
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return account


@router.get(
    "/admin/billing/accounts/{account_id}",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=BillingAccountResponse,
)
def get_billing_account(
    account_id: str,
    tenant_id: str,
    request: Request,
) -> BillingAccountResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        account = _engine.get_billing_account(db, account_id)
    if account is None:
        raise HTTPException(
            status_code=404, detail={"code": "BILLING_ACCOUNT_NOT_FOUND"}
        )
    return account


@router.get(
    "/admin/tenants/{tenant_id}/billing/account",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=BillingAccountResponse,
)
def get_billing_account_for_tenant(
    tenant_id: str,
    request: Request,
    provider: str = "stripe",
) -> BillingAccountResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        account = _engine.get_billing_account_for_tenant(db, tenant_id, provider)
    if account is None:
        raise HTTPException(
            status_code=404, detail={"code": "BILLING_ACCOUNT_NOT_FOUND"}
        )
    return account


@router.patch(
    "/admin/billing/accounts/{account_id}",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=BillingAccountResponse,
)
def update_billing_account(
    account_id: str,
    tenant_id: str,
    body: UpdateBillingAccountRequest,
    request: Request,
) -> BillingAccountResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        try:
            account = _engine.update_billing_account(db, account_id, body)
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return account


# ---------------------------------------------------------------------------
# Subscription links
# ---------------------------------------------------------------------------


@router.post(
    "/admin/billing/subscription-links",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=BillingSubscriptionLinkResponse,
)
def create_subscription_link(
    body: CreateBillingSubscriptionLinkRequest,
    request: Request,
) -> BillingSubscriptionLinkResponse:
    bind_tenant_id(request, body.tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        try:
            link = _engine.create_subscription_link(
                db,
                tenant_id=body.tenant_id,
                subscription_contract_id=body.subscription_contract_id,
                subscription_item_id=body.subscription_item_id,
                provider=body.provider,
                provider_subscription_id=body.provider_subscription_id,
                provider_price_id=body.provider_price_id,
                provider_product_id=body.provider_product_id,
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return link


@router.get(
    "/admin/billing/subscription-links/{link_id}",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=BillingSubscriptionLinkResponse,
)
def get_subscription_link(
    link_id: str,
    tenant_id: str,
    request: Request,
) -> BillingSubscriptionLinkResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        link = _engine.get_subscription_link(db, link_id)
    if link is None:
        raise HTTPException(
            status_code=404, detail={"code": "SUBSCRIPTION_LINK_NOT_FOUND"}
        )
    return link


@router.get(
    "/admin/tenants/{tenant_id}/billing/subscription-links",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_subscription_links(tenant_id: str, request: Request) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        links = _engine.list_subscription_links(db, tenant_id)
    return {
        "tenant_id": tenant_id,
        "links": [lnk.model_dump() for lnk in links],
        "count": len(links),
    }


@router.post(
    "/admin/billing/subscription-links/{link_id}/sync",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=BillingSubscriptionLinkResponse,
)
def sync_subscription_link(
    link_id: str,
    tenant_id: str,
    request: Request,
) -> BillingSubscriptionLinkResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    provider: BillingProvider
    try:
        provider = StripeProvider()
    except Exception:
        provider = NullBillingProvider()
    with Session(eng) as db:
        try:
            link = _engine.sync_subscription_link(db, link_id, provider)
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return link


# ---------------------------------------------------------------------------
# Usage meters
# ---------------------------------------------------------------------------


@router.post(
    "/admin/billing/meters",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=UsageMeterResponse,
)
def create_meter(body: CreateUsageMeterRequest) -> UsageMeterResponse:
    eng = get_engine()
    with Session(eng) as db:
        try:
            meter = _engine.create_meter(
                db,
                meter_code=body.meter_code,
                display_name=body.display_name,
                unit=body.unit,
                aggregation_mode=body.aggregation_mode,
                billing_category=body.billing_category,
                metadata_json=body.metadata_json,
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return meter


@router.get(
    "/admin/billing/meters",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_meters(active_only: bool = True) -> dict[str, Any]:
    eng = get_engine()
    with Session(eng) as db:
        meters = _engine.list_meters(db, active_only=active_only)
    return {"meters": [m.model_dump() for m in meters], "count": len(meters)}


@router.patch(
    "/admin/billing/meters/{meter_code}",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=UsageMeterResponse,
)
def update_meter(meter_code: str, body: UpdateUsageMeterRequest) -> UsageMeterResponse:
    eng = get_engine()
    with Session(eng) as db:
        try:
            meter = _engine.update_meter(db, meter_code, body)
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return meter


# ---------------------------------------------------------------------------
# Usage events
# ---------------------------------------------------------------------------


@router.post(
    "/billing/usage/events",
    response_model=UsageEventResponse,
)
async def record_usage_event(
    body: RecordUsageEventRequest,
    request: Request,
) -> UsageEventResponse:
    tenant_id = require_bound_tenant(request)
    eng = get_engine()
    with Session(eng) as db:
        try:
            evt = _engine.record_usage(
                db,
                tenant_id=tenant_id,
                meter_code=body.meter_code,
                quantity=body.quantity,
                idempotency_key=body.idempotency_key,
                subscription_item_id=body.subscription_item_id,
                source=body.source,
                occurred_at=body.occurred_at,
                metadata_json=body.metadata_json,
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return evt


@router.get(
    "/admin/tenants/{tenant_id}/billing/usage",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_usage_events(
    tenant_id: str,
    request: Request,
    billing_status: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        events = _engine.list_usage_events(
            db, tenant_id, billing_status=billing_status, limit=limit
        )
    return {
        "tenant_id": tenant_id,
        "events": [e.model_dump() for e in events],
        "count": len(events),
    }


# ---------------------------------------------------------------------------
# Stripe webhook  (public — no scope dep; signature-verified)
# ---------------------------------------------------------------------------


@router.post("/billing/webhooks/stripe")
async def billing_stripe_webhook(request: Request) -> dict[str, Any]:
    """Receive Stripe webhook events for billing lifecycle updates.

    Idempotent: replayed events (already in ledger) return immediately.
    Never grants or revokes entitlements — only updates sync_status on links.
    """
    raw_body = await request.body()
    sig_header = request.headers.get("Stripe-Signature")

    try:
        provider = StripeProvider()
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="STRIPE_WEBHOOK_SECRET_NOT_CONFIGURED",
        )

    try:
        valid = provider.verify_webhook_signature(raw_body, sig_header)
    except ProviderNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if not valid:
        raise HTTPException(
            status_code=400,
            detail="STRIPE_WEBHOOK_SIGNATURE_INVALID",
        )

    try:
        stripe_event = provider.parse_webhook(raw_body, sig_header)
    except ProviderNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    event_id = stripe_event.get("id", "")
    event_type = stripe_event.get("type", "unknown")

    BILLING_WEBHOOKS_TOTAL.labels(event_type=event_type).inc()

    eng = get_engine()
    with Session(eng) as db:
        # Idempotency: check if this stripe event_id is already in the ledger
        if event_id:
            existing = (
                db.query(BillingEventLedger)
                .filter(
                    BillingEventLedger.entity_type == "stripe_webhook",
                    BillingEventLedger.entity_id == event_id,
                )
                .first()
            )
            if existing is not None:
                BILLING_WEBHOOK_REPLAY_TOTAL.inc()
                return {"received": True}

        _append_ledger_entry(
            db,
            tenant_id="stripe",
            event_type=f"webhook.{event_type}",
            entity_type="stripe_webhook",
            entity_id=event_id,
            provider="stripe",
            new_state=event_type,
        )

        if event_type in _SUBSCRIPTION_UPDATED_TYPES:
            _handle_stripe_subscription_event(db, stripe_event, event_type)

        db.commit()

    return {"received": True}


def _handle_stripe_subscription_event(
    db: Session,
    stripe_event: dict,
    event_type: str,
) -> None:
    """Update BillingSubscriptionLink.sync_status for subscription lifecycle events.

    Never modifies SubscriptionItem or TenantBundleAssignment.
    """
    from datetime import datetime, timezone  # noqa: PLC0415

    data_obj = stripe_event.get("data", {}).get("object", {})
    provider_subscription_id = data_obj.get("id") or data_obj.get("subscription")
    if not provider_subscription_id:
        return

    new_sync_status = _SYNC_STATUS_MAP.get(event_type, "synced")
    links = (
        db.query(BillingSubscriptionLink)
        .filter(
            BillingSubscriptionLink.provider_subscription_id == provider_subscription_id
        )
        .all()
    )
    for link in links:
        link.sync_status = new_sync_status
        link.last_synced_at = datetime.now(timezone.utc)
        link.updated_at = datetime.now(timezone.utc)
        db.flush()


# ---------------------------------------------------------------------------
# Billing explain
# ---------------------------------------------------------------------------


@router.get(
    "/admin/billing/explain",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=BillingExplainResponse,
)
def billing_explain(
    tenant_id: str,
    request: Request,
) -> BillingExplainResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        result = _engine.explain_billing(db, tenant_id)
    return result
