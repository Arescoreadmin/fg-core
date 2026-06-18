"""services/billing/engine.py — BillingEngine: central service for P1.5 billing layer.

Orchestrates billing accounts, subscription links, usage meters, usage events,
and the billing explain view. Never grants or revokes capabilities — billing
observes and monetizes, entitlement logic lives in P1.2/P1.4.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from api.db_models_billing import (
    BillingAccount,
    BillingEventLedger,
    BillingSubscriptionLink,
    UsageEvent,
    UsageMeter,
)
from api.observability.metrics import (
    BILLING_ACCOUNTS_CREATED_TOTAL,
    BILLING_SUBSCRIPTION_LINKS_TOTAL,
    BILLING_USAGE_EVENTS_TOTAL,
)
from services.billing.metering import _append_ledger_entry, record_usage_event
from services.billing.models import (
    BillingAccountResponse,
    BillingExplainResponse,
    BillingLedgerEntryResponse,
    BillingSubscriptionLinkResponse,
    UpdateBillingAccountRequest,
    UpdateUsageMeterRequest,
    UsageEventResponse,
    UsageMeterResponse,
)

log = logging.getLogger("frostgate.billing.engine")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _account_to_response(row: BillingAccount) -> BillingAccountResponse:
    return BillingAccountResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        provider=row.provider,
        provider_customer_id=row.provider_customer_id,
        billing_email=row.billing_email,
        billing_status=row.billing_status,
        metadata_json=row.metadata_json or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _link_to_response(row: BillingSubscriptionLink) -> BillingSubscriptionLinkResponse:
    return BillingSubscriptionLinkResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        subscription_contract_id=row.subscription_contract_id,
        subscription_item_id=row.subscription_item_id,
        provider=row.provider,
        provider_subscription_id=row.provider_subscription_id,
        provider_price_id=row.provider_price_id,
        provider_product_id=row.provider_product_id,
        sync_status=row.sync_status,
        last_synced_at=row.last_synced_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _meter_to_response(row: UsageMeter) -> UsageMeterResponse:
    return UsageMeterResponse(
        id=row.id,
        meter_code=row.meter_code,
        display_name=row.display_name,
        unit=row.unit,
        aggregation_mode=row.aggregation_mode,
        billing_category=row.billing_category,
        active=row.active,
        metadata_json=row.metadata_json or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _event_to_response(row: UsageEvent) -> UsageEventResponse:
    return UsageEventResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        subscription_item_id=row.subscription_item_id,
        meter_code=row.meter_code,
        quantity=row.quantity,
        idempotency_key=row.idempotency_key,
        source=row.source,
        occurred_at=row.occurred_at,
        reported_at=row.reported_at,
        billing_status=row.billing_status,
        provider_event_id=row.provider_event_id,
        metadata_json=row.metadata_json or {},
    )


def _ledger_to_response(row: BillingEventLedger) -> BillingLedgerEntryResponse:
    return BillingLedgerEntryResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        event_type=row.event_type,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        provider=row.provider,
        old_state=row.old_state,
        new_state=row.new_state,
        actor=row.actor,
        reason=row.reason,
        occurred_at=row.occurred_at,
        prev_hash=row.prev_hash,
        event_hash=row.event_hash,
    )


class BillingEngine:
    """Central service for the P1.5 billing integration layer."""

    # ------------------------------------------------------------------
    # BillingAccount
    # ------------------------------------------------------------------

    def create_billing_account(
        self,
        db: Session,
        tenant_id: str,
        provider: str,
        *,
        billing_email: str | None = None,
        billing_status: str = "active",
        metadata_json: dict | None = None,
        provider_customer_id: str | None = None,
    ) -> BillingAccountResponse:
        existing = (
            db.query(BillingAccount)
            .filter(
                BillingAccount.tenant_id == tenant_id,
                BillingAccount.provider == provider,
            )
            .first()
        )
        if existing is not None:
            raise ValueError(
                f"billing account already exists for tenant={tenant_id} provider={provider}"
            )

        account = BillingAccount(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            provider=provider,
            provider_customer_id=provider_customer_id,
            billing_email=billing_email,
            billing_status=billing_status,
            metadata_json=metadata_json or {},
        )
        db.add(account)
        db.flush()

        _append_ledger_entry(
            db,
            tenant_id=tenant_id,
            event_type="billing_account_created",
            entity_type="billing_account",
            entity_id=account.id,
            new_state=billing_status,
        )

        BILLING_ACCOUNTS_CREATED_TOTAL.inc()
        return _account_to_response(account)

    def get_billing_account(
        self, db: Session, account_id: str
    ) -> BillingAccountResponse | None:
        row = db.query(BillingAccount).filter(BillingAccount.id == account_id).first()
        return _account_to_response(row) if row is not None else None

    def get_billing_account_for_tenant(
        self, db: Session, tenant_id: str, provider: str = "stripe"
    ) -> BillingAccountResponse | None:
        row = (
            db.query(BillingAccount)
            .filter(
                BillingAccount.tenant_id == tenant_id,
                BillingAccount.provider == provider,
            )
            .first()
        )
        return _account_to_response(row) if row is not None else None

    def update_billing_account(
        self,
        db: Session,
        account_id: str,
        updates: UpdateBillingAccountRequest,
    ) -> BillingAccountResponse:
        row = db.query(BillingAccount).filter(BillingAccount.id == account_id).first()
        if row is None:
            raise ValueError(f"billing account not found: {account_id}")

        old_status = row.billing_status
        if updates.billing_email is not None:
            row.billing_email = updates.billing_email
        if updates.billing_status is not None:
            row.billing_status = updates.billing_status
        if updates.provider_customer_id is not None:
            row.provider_customer_id = updates.provider_customer_id
        if updates.metadata_json is not None:
            row.metadata_json = updates.metadata_json
        row.updated_at = _utcnow()
        db.flush()

        if updates.billing_status is not None and updates.billing_status != old_status:
            _append_ledger_entry(
                db,
                tenant_id=row.tenant_id,
                event_type="billing_account_status_changed",
                entity_type="billing_account",
                entity_id=row.id,
                old_state=old_status,
                new_state=updates.billing_status,
            )

        return _account_to_response(row)

    # ------------------------------------------------------------------
    # BillingSubscriptionLink
    # ------------------------------------------------------------------

    def create_subscription_link(
        self,
        db: Session,
        tenant_id: str,
        subscription_contract_id: str,
        *,
        subscription_item_id: str | None = None,
        provider: str = "stripe",
        provider_subscription_id: str | None = None,
        provider_price_id: str | None = None,
        provider_product_id: str | None = None,
    ) -> BillingSubscriptionLinkResponse:
        link = BillingSubscriptionLink(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            subscription_contract_id=subscription_contract_id,
            subscription_item_id=subscription_item_id,
            provider=provider,
            provider_subscription_id=provider_subscription_id,
            provider_price_id=provider_price_id,
            provider_product_id=provider_product_id,
            sync_status="pending",
        )
        db.add(link)
        db.flush()

        _append_ledger_entry(
            db,
            tenant_id=tenant_id,
            event_type="subscription_link_created",
            entity_type="billing_subscription_link",
            entity_id=link.id,
            new_state="pending",
        )

        BILLING_SUBSCRIPTION_LINKS_TOTAL.inc()
        return _link_to_response(link)

    def get_subscription_link(
        self, db: Session, link_id: str
    ) -> BillingSubscriptionLinkResponse | None:
        row = (
            db.query(BillingSubscriptionLink)
            .filter(BillingSubscriptionLink.id == link_id)
            .first()
        )
        return _link_to_response(row) if row is not None else None

    def list_subscription_links(
        self, db: Session, tenant_id: str
    ) -> list[BillingSubscriptionLinkResponse]:
        rows = (
            db.query(BillingSubscriptionLink)
            .filter(BillingSubscriptionLink.tenant_id == tenant_id)
            .all()
        )
        return [_link_to_response(r) for r in rows]

    def sync_subscription_link(
        self, db: Session, link_id: str, provider
    ) -> BillingSubscriptionLinkResponse:
        row = (
            db.query(BillingSubscriptionLink)
            .filter(BillingSubscriptionLink.id == link_id)
            .first()
        )
        if row is None:
            raise ValueError(f"subscription link not found: {link_id}")

        old_status = row.sync_status
        try:
            if row.provider_subscription_id:
                provider.retrieve_invoice(row.provider_subscription_id)
            row.sync_status = "synced"
            row.last_synced_at = _utcnow()
        except Exception as exc:
            log.warning("billing.sync_link_failed link_id=%s error=%s", link_id, exc)
            row.sync_status = "failed"

        row.updated_at = _utcnow()
        db.flush()

        _append_ledger_entry(
            db,
            tenant_id=row.tenant_id,
            event_type="subscription_link_synced",
            entity_type="billing_subscription_link",
            entity_id=row.id,
            old_state=old_status,
            new_state=row.sync_status,
        )

        return _link_to_response(row)

    # ------------------------------------------------------------------
    # UsageMeter
    # ------------------------------------------------------------------

    def create_meter(
        self,
        db: Session,
        meter_code: str,
        display_name: str,
        unit: str,
        aggregation_mode: str,
        billing_category: str,
        metadata_json: dict | None = None,
    ) -> UsageMeterResponse:
        existing = (
            db.query(UsageMeter).filter(UsageMeter.meter_code == meter_code).first()
        )
        if existing is not None:
            raise ValueError(f"meter_code already exists: {meter_code!r}")

        meter = UsageMeter(
            id=str(uuid.uuid4()),
            meter_code=meter_code,
            display_name=display_name,
            unit=unit,
            aggregation_mode=aggregation_mode,
            billing_category=billing_category,
            active="1",
            metadata_json=metadata_json or {},
        )
        db.add(meter)
        db.flush()
        return _meter_to_response(meter)

    def list_meters(
        self, db: Session, *, active_only: bool = True
    ) -> list[UsageMeterResponse]:
        query = db.query(UsageMeter)
        if active_only:
            query = query.filter(UsageMeter.active == "1")
        rows = query.all()
        return [_meter_to_response(r) for r in rows]

    def update_meter(
        self,
        db: Session,
        meter_code: str,
        updates: UpdateUsageMeterRequest,
    ) -> UsageMeterResponse:
        row = db.query(UsageMeter).filter(UsageMeter.meter_code == meter_code).first()
        if row is None:
            raise ValueError(f"meter not found: {meter_code!r}")

        if updates.display_name is not None:
            row.display_name = updates.display_name
        if updates.active is not None:
            row.active = updates.active
        if updates.metadata_json is not None:
            row.metadata_json = updates.metadata_json
        row.updated_at = _utcnow()
        db.flush()
        return _meter_to_response(row)

    # ------------------------------------------------------------------
    # Usage Events
    # ------------------------------------------------------------------

    def record_usage(
        self,
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
    ) -> UsageEventResponse:
        evt = record_usage_event(
            db,
            tenant_id,
            meter_code,
            quantity,
            idempotency_key,
            subscription_item_id=subscription_item_id,
            source=source,
            occurred_at=occurred_at,
            metadata_json=metadata_json,
            provider=provider,
        )
        BILLING_USAGE_EVENTS_TOTAL.labels(meter_code=meter_code).inc()
        return _event_to_response(evt)

    def list_usage_events(
        self,
        db: Session,
        tenant_id: str,
        *,
        billing_status: str | None = None,
        limit: int = 100,
    ) -> list[UsageEventResponse]:
        query = db.query(UsageEvent).filter(UsageEvent.tenant_id == tenant_id)
        if billing_status is not None:
            query = query.filter(UsageEvent.billing_status == billing_status)
        rows = query.limit(limit).all()
        return [_event_to_response(r) for r in rows]

    # ------------------------------------------------------------------
    # Explain
    # ------------------------------------------------------------------

    def explain_billing(self, db: Session, tenant_id: str) -> BillingExplainResponse:
        account_row = (
            db.query(BillingAccount)
            .filter(BillingAccount.tenant_id == tenant_id)
            .first()
        )
        links = (
            db.query(BillingSubscriptionLink)
            .filter(BillingSubscriptionLink.tenant_id == tenant_id)
            .all()
        )
        active_meters = db.query(UsageMeter).filter(UsageMeter.active == "1").all()
        pending = (
            db.query(UsageEvent)
            .filter(
                UsageEvent.tenant_id == tenant_id,
                UsageEvent.billing_status == "pending",
            )
            .limit(20)
            .all()
        )
        failed = (
            db.query(UsageEvent)
            .filter(
                UsageEvent.tenant_id == tenant_id,
                UsageEvent.billing_status == "failed",
            )
            .limit(20)
            .all()
        )
        ledger_rows = (
            db.query(BillingEventLedger)
            .filter(BillingEventLedger.tenant_id == tenant_id)
            .order_by(BillingEventLedger.occurred_at.desc())
            .limit(20)
            .all()
        )

        return BillingExplainResponse(
            tenant_id=tenant_id,
            billing_account=_account_to_response(account_row)
            if account_row is not None
            else None,
            subscription_links=[_link_to_response(r) for r in links],
            active_meters=[_meter_to_response(r) for r in active_meters],
            pending_usage=[_event_to_response(r) for r in pending],
            failed_usage=[_event_to_response(r) for r in failed],
            recent_ledger=[_ledger_to_response(r) for r in ledger_rows],
        )
