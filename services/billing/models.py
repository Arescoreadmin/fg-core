"""services/billing/models.py — Pydantic v2 schemas for the Billing Integration Layer (P1.5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CreateBillingAccountRequest(BaseModel):
    provider: str = "stripe"
    provider_customer_id: str | None = None
    billing_email: str | None = None
    billing_status: str = "active"
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class BillingAccountResponse(BaseModel):
    id: str
    tenant_id: str
    provider: str
    provider_customer_id: str | None
    billing_email: str | None
    billing_status: str
    metadata_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class UpdateBillingAccountRequest(BaseModel):
    billing_email: str | None = None
    billing_status: str | None = None
    provider_customer_id: str | None = None
    metadata_json: dict[str, Any] | None = None


class CreateBillingSubscriptionLinkRequest(BaseModel):
    tenant_id: str
    subscription_contract_id: str
    subscription_item_id: str | None = None
    provider: str = "stripe"
    provider_subscription_id: str | None = None
    provider_price_id: str | None = None
    provider_product_id: str | None = None


class BillingSubscriptionLinkResponse(BaseModel):
    id: str
    tenant_id: str
    subscription_contract_id: str
    subscription_item_id: str | None
    provider: str
    provider_subscription_id: str | None
    provider_price_id: str | None
    provider_product_id: str | None
    sync_status: str
    last_synced_at: datetime | None
    created_at: datetime
    updated_at: datetime


class CreateUsageMeterRequest(BaseModel):
    meter_code: str
    display_name: str
    unit: str = "count"
    aggregation_mode: str = "sum"
    billing_category: str
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class UsageMeterResponse(BaseModel):
    id: str
    meter_code: str
    display_name: str
    unit: str
    aggregation_mode: str
    billing_category: str
    active: str
    metadata_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class UpdateUsageMeterRequest(BaseModel):
    display_name: str | None = None
    active: str | None = None
    metadata_json: dict[str, Any] | None = None


class RecordUsageEventRequest(BaseModel):
    meter_code: str
    quantity: str
    idempotency_key: str
    subscription_item_id: str | None = None
    source: str = "api"
    occurred_at: datetime | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class UsageEventResponse(BaseModel):
    id: str
    tenant_id: str
    subscription_item_id: str | None
    meter_code: str
    quantity: str
    idempotency_key: str
    source: str
    occurred_at: datetime
    reported_at: datetime | None
    billing_status: str
    provider_event_id: str | None
    metadata_json: dict[str, Any]


class BillingLedgerEntryResponse(BaseModel):
    id: str
    tenant_id: str
    event_type: str
    entity_type: str
    entity_id: str
    provider: str
    old_state: str | None
    new_state: str | None
    actor: str
    reason: str | None
    occurred_at: datetime
    prev_hash: str
    event_hash: str


class BillingExplainResponse(BaseModel):
    tenant_id: str
    billing_account: BillingAccountResponse | None
    subscription_links: list[BillingSubscriptionLinkResponse]
    active_meters: list[UsageMeterResponse]
    pending_usage: list[UsageEventResponse]
    failed_usage: list[UsageEventResponse]
    recent_ledger: list[BillingLedgerEntryResponse]
