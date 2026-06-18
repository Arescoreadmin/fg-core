"""api/db_models_billing.py — Billing Integration Layer ORM models (P1.5).

Five models:
  BillingAccount           — provider-specific billing account per tenant
  BillingSubscriptionLink  — links a SubscriptionItem/Contract to a provider subscription
  UsageMeter               — defines what is metered and how
  UsageEvent               — append-only usage record (immutability guard)
  BillingEventLedger       — append-only billing lifecycle audit ledger (hash-chained)

Auto-registered via the import at the bottom of api/db_models.py.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base, utcnow


def _raise_immutable(mapper, connection, target) -> None:
    raise ValueError(f"{target.__class__.__name__} rows are append-only")


class BillingAccount(Base):
    """P1.5: Provider-specific billing account record for a tenant.

    One account per (tenant_id, provider) pair. Tracks the external customer
    identity and billing lifecycle — never controls entitlements.
    """

    __tablename__ = "billing_accounts"
    __table_args__ = (
        Index("idx_billing_accounts_tenant", "tenant_id"),
        Index("idx_billing_accounts_tenant_provider", "tenant_id", "provider"),
    )

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False)
    provider: Mapped[Any] = mapped_column(Text, nullable=False, default="stripe")
    provider_customer_id: Mapped[Any] = mapped_column(Text, nullable=True, unique=True)
    billing_email: Mapped[Any] = mapped_column(Text, nullable=True)
    # active | suspended | past_due | manual_invoice | archived
    billing_status: Mapped[Any] = mapped_column(Text, nullable=False, default="active")
    metadata_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class BillingSubscriptionLink(Base):
    """P1.5: Bridge between a SubscriptionItem/Contract and a provider subscription.

    Tracks the provider-side subscription state without owning entitlements.
    sync_status reflects the last known synchronization outcome.
    """

    __tablename__ = "billing_subscription_links"
    __table_args__ = (
        Index("idx_billing_sub_links_tenant", "tenant_id"),
        Index("idx_billing_sub_links_contract", "subscription_contract_id"),
    )

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False)
    subscription_contract_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("subscription_contracts.id"), nullable=False
    )
    subscription_item_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("subscription_items.id"), nullable=True
    )
    provider: Mapped[Any] = mapped_column(Text, nullable=False, default="stripe")
    provider_subscription_id: Mapped[Any] = mapped_column(Text, nullable=True)
    provider_price_id: Mapped[Any] = mapped_column(Text, nullable=True)
    provider_product_id: Mapped[Any] = mapped_column(Text, nullable=True)
    # pending | synced | failed | disabled
    sync_status: Mapped[Any] = mapped_column(Text, nullable=False, default="pending")
    last_synced_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class UsageMeter(Base):
    """P1.5: Defines a billable usage dimension.

    meter_code is globally unique and stable across schema migrations.
    active stored as Text "1"/"0" to avoid SQLite Boolean mapping issues.
    """

    __tablename__ = "usage_meters"

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    meter_code: Mapped[Any] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[Any] = mapped_column(Text, nullable=False)
    unit: Mapped[Any] = mapped_column(Text, nullable=False, default="count")
    # sum | max | unique_count
    aggregation_mode: Mapped[Any] = mapped_column(Text, nullable=False, default="sum")
    billing_category: Mapped[Any] = mapped_column(Text, nullable=False)
    active: Mapped[Any] = mapped_column(Text, nullable=False, default="1")
    metadata_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class UsageEvent(Base):
    """P1.5: Append-only record of a single usage occurrence.

    quantity stored as Text to avoid float/Decimal representation issues.
    Idempotency is enforced via (tenant_id, idempotency_key) UniqueConstraint.
    ORM guards prevent any modification after insertion.
    """

    __tablename__ = "usage_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_usage_events_idempotency"
        ),
        Index("idx_usage_events_tenant", "tenant_id"),
        Index("idx_usage_events_tenant_status", "tenant_id", "billing_status"),
        Index("idx_usage_events_meter", "meter_code"),
    )

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False)
    subscription_item_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("subscription_items.id"), nullable=True
    )
    meter_code: Mapped[Any] = mapped_column(Text, nullable=False)
    quantity: Mapped[Any] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[Any] = mapped_column(Text, nullable=False)
    source: Mapped[Any] = mapped_column(Text, nullable=False, default="api")
    occurred_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    reported_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    # pending | reported | rejected | ignored | failed
    billing_status: Mapped[Any] = mapped_column(Text, nullable=False, default="pending")
    provider_event_id: Mapped[Any] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )


class BillingEventLedger(Base):
    """P1.5: Append-only billing lifecycle audit ledger.

    Hash-chained: each entry includes prev_hash from the previous entry for
    the same tenant, enabling tamper detection. GENESIS sentinel for the first entry.
    ORM guards prevent modification after insertion.
    """

    __tablename__ = "billing_event_ledger"
    __table_args__ = (
        UniqueConstraint("event_hash", name="uq_billing_event_ledger_hash"),
        Index("idx_billing_event_ledger_tenant", "tenant_id"),
        Index("idx_billing_event_ledger_entity", "entity_type", "entity_id"),
    )

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False)
    event_type: Mapped[Any] = mapped_column(Text, nullable=False)
    entity_type: Mapped[Any] = mapped_column(Text, nullable=False)
    entity_id: Mapped[Any] = mapped_column(Text, nullable=False)
    provider: Mapped[Any] = mapped_column(Text, nullable=False, default="system")
    old_state: Mapped[Any] = mapped_column(Text, nullable=True)
    new_state: Mapped[Any] = mapped_column(Text, nullable=True)
    actor: Mapped[Any] = mapped_column(Text, nullable=False, default="system")
    reason: Mapped[Any] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    prev_hash: Mapped[Any] = mapped_column(Text, nullable=False, default="GENESIS")
    event_hash: Mapped[Any] = mapped_column(Text, nullable=False, unique=True)


event.listen(UsageEvent, "before_update", _raise_immutable)
event.listen(UsageEvent, "before_delete", _raise_immutable)
event.listen(BillingEventLedger, "before_update", _raise_immutable)
event.listen(BillingEventLedger, "before_delete", _raise_immutable)
