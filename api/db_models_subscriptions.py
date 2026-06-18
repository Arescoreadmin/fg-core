"""api/db_models_subscriptions.py — Subscription Assignment Engine ORM models (P1.4).

Three new models:
  SubscriptionContract   — commercial authority (one per deal)
  SubscriptionItem       — active bundle assignment from contract, with lifecycle state
  SubscriptionEventLedger — immutable event log with SHA-256 hash chain

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


class SubscriptionContract(Base):
    """P1.4: Commercial authority record governing subscription assignments.

    One contract per commercial deal. A tenant can have multiple contracts
    (e.g., base + add-ons, or historical + current).
    """

    __tablename__ = "subscription_contracts"
    __table_args__ = (
        Index("idx_sub_contracts_tenant", "tenant_id"),
        Index("idx_sub_contracts_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False)
    contract_ref: Mapped[Any] = mapped_column(Text, nullable=False)
    # metadata-driven package code — no hardcoded SKU names
    sku_package: Mapped[Any] = mapped_column(Text, nullable=False)
    sku_metadata: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )
    # draft | active | suspended | canceled | expired
    status: Mapped[Any] = mapped_column(Text, nullable=False, default="draft")
    starts_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Any] = mapped_column(Text, nullable=False, default="system")
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    notes: Mapped[Any] = mapped_column(Text, nullable=True)


class SubscriptionItem(Base):
    """P1.4: Subscription line item — links a contract to a bundle with lifecycle state.

    Creating an active item automatically syncs a TenantBundleAssignment so that the
    existing capability resolver picks it up. Status transitions maintain that sync.
    """

    __tablename__ = "subscription_items"
    __table_args__ = (
        Index("idx_sub_items_tenant", "tenant_id"),
        Index("idx_sub_items_contract", "contract_id"),
        Index("idx_sub_items_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    contract_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("subscription_contracts.id"), nullable=False
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False)
    bundle_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("policy_bundles.id"), nullable=False
    )
    # metadata-driven SKU code for this line item
    sku_code: Mapped[Any] = mapped_column(Text, nullable=False)
    # meter_code wires to future usage-based billing — no billing logic here
    meter_code: Mapped[Any] = mapped_column(Text, nullable=True)
    # active | suspended | canceled | expired
    status: Mapped[Any] = mapped_column(Text, nullable=False, default="active")
    starts_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    # MSP parent subscription — inherited rights design point (not full impl)
    parent_item_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("subscription_items.id"), nullable=True
    )
    # FK to the synced TenantBundleAssignment created by the engine
    bundle_assignment_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("tenant_bundle_assignments.id"), nullable=True
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class SubscriptionEventLedger(Base):
    """P1.4: Immutable subscription lifecycle event log.

    Append-only — ORM-level guards prevent updates and deletes.
    SHA-256 hash chain: each entry hashes the previous entry's hash + its own payload,
    enabling tamper detection over the full event sequence.

    Event types: created | activated | suspended | canceled | expired | reactivated
    """

    __tablename__ = "subscription_event_ledger"
    __table_args__ = (
        UniqueConstraint("entry_hash", name="uq_sub_event_ledger_hash"),
        Index("idx_sub_event_ledger_item", "subscription_item_id"),
        Index("idx_sub_event_ledger_tenant", "tenant_id"),
    )

    id: Mapped[Any] = mapped_column(
        Text, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    subscription_item_id: Mapped[Any] = mapped_column(
        Text, ForeignKey("subscription_items.id"), nullable=False
    )
    tenant_id: Mapped[Any] = mapped_column(Text, nullable=False)
    event_type: Mapped[Any] = mapped_column(Text, nullable=False)
    event_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    actor: Mapped[Any] = mapped_column(Text, nullable=False, default="system")
    reason: Mapped[Any] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )
    # SHA-256 hash chain — GENESIS for the first entry, prev entry_hash thereafter
    prev_hash: Mapped[Any] = mapped_column(Text, nullable=False, default="GENESIS")
    entry_hash: Mapped[Any] = mapped_column(Text, nullable=False, unique=True)


event.listen(SubscriptionEventLedger, "before_update", _raise_immutable)
event.listen(SubscriptionEventLedger, "before_delete", _raise_immutable)
