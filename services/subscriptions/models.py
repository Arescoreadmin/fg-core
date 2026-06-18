"""services/subscriptions/models.py — Pydantic schemas for the Subscription Assignment Engine (P1.4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Contract schemas
# ---------------------------------------------------------------------------


class CreateContractRequest(BaseModel):
    contract_ref: str
    sku_package: str
    sku_metadata: dict[str, Any] = Field(default_factory=dict)
    starts_at: datetime
    ends_at: datetime | None = None
    created_by: str = "admin"
    notes: str | None = None


class UpdateContractStatusRequest(BaseModel):
    status: str  # active | suspended | canceled | expired
    actor: str = "admin"
    reason: str | None = None


class ContractResponse(BaseModel):
    id: str
    tenant_id: str
    contract_ref: str
    sku_package: str
    sku_metadata: dict[str, Any]
    status: str
    starts_at: datetime
    ends_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    notes: str | None


# ---------------------------------------------------------------------------
# SubscriptionItem schemas
# ---------------------------------------------------------------------------


class CreateItemRequest(BaseModel):
    bundle_id: str
    sku_code: str
    meter_code: str | None = None
    starts_at: datetime
    ends_at: datetime | None = None
    parent_item_id: str | None = None  # MSP inherited rights


class UpdateItemStatusRequest(BaseModel):
    status: str  # active | suspended | canceled | expired
    actor: str = "admin"
    reason: str | None = None


class ItemResponse(BaseModel):
    id: str
    contract_id: str
    tenant_id: str
    bundle_id: str
    sku_code: str
    meter_code: str | None
    status: str
    starts_at: datetime
    ends_at: datetime | None
    parent_item_id: str | None
    bundle_assignment_id: str | None
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Ledger schema
# ---------------------------------------------------------------------------


class LedgerEntryResponse(BaseModel):
    id: str
    subscription_item_id: str
    tenant_id: str
    event_type: str
    event_at: datetime
    actor: str
    reason: str | None
    metadata_json: dict[str, Any]
    prev_hash: str
    entry_hash: str


# ---------------------------------------------------------------------------
# Explain-capability schema
# ---------------------------------------------------------------------------


class ResolutionLayer(BaseModel):
    layer: str
    result: str  # found | miss | granted | denied | skipped
    detail: dict[str, Any] = Field(default_factory=dict)


class ExplainCapabilityResponse(BaseModel):
    tenant_id: str
    capability: str
    decision: str  # granted | denied
    source: str  # registry_miss | no_tenant | explicit | subscription | bundle | tier | error
    resolution_chain: list[ResolutionLayer]
    dependency_checks: dict[str, str] = Field(default_factory=dict)
    # granted | denied per dependency cap
