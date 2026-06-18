"""api/subscriptions.py — Subscription Assignment Engine API (P1.4).

Admin routes for the commercial authority layer:
  POST   /admin/subscriptions/contracts                         create contract
  GET    /admin/subscriptions/contracts/{contract_id}           get contract
  PATCH  /admin/subscriptions/contracts/{contract_id}/status    update contract status
  GET    /admin/tenants/{tenant_id}/subscriptions/contracts     list contracts for tenant
  POST   /admin/subscriptions/contracts/{contract_id}/items     create subscription item
  GET    /admin/subscriptions/items/{item_id}                   get subscription item
  PATCH  /admin/subscriptions/items/{item_id}/status            update item status
  GET    /admin/tenants/{tenant_id}/subscriptions/items         list items for tenant
  GET    /admin/subscriptions/items/{item_id}/ledger            get item event ledger

Tenant-scoped explain-capability route:
  GET    /subscriptions/explain-capability                       explain capability decision
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth_scopes import bind_tenant_id, require_bound_tenant, require_scopes
from api.db import get_engine
from services.subscriptions.engine import SubscriptionEngine
from services.subscriptions.models import (
    ContractResponse,
    CreateContractRequest,
    CreateItemRequest,
    ExplainCapabilityResponse,
    ItemResponse,
    UpdateContractStatusRequest,
    UpdateItemStatusRequest,
)
from sqlalchemy.orm import Session

router = APIRouter(tags=["subscriptions"])
_engine = SubscriptionEngine()


# ---------------------------------------------------------------------------
# Contract routes
# ---------------------------------------------------------------------------


@router.post(
    "/admin/subscriptions/contracts",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=ContractResponse,
)
def create_contract(
    tenant_id: str,
    body: CreateContractRequest,
    request: Request,
) -> ContractResponse:
    """Create a commercial subscription contract for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        try:
            contract = _engine.create_contract(
                db,
                tenant_id=tenant_id,
                contract_ref=body.contract_ref,
                sku_package=body.sku_package,
                starts_at=body.starts_at,
                sku_metadata=body.sku_metadata,
                ends_at=body.ends_at,
                status="draft",
                created_by=body.created_by,
                notes=body.notes,
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return contract


@router.get(
    "/admin/subscriptions/contracts/{contract_id}",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=ContractResponse,
)
def get_contract(
    contract_id: str,
    tenant_id: str,
    request: Request,
) -> ContractResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        contract = _engine.get_contract(db, contract_id, tenant_id)
    if contract is None:
        raise HTTPException(status_code=404, detail={"code": "CONTRACT_NOT_FOUND"})
    return contract


@router.patch(
    "/admin/subscriptions/contracts/{contract_id}/status",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=ContractResponse,
)
def update_contract_status(
    contract_id: str,
    tenant_id: str,
    body: UpdateContractStatusRequest,
    request: Request,
) -> ContractResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        try:
            contract = _engine.update_contract_status(
                db, contract_id, tenant_id, body.status, body.actor, body.reason
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if contract is None:
        raise HTTPException(status_code=404, detail={"code": "CONTRACT_NOT_FOUND"})
    return contract


@router.get(
    "/admin/tenants/{tenant_id}/subscriptions/contracts",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_contracts(tenant_id: str, request: Request) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        contracts = _engine.list_contracts(db, tenant_id)
    return {
        "tenant_id": tenant_id,
        "contracts": [c.model_dump() for c in contracts],
        "count": len(contracts),
    }


# ---------------------------------------------------------------------------
# SubscriptionItem routes
# ---------------------------------------------------------------------------


@router.post(
    "/admin/subscriptions/contracts/{contract_id}/items",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=ItemResponse,
)
def create_item(
    contract_id: str,
    tenant_id: str,
    body: CreateItemRequest,
    request: Request,
) -> ItemResponse:
    """Create a subscription item under a contract, syncing the bundle assignment."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        try:
            item = _engine.create_item(
                db,
                contract_id=contract_id,
                tenant_id=tenant_id,
                bundle_id=body.bundle_id,
                sku_code=body.sku_code,
                starts_at=body.starts_at,
                meter_code=body.meter_code,
                ends_at=body.ends_at,
                parent_item_id=body.parent_item_id,
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return item


@router.get(
    "/admin/subscriptions/items/{item_id}",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=ItemResponse,
)
def get_item(item_id: str, tenant_id: str, request: Request) -> ItemResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        item = _engine.get_item(db, item_id, tenant_id)
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "ITEM_NOT_FOUND"})
    return item


@router.patch(
    "/admin/subscriptions/items/{item_id}/status",
    dependencies=[Depends(require_scopes("admin:write"))],
    response_model=ItemResponse,
)
def update_item_status(
    item_id: str,
    tenant_id: str,
    body: UpdateItemStatusRequest,
    request: Request,
) -> ItemResponse:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        try:
            item = _engine.update_item_status(
                db, item_id, tenant_id, body.status, body.actor, body.reason
            )
            db.commit()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "ITEM_NOT_FOUND"})
    return item


@router.get(
    "/admin/tenants/{tenant_id}/subscriptions/items",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_items(tenant_id: str, request: Request) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        items = _engine.list_items(db, tenant_id)
    return {
        "tenant_id": tenant_id,
        "items": [i.model_dump() for i in items],
        "count": len(items),
    }


@router.get(
    "/admin/subscriptions/items/{item_id}/ledger",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_item_ledger(item_id: str, tenant_id: str, request: Request) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    eng = get_engine()
    with Session(eng) as db:
        entries = _engine.list_ledger(db, item_id, tenant_id)
    return {
        "item_id": item_id,
        "tenant_id": tenant_id,
        "entries": [e.model_dump() for e in entries],
        "count": len(entries),
    }


# ---------------------------------------------------------------------------
# Explain-capability (tenant-scoped)
# ---------------------------------------------------------------------------


@router.get(
    "/subscriptions/explain-capability",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=ExplainCapabilityResponse,
)
def explain_capability(
    capability: str,
    request: Request,
) -> ExplainCapabilityResponse:
    """Explain the full capability resolution chain for the calling tenant.

    Traces: registry → explicit grant → bundle/subscription assignment → tier default.
    """
    tenant_id = require_bound_tenant(request)
    eng = get_engine()
    with Session(eng) as db:
        result = _engine.explain_capability(db, tenant_id, capability)

    try:
        from api.observability.metrics import SUBSCRIPTION_EXPLAIN_REQUESTS_TOTAL

        SUBSCRIPTION_EXPLAIN_REQUESTS_TOTAL.labels(result=result.decision).inc()
    except Exception:
        pass

    return result
