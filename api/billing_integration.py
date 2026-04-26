"""
Minimal Billing Integration — Task 13.1

Converts tenant-attributed usage records (from api/usage_attribution.py) into
deterministic, invoiceable billing records using a single flat per-unit pricing
model.

Guarantees:
- One pricing model only: flat per-unit, integer cents, USD.
- Billing records are tenant-scoped and customer-attributed.
- Billing is idempotent: same (tenant, customer, idempotency_key) always
  produces the same invoice_id; repeated calls return the existing record.
- Same idempotency_key under a different tenant produces a distinct invoice_id —
  no cross-tenant billing collision.
- Rebilling prevention: each usage_id may only appear in one invoice per
  (tenant, customer). generate_invoice() excludes already-billed usage_ids.
- idempotency_key is required; missing/blank keys fail closed.
- Usage records are never mutated; billing reads them as immutable source data.
- No external provider calls (no Stripe, no network, no webhooks).
- All money math uses integer cents only — no floats.
- Structured error contract via api/error_contracts.py (Task 11.1).
- No external dependencies, no DB migrations.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException

from api.error_contracts import api_error
from api.usage_attribution import query_usage

log = logging.getLogger("frostgate.billing_integration")

# ---------------------------------------------------------------------------
# Stable error codes (never change meaning once published)
# ---------------------------------------------------------------------------

ERR_TENANT_REQUIRED = "BILLING_TENANT_REQUIRED"
ERR_CUSTOMER_REQUIRED = "BILLING_CUSTOMER_REQUIRED"
ERR_NO_USAGE = "BILLING_NO_USAGE"
ERR_INVALID_PRICING_MODEL = "BILLING_INVALID_PRICING_MODEL"
ERR_FORBIDDEN = "BILLING_FORBIDDEN"
ERR_EXPORT_INVALID_FORMAT = "BILLING_EXPORT_INVALID_FORMAT"
ERR_IDEMPOTENCY_KEY_REQUIRED = "BILLING_IDEMPOTENCY_KEY_REQUIRED"

_VALID_EXPORT_FORMATS = frozenset({"json", "csv"})

# ---------------------------------------------------------------------------
# Pricing model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PricingModel:
    """A single flat per-unit pricing model.

    Fields:
        pricing_model_id: Stable identifier for this model.
        currency:         ISO 4217 currency code (e.g. "USD").
        unit_amount_cents: Integer cents charged per unit.  Must be >= 0.
        billable_action:  When set, only usage records with this action are
                          billed.  None = bill all actions.
        active:           False = model is retired; reject billing against it.
    """

    pricing_model_id: str
    currency: str
    unit_amount_cents: int  # integer cents; no floats
    billable_action: str | None
    active: bool


def default_pricing_model() -> PricingModel:
    """Return the canonical flat-per-unit pricing model for this deployment.

    One unit = 1 cent USD.  All actions are billable.
    """
    return PricingModel(
        pricing_model_id="flat-per-unit-v1",
        currency="USD",
        unit_amount_cents=1,
        billable_action=None,  # all actions
        active=True,
    )


# ---------------------------------------------------------------------------
# Billing record models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BillingLineItem:
    """One line item in a billing invoice, corresponding to one usage record.

    Fields:
        line_item_id:      SHA-256(invoice_id + ":" + usage_id)[:24] — stable.
        usage_id:          Source UsageRecord.usage_id.
        tenant_id:         Tenant this line item belongs to.
        customer_id:       Customer identity from the source usage record.
        action:            Action/event_type from the source usage record.
        units:             Units from the source usage record.
        unit_amount_cents: Integer cents per unit from the pricing model.
        amount_cents:      units * unit_amount_cents (integer; never negative).
        currency:          ISO currency code.
    """

    line_item_id: str
    usage_id: str
    tenant_id: str
    customer_id: str
    action: str
    units: int
    unit_amount_cents: int
    amount_cents: int
    currency: str


@dataclass(frozen=True)
class BillingInvoice:
    """An immutable billing invoice draft produced from tenant usage.

    Fields:
        invoice_id:        SHA-256(tenant_id + ":" + customer_id + ":" + idempotency_key)[:32].
        tenant_id:         Trusted tenant this invoice belongs to.
        customer_id:       Customer identity from validated usage attribution.
        pricing_model_id:  Pricing model used to generate this invoice.
        currency:          ISO currency code.
        subtotal_cents:    Sum of all line item amount_cents.
        total_cents:       Same as subtotal_cents (no tax, no discounts).
        status:            Always "draft" — no real payment collection.
        source_usage_count: Number of usage records included.
        idempotency_key:   The idempotency key used to generate this invoice.
        created_at:        Unix timestamp of first generation.
        line_items:        Frozen tuple of BillingLineItem, ordered by
                           (created_at, usage_id) from the source usage records.
    """

    invoice_id: str
    tenant_id: str
    customer_id: str
    pricing_model_id: str
    currency: str
    subtotal_cents: int
    total_cents: int
    status: str  # "draft"
    source_usage_count: int
    idempotency_key: str
    created_at: int
    line_items: tuple[BillingLineItem, ...]


@dataclass(frozen=True)
class BillingWriteResult:
    """Result of a generate_invoice() call."""

    invoice: BillingInvoice
    created: bool  # True = new invoice; False = idempotent no-op (existing returned)


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

# invoice_id → BillingInvoice
_store: dict[str, BillingInvoice] = {}

# (tenant_id, customer_id) → set of billed usage_ids
# Tracks which usage_ids have already been invoiced per tenant/customer pair.
# Prevents rebilling: a usage_id may only appear in one invoice.
_billed: dict[tuple[str, str], set[str]] = {}


def _reset_store() -> None:
    """Reset in-memory store.  For test isolation only."""
    _store.clear()
    _billed.clear()


# ---------------------------------------------------------------------------
# Deterministic ID helpers
# ---------------------------------------------------------------------------


def _derive_invoice_id(tenant_id: str, customer_id: str, idempotency_key: str) -> str:
    payload = f"{tenant_id}:{customer_id}:{idempotency_key}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


def _derive_line_item_id(invoice_id: str, usage_id: str) -> str:
    payload = f"{invoice_id}:{usage_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _require_tenant(tenant_id: Any) -> str:
    if not tenant_id or not str(tenant_id).strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_TENANT_REQUIRED,
                "trusted_tenant_id is required for billing",
                action="supply tenant_id from validated credential/session context",
            ),
        )
    return str(tenant_id).strip()


def _require_customer(customer_id: Any) -> str:
    if not customer_id or not str(customer_id).strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_CUSTOMER_REQUIRED,
                "customer_id is required for billing",
                action="supply customer_id from validated credential context",
            ),
        )
    return str(customer_id).strip()


def _require_idempotency_key(idempotency_key: Any) -> str:
    if not isinstance(idempotency_key, str) or not idempotency_key.strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_IDEMPOTENCY_KEY_REQUIRED,
                "idempotency_key is required for invoice generation",
                action="supply a stable caller-assigned idempotency_key; do not use timestamps or random values",
            ),
        )
    return idempotency_key.strip()


def _require_active_model(model: PricingModel) -> None:
    if not model.active:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_INVALID_PRICING_MODEL,
                "pricing model is not active",
                action="use an active pricing model",
            ),
        )
    if model.unit_amount_cents < 0:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_INVALID_PRICING_MODEL,
                "unit_amount_cents must be >= 0",
            ),
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_invoice(
    trusted_tenant_id: str,
    customer_id: str,
    idempotency_key: str | None = None,
    pricing_model: PricingModel | None = None,
    now: int | None = None,
) -> BillingWriteResult:
    """Generate a billing invoice from tenant-attributed usage records.

    Reads usage records from api/usage_attribution.query_usage() filtered by
    trusted_tenant_id and customer_id.  Usage records are never mutated.

    Only uninvoiced usage records are included — usage_ids that already appear
    in a prior invoice for this (tenant, customer) pair are excluded.  This
    prevents double-billing when generate_invoice() is called multiple times
    with different idempotency keys.

    Args:
        trusted_tenant_id: Pre-validated tenant from credential/session context.
                           Must NOT be sourced from request body.
        customer_id:       Customer identity from validated credential context.
        idempotency_key:   Required caller-supplied idempotency key.  Must be
                           a non-empty string.  No timestamp fallback is
                           provided — callers must supply a stable key.
        pricing_model:     Pricing model to apply.  Defaults to
                           default_pricing_model().
        now:               Unix timestamp override (for tests).

    Returns:
        BillingWriteResult(invoice, created=True) for new invoices.
        BillingWriteResult(invoice, created=False) for idempotent no-ops.

    Raises:
        HTTPException 400 BILLING_TENANT_REQUIRED          — missing tenant.
        HTTPException 400 BILLING_CUSTOMER_REQUIRED        — missing customer.
        HTTPException 400 BILLING_IDEMPOTENCY_KEY_REQUIRED — missing/blank key.
        HTTPException 400 BILLING_NO_USAGE                 — no uninvoiced usage.
        HTTPException 400 BILLING_INVALID_PRICING_MODEL    — inactive/invalid model.

    Security invariants:
        - trusted_tenant_id and customer_id from trusted context only
        - usage records filtered by both tenant and customer before billing
        - foreign tenant/customer usage is never included
        - no mutation of source usage records
        - no external provider calls
        - already-billed usage_ids are never included in a new invoice
    """
    tid = _require_tenant(trusted_tenant_id)
    cid = _require_customer(customer_id)
    ikey = _require_idempotency_key(idempotency_key)
    model = pricing_model if pricing_model is not None else default_pricing_model()
    _require_active_model(model)
    ts = int(now) if now is not None else int(time.time())

    invoice_id = _derive_invoice_id(tid, cid, ikey)

    # Idempotency check: return existing if same (tenant, customer, key)
    if invoice_id in _store:
        existing = _store[invoice_id]
        log.debug("billing.idempotent tenant=%s invoice_id=%s", tid, invoice_id[:8])
        return BillingWriteResult(invoice=existing, created=False)

    # Load usage records for this tenant+customer only — never foreign data
    usage_records = query_usage(tid, customer_id=cid)

    # Filter by billable_action if model specifies one
    if model.billable_action is not None:
        usage_records = [r for r in usage_records if r.action == model.billable_action]

    # Exclude already-billed usage_ids — prevents double-billing across invoice calls
    already_billed: frozenset[str] | set[str] = _billed.get((tid, cid), frozenset())
    usage_records = [r for r in usage_records if r.usage_id not in already_billed]

    if not usage_records:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_NO_USAGE,
                "no uninvoiced usage records found for this tenant and customer",
                action="record new usage before generating another invoice",
            ),
        )

    # Build line items — deterministic order: (created_at, usage_id)
    line_items: list[BillingLineItem] = []
    for r in sorted(usage_records, key=lambda x: (x.created_at, x.usage_id)):
        amount_cents = r.units * model.unit_amount_cents
        line_items.append(
            BillingLineItem(
                line_item_id=_derive_line_item_id(invoice_id, r.usage_id),
                usage_id=r.usage_id,
                tenant_id=tid,
                customer_id=cid,
                action=r.action,
                units=r.units,
                unit_amount_cents=model.unit_amount_cents,
                amount_cents=amount_cents,
                currency=model.currency,
            )
        )

    subtotal_cents = sum(li.amount_cents for li in line_items)

    invoice = BillingInvoice(
        invoice_id=invoice_id,
        tenant_id=tid,
        customer_id=cid,
        pricing_model_id=model.pricing_model_id,
        currency=model.currency,
        subtotal_cents=subtotal_cents,
        total_cents=subtotal_cents,  # no tax, no discounts
        status="draft",
        source_usage_count=len(line_items),
        idempotency_key=ikey,
        created_at=ts,
        line_items=tuple(line_items),
    )
    _store[invoice_id] = invoice

    # Mark all included usage_ids as billed for this (tenant, customer) pair
    key = (tid, cid)
    if key not in _billed:
        _billed[key] = set()
    for li in line_items:
        _billed[key].add(li.usage_id)

    log.debug(
        "billing.invoice tenant=%s customer_prefix=%s total_cents=%d items=%d",
        tid,
        cid[:8],
        subtotal_cents,
        len(line_items),
    )
    return BillingWriteResult(invoice=invoice, created=True)


def query_invoices(
    trusted_tenant_id: str,
    *,
    customer_id: str | None = None,
    status: str | None = None,
) -> list[BillingInvoice]:
    """Query billing invoices for a single trusted tenant.

    Only returns invoices for trusted_tenant_id.  Foreign tenant invoices are
    never returned — not even an empty result reveals their existence.

    Returns:
        List of BillingInvoice ordered by (created_at ASC, invoice_id ASC).
    """
    tid = _require_tenant(trusted_tenant_id)

    results = [inv for inv in _store.values() if inv.tenant_id == tid]

    if customer_id is not None:
        results = [inv for inv in results if inv.customer_id == customer_id]
    if status is not None:
        results = [inv for inv in results if inv.status == status]

    results.sort(key=lambda inv: (inv.created_at, inv.invoice_id))
    return results


def export_invoices(
    trusted_tenant_id: str,
    fmt: str = "json",
) -> str:
    """Export billing invoices for a trusted tenant.

    Args:
        trusted_tenant_id: Pre-validated tenant.
        fmt:               "json" or "csv".  Default "json".

    Returns:
        String in the requested format.  Deterministic for same input set.
        Safe columns only; no line_items in flat export, no secrets, no hashes.

    Raises:
        HTTPException 400 BILLING_EXPORT_INVALID_FORMAT — unknown format.
    """
    tid = _require_tenant(trusted_tenant_id)

    if fmt not in _VALID_EXPORT_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_EXPORT_INVALID_FORMAT,
                f"export format {fmt!r} is not supported",
                action=f"use one of: {', '.join(sorted(_VALID_EXPORT_FORMATS))}",
            ),
        )

    invoices = query_invoices(tid)

    _EXPORT_COLUMNS = (
        "invoice_id",
        "tenant_id",
        "customer_id",
        "pricing_model_id",
        "currency",
        "subtotal_cents",
        "total_cents",
        "status",
        "source_usage_count",
        "idempotency_key",
        "created_at",
    )

    def _row(inv: BillingInvoice) -> dict:
        return {c: getattr(inv, c) for c in _EXPORT_COLUMNS}

    if fmt == "json":
        return json.dumps(
            [_row(inv) for inv in invoices],
            separators=(",", ":"),
            sort_keys=True,
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(_EXPORT_COLUMNS))
    writer.writeheader()
    for inv in invoices:
        writer.writerow(_row(inv))
    return buf.getvalue()
