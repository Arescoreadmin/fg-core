"""
Task 13.1 — Minimal Billing Integration

Tests proving:
1)  Invoice is generated from tenant usage records
2)  Missing tenant_id raises BILLING_TENANT_REQUIRED (400)
3)  Missing customer_id raises BILLING_CUSTOMER_REQUIRED (400)
4)  No usage records raises BILLING_NO_USAGE (400)
5)  Idempotency: same (tenant, customer, idempotency_key) returns existing invoice
6)  Same idempotency_key under different tenant produces distinct invoice_id
7)  All money math uses integer cents; no floats
8)  Line items ordered by (created_at, usage_id)
9)  query_invoices returns only trusted-tenant invoices
10) query_invoices filters by customer_id
11) query_invoices filters by status
12) export_invoices json format is correct and deterministic
13) export_invoices csv format is correct
14) export_invoices rejects invalid format
15) Inactive pricing model raises BILLING_INVALID_PRICING_MODEL
16) billable_action filter excludes non-matching usage records
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from fastapi import HTTPException

from api.billing_integration import (
    ERR_CUSTOMER_REQUIRED,
    ERR_EXPORT_INVALID_FORMAT,
    ERR_INVALID_PRICING_MODEL,
    ERR_NO_USAGE,
    ERR_TENANT_REQUIRED,
    BillingInvoice,
    PricingModel,
    _reset_store,
    export_invoices,
    generate_invoice,
    query_invoices,
)
from api.usage_attribution import _reset_store as _reset_usage_store
from api.usage_attribution import record_usage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_stores():
    """Reset both usage and billing in-memory stores before each test."""
    _reset_usage_store()
    _reset_store()
    yield
    _reset_usage_store()
    _reset_store()


def _seed_usage(
    tenant_id: str = "tenant-a",
    customer_id: str = "cust-1",
    action: str = "rag_query",
    units: int = 3,
    idempotency_key: str = "usage-001",
    now: int = 1_000_000,
) -> None:
    record_usage(
        trusted_tenant_id=tenant_id,
        customer_id=customer_id,
        action=action,
        units=units,
        idempotency_key=idempotency_key,
        now=now,
    )


# ---------------------------------------------------------------------------
# 1) test_invoice_generated_from_tenant_usage
# ---------------------------------------------------------------------------


def test_invoice_generated_from_tenant_usage():
    """generate_invoice builds a draft invoice from existing usage records."""
    _seed_usage(units=4, idempotency_key="u1")

    result = generate_invoice(
        trusted_tenant_id="tenant-a",
        customer_id="cust-1",
        idempotency_key="inv-001",
    )
    assert result.created is True
    inv = result.invoice
    assert isinstance(inv, BillingInvoice)
    assert inv.tenant_id == "tenant-a"
    assert inv.customer_id == "cust-1"
    assert inv.status == "draft"
    assert inv.source_usage_count == 1
    assert inv.invoice_id  # non-empty


# ---------------------------------------------------------------------------
# 2) test_missing_tenant_raises_billing_tenant_required
# ---------------------------------------------------------------------------


def test_missing_tenant_raises_billing_tenant_required():
    """Empty or None trusted_tenant_id must raise BILLING_TENANT_REQUIRED (400)."""
    for bad in (None, "", "  "):
        with pytest.raises(HTTPException) as exc:
            generate_invoice(
                trusted_tenant_id=bad, customer_id="cust-1", idempotency_key="k"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_TENANT_REQUIRED


# ---------------------------------------------------------------------------
# 3) test_missing_customer_raises_billing_customer_required
# ---------------------------------------------------------------------------


def test_missing_customer_raises_billing_customer_required():
    """Empty or None customer_id must raise BILLING_CUSTOMER_REQUIRED (400)."""
    for bad in (None, "", "  "):
        with pytest.raises(HTTPException) as exc:
            generate_invoice(
                trusted_tenant_id="tenant-a", customer_id=bad, idempotency_key="k"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_CUSTOMER_REQUIRED


# ---------------------------------------------------------------------------
# 4) test_no_usage_raises_billing_no_usage
# ---------------------------------------------------------------------------


def test_no_usage_raises_billing_no_usage():
    """generate_invoice with no matching usage records raises BILLING_NO_USAGE (400)."""
    # No usage records seeded at all
    with pytest.raises(HTTPException) as exc:
        generate_invoice(
            trusted_tenant_id="tenant-a",
            customer_id="cust-1",
            idempotency_key="inv-empty",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == ERR_NO_USAGE


# ---------------------------------------------------------------------------
# 5) test_idempotency_returns_existing_invoice
# ---------------------------------------------------------------------------


def test_idempotency_returns_existing_invoice():
    """Same (tenant, customer, idempotency_key) returns the existing invoice."""
    _seed_usage(idempotency_key="u1")

    r1 = generate_invoice("tenant-a", "cust-1", idempotency_key="inv-idem")
    r2 = generate_invoice("tenant-a", "cust-1", idempotency_key="inv-idem")

    assert r1.created is True
    assert r2.created is False
    assert r1.invoice.invoice_id == r2.invoice.invoice_id

    # Only one invoice stored
    invoices = query_invoices("tenant-a")
    assert len(invoices) == 1


# ---------------------------------------------------------------------------
# 6) test_same_idempotency_key_different_tenant_distinct_invoice
# ---------------------------------------------------------------------------


def test_same_idempotency_key_different_tenant_distinct_invoice():
    """Same idempotency_key under different tenants must produce distinct invoice_ids."""
    _seed_usage(tenant_id="tenant-a", customer_id="cust-1", idempotency_key="u1")
    _seed_usage(tenant_id="tenant-b", customer_id="cust-2", idempotency_key="u2")

    r_a = generate_invoice("tenant-a", "cust-1", idempotency_key="shared-inv-key")
    r_b = generate_invoice("tenant-b", "cust-2", idempotency_key="shared-inv-key")

    assert r_a.created is True
    assert r_b.created is True
    assert r_a.invoice.invoice_id != r_b.invoice.invoice_id
    assert r_a.invoice.tenant_id == "tenant-a"
    assert r_b.invoice.tenant_id == "tenant-b"


# ---------------------------------------------------------------------------
# 7) test_money_math_uses_integer_cents
# ---------------------------------------------------------------------------


def test_money_math_uses_integer_cents():
    """All amount_cents values must be integers; no floats allowed."""
    _seed_usage(units=7, idempotency_key="u1")

    model = PricingModel(
        pricing_model_id="test-model",
        currency="USD",
        unit_amount_cents=3,
        billable_action=None,
        active=True,
    )
    result = generate_invoice(
        "tenant-a", "cust-1", idempotency_key="inv-math", pricing_model=model
    )
    inv = result.invoice

    # 7 units * 3 cents = 21 cents
    assert inv.subtotal_cents == 21
    assert inv.total_cents == 21
    assert isinstance(inv.subtotal_cents, int)
    assert isinstance(inv.total_cents, int)

    for li in inv.line_items:
        assert isinstance(li.amount_cents, int)
        assert isinstance(li.unit_amount_cents, int)
        assert isinstance(li.units, int)


# ---------------------------------------------------------------------------
# 8) test_line_items_ordered_by_created_at_usage_id
# ---------------------------------------------------------------------------


def test_line_items_ordered_by_created_at_usage_id():
    """Line items must be ordered by (created_at, usage_id) from source usage records."""
    # Seed three records with different timestamps
    record_usage(
        "tenant-a", "cust-1", "op-c", units=1, idempotency_key="u-c", now=1_000_002
    )
    record_usage(
        "tenant-a", "cust-1", "op-a", units=1, idempotency_key="u-a", now=1_000_000
    )
    record_usage(
        "tenant-a", "cust-1", "op-b", units=1, idempotency_key="u-b", now=1_000_001
    )

    result = generate_invoice("tenant-a", "cust-1", idempotency_key="inv-order")
    items = result.invoice.line_items

    assert len(items) == 3
    assert items[0].action == "op-a"
    assert items[1].action == "op-b"
    assert items[2].action == "op-c"


# ---------------------------------------------------------------------------
# 9) test_query_invoices_returns_only_trusted_tenant
# ---------------------------------------------------------------------------


def test_query_invoices_returns_only_trusted_tenant():
    """query_invoices must return only invoices belonging to the trusted tenant."""
    _seed_usage(tenant_id="tenant-a", customer_id="cust-1", idempotency_key="ua1")
    _seed_usage(tenant_id="tenant-b", customer_id="cust-2", idempotency_key="ub1")

    generate_invoice("tenant-a", "cust-1", idempotency_key="inv-a")
    generate_invoice("tenant-b", "cust-2", idempotency_key="inv-b")

    results_a = query_invoices("tenant-a")
    assert len(results_a) == 1
    assert results_a[0].tenant_id == "tenant-a"

    results_b = query_invoices("tenant-b")
    assert len(results_b) == 1
    assert results_b[0].tenant_id == "tenant-b"


# ---------------------------------------------------------------------------
# 10) test_query_invoices_filters_by_customer_id
# ---------------------------------------------------------------------------


def test_query_invoices_filters_by_customer_id():
    """query_invoices with customer_id filters to that customer only."""
    _seed_usage(tenant_id="tenant-a", customer_id="cust-x", idempotency_key="ux1")
    _seed_usage(tenant_id="tenant-a", customer_id="cust-y", idempotency_key="uy1")

    generate_invoice("tenant-a", "cust-x", idempotency_key="inv-x")
    generate_invoice("tenant-a", "cust-y", idempotency_key="inv-y")

    results = query_invoices("tenant-a", customer_id="cust-x")
    assert len(results) == 1
    assert results[0].customer_id == "cust-x"


# ---------------------------------------------------------------------------
# 11) test_query_invoices_filters_by_status
# ---------------------------------------------------------------------------


def test_query_invoices_filters_by_status():
    """query_invoices with status='draft' returns all drafts; unknown status returns empty."""
    _seed_usage(idempotency_key="u1")
    generate_invoice("tenant-a", "cust-1", idempotency_key="inv-s1")

    drafts = query_invoices("tenant-a", status="draft")
    assert len(drafts) == 1
    assert drafts[0].status == "draft"

    paid = query_invoices("tenant-a", status="paid")
    assert paid == []


# ---------------------------------------------------------------------------
# 12) test_export_invoices_json_correct_and_deterministic
# ---------------------------------------------------------------------------


def test_export_invoices_json_correct_and_deterministic():
    """export_invoices JSON output contains correct fields and is deterministic."""
    _seed_usage(units=5, idempotency_key="u1")
    generate_invoice("tenant-a", "cust-1", idempotency_key="inv-json", now=2_000_000)

    out1 = export_invoices("tenant-a", fmt="json")
    out2 = export_invoices("tenant-a", fmt="json")
    assert out1 == out2  # deterministic

    rows = json.loads(out1)
    assert len(rows) == 1
    row = rows[0]

    # Required fields present
    for field in (
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
    ):
        assert field in row, f"missing field: {field}"

    # line_items must not appear in flat export
    assert "line_items" not in row
    assert row["tenant_id"] == "tenant-a"
    assert row["status"] == "draft"


# ---------------------------------------------------------------------------
# 13) test_export_invoices_csv_correct
# ---------------------------------------------------------------------------


def test_export_invoices_csv_correct():
    """export_invoices CSV output contains correct headers and one data row."""
    _seed_usage(idempotency_key="u1")
    generate_invoice("tenant-a", "cust-1", idempotency_key="inv-csv")

    out = export_invoices("tenant-a", fmt="csv")
    reader = csv.DictReader(io.StringIO(out))
    rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    assert row["tenant_id"] == "tenant-a"
    assert row["status"] == "draft"
    assert "invoice_id" in row
    assert "line_items" not in row


# ---------------------------------------------------------------------------
# 14) test_export_invoices_rejects_invalid_format
# ---------------------------------------------------------------------------


def test_export_invoices_rejects_invalid_format():
    """Unsupported export format must raise BILLING_EXPORT_INVALID_FORMAT (400)."""
    _seed_usage(idempotency_key="u1")
    generate_invoice("tenant-a", "cust-1", idempotency_key="inv-fmt")

    for bad_fmt in ("xml", "parquet", "", "JSON", "CSV"):
        with pytest.raises(HTTPException) as exc:
            export_invoices("tenant-a", fmt=bad_fmt)
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_EXPORT_INVALID_FORMAT


# ---------------------------------------------------------------------------
# 15) test_inactive_pricing_model_raises_invalid_model
# ---------------------------------------------------------------------------


def test_inactive_pricing_model_raises_invalid_model():
    """An inactive pricing model must raise BILLING_INVALID_PRICING_MODEL (400)."""
    _seed_usage(idempotency_key="u1")

    inactive = PricingModel(
        pricing_model_id="retired-model",
        currency="USD",
        unit_amount_cents=5,
        billable_action=None,
        active=False,
    )
    with pytest.raises(HTTPException) as exc:
        generate_invoice(
            "tenant-a", "cust-1", idempotency_key="inv-inactive", pricing_model=inactive
        )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == ERR_INVALID_PRICING_MODEL


# ---------------------------------------------------------------------------
# 16) test_billable_action_filter_excludes_non_matching_usage
# ---------------------------------------------------------------------------


def test_billable_action_filter_excludes_non_matching_usage():
    """When billable_action is set, only matching usage records are billed."""
    record_usage(
        "tenant-a",
        "cust-1",
        "rag_query",
        units=2,
        idempotency_key="u-rag",
        now=1_000_000,
    )
    record_usage(
        "tenant-a", "cust-1", "embed", units=3, idempotency_key="u-emb", now=1_000_001
    )

    rag_only_model = PricingModel(
        pricing_model_id="rag-only-v1",
        currency="USD",
        unit_amount_cents=10,
        billable_action="rag_query",
        active=True,
    )
    result = generate_invoice(
        "tenant-a",
        "cust-1",
        idempotency_key="inv-rag-only",
        pricing_model=rag_only_model,
    )
    inv = result.invoice

    # Only the rag_query record should be included
    assert inv.source_usage_count == 1
    assert inv.line_items[0].action == "rag_query"
    assert inv.subtotal_cents == 20  # 2 units * 10 cents


# ---------------------------------------------------------------------------
# Bonus: negative unit_amount_cents is rejected
# ---------------------------------------------------------------------------


def test_negative_unit_amount_cents_rejected():
    """A pricing model with unit_amount_cents < 0 must raise BILLING_INVALID_PRICING_MODEL."""
    _seed_usage(idempotency_key="u1")

    negative = PricingModel(
        pricing_model_id="negative-model",
        currency="USD",
        unit_amount_cents=-1,
        billable_action=None,
        active=True,
    )
    with pytest.raises(HTTPException) as exc:
        generate_invoice(
            "tenant-a", "cust-1", idempotency_key="inv-neg", pricing_model=negative
        )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == ERR_INVALID_PRICING_MODEL
