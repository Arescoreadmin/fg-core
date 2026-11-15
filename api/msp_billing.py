"""MSP-006 — partner billing and usage attribution on the existing authorities.

This module is NOT standalone and is NOT a billing engine. It composes:

  consent       api/msp_authority.py (MSP-001 relationships; never extended here)
  agreement     subscription_contracts (api/subscriptions.py commercial authority)
  price         tenant_contracts -> pricing_versions (hash-pinned, append-only)
  usage         usage_events via services/billing/metering.record_usage_event
  ledger        billing_event_ledger (written by record_usage_event)
  audit         per-tenant identity audit chain (emit_msp_audit)
  provider      services/billing BillingProvider via BillingReconciler (test mode)

The only new state is ``msp_payer_assignments``: which party pays for one product
delivered to one customer under one relationship. A platform operator creates it,
bound to the payer's existing commercial agreement. A customer approving an MSP
relationship never creates one, and neither party can create one.

Five questions every charge answers:
  who consumed     metadata.customer_tenant_id   (the delivering tenant, from the DB)
  who provided     metadata.msp_tenant_id + relationship_id
  who pays         metadata.payer_tenant_id + payer_assignment_id + billing_mode
  what occurred    product_code, quantity, unit, source_event_id, source_event_ref
  how to verify    pricing_version_id + pricing_hash, tenant_contract_id + contract_hash,
                   payload_sha256; reconcile_period() recomputes all of it.

Billable completion (first and only product, ``assessment.delivered``): an
engagement that QA approval advanced to ``delivered`` after the readiness and
production-qualification gates passed, evidenced by its
``engagement.status_transitioned`` audit event. Recorded in the same transaction.

Money is integer minor units with an explicit ISO currency. No float anywhere.

Routes (prefix /admin/msp/billing):
  GET   /payer-assignments                         billing.read, own organization
  GET   /usage?period=YYYY-MM                      billing.read, payer's own charges
  POST  /payer-assignments                         platform.admin, internal gateway
  POST  /payer-assignments/{id}/terminate          platform.admin, internal gateway
  GET   /reconciliation?payer_tenant_id&period     platform.admin, internal gateway
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.admin import require_internal_admin_gateway
from api.auth_dispatch import require_permission
from api.auth_scopes import require_scopes, resolve_authoritative_tenant
from api.db import set_tenant_context
from api.db_models import PricingVersion, TenantContract
from api.db_models_billing import BillingEventLedger, UsageEvent
from api.db_models_field_assessment import FaEngagement, FaEngagementAuditEvent
from api.db_models_identity import TenantIdentityAuditEvent
from api.db_models_msp import MspPayerAssignment
from api.db_models_subscriptions import SubscriptionContract
from api.deps import auth_ctx_db_session
from api.entitlements import _ensure_admin_gateway_tenant_bound
from api.msp_authority import (
    MSP_ACCESS_DENIED,
    as_utc,
    correlation_id,
    effective_status,
    emit_msp_audit,
    load_relationship,
    msp_error,
    msp_organization_active,
    tenant_kind_and_name,
    utcnow,
)
from api.signed_artifacts import canonical_hash
from services.billing.metering import record_usage_event
from services.billing.reconciliation import BillingReconciler

log = logging.getLogger("frostgate.msp.billing")

router = APIRouter(prefix="/admin/msp/billing", tags=["msp-006"])

USAGE_SCHEMA_VERSION = "msp006.usage.v1"
TRUSTED_PRODUCER = "field_assessment.delivery"
RESERVED_METER_PREFIX = "msp."
# The trusted producer's idempotency namespace. Reserved on the public route so
# no other writer can pre-occupy a (tenant_id, idempotency_key) slot.
RESERVED_KEY_PREFIX = "msp006:"

PRODUCT_ASSESSMENT_DELIVERED = "assessment.delivered"
# product_code -> (meter_code, unit). One product until another is authorized.
PRODUCTS: dict[str, tuple[str, str]] = {
    PRODUCT_ASSESSMENT_DELIVERED: ("msp.assessment_delivered", "assessment"),
}
MSP_METERS = frozenset(meter for meter, _ in PRODUCTS.values())

MAX_ASSIGNMENT_DAYS = 400
DEFAULT_PAGE = 50
MAX_PAGE = 200
_PERIOD_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")

# Error codes (stable; the console and operators map these, never server text)
BILLING_PAYER_ASSIGNMENT_INVALID = "BILLING_PAYER_ASSIGNMENT_INVALID"
BILLING_PAYER_ASSIGNMENT_EXISTS = "BILLING_PAYER_ASSIGNMENT_EXISTS"
BILLING_PAYER_ASSIGNMENT_NOT_FOUND = "BILLING_PAYER_ASSIGNMENT_NOT_FOUND"
BILLING_AGREEMENT_INVALID = "BILLING_AGREEMENT_INVALID"
BILLING_RELATIONSHIP_INACTIVE = "BILLING_RELATIONSHIP_INACTIVE"
BILLING_PERIOD_INVALID = "BILLING_PERIOD_INVALID"
BILLING_PRODUCT_UNKNOWN = "BILLING_PRODUCT_UNKNOWN"
BILLING_METER_RESTRICTED = "BILLING_METER_RESTRICTED"

# Payer-resolution outcomes. Only RESOLVED is billable.
RESOLVED = "RESOLVED"
NO_PAYER_ASSIGNMENT = "NO_PAYER_ASSIGNMENT"
PAYER_AMBIGUOUS = "PAYER_AMBIGUOUS"
PAYER_ASSIGNMENT_NOT_IN_EFFECT = "PAYER_ASSIGNMENT_NOT_IN_EFFECT"
CUSTOMER_TENANT_INACTIVE = "CUSTOMER_TENANT_INACTIVE"
MSP_RELATIONSHIP_INACTIVE = "MSP_RELATIONSHIP_INACTIVE"
MSP_ORGANIZATION_NOT_ACTIVE = "MSP_ORGANIZATION_NOT_ACTIVE"
PAYER_AGREEMENT_INVALID = "PAYER_AGREEMENT_INVALID"
PRICING_NOT_FOUND = "PRICING_NOT_FOUND"
PRICING_CONTRACT_HASH_MISMATCH = "PRICING_CONTRACT_HASH_MISMATCH"
PRICING_HASH_MISMATCH = "PRICING_HASH_MISMATCH"
PRICING_RATE_INVALID = "PRICING_RATE_INVALID"
PRICING_CURRENCY_MISMATCH = "PRICING_CURRENCY_MISMATCH"
METER_NOT_CONFIGURED = "METER_NOT_CONFIGURED"
UNKNOWN_PRODUCT = "UNKNOWN_PRODUCT"


class UsageIdempotencyConflict(RuntimeError):
    """The same idempotency key arrived with a different payload."""


class LiveProcessorRefused(RuntimeError):
    """MSP-006 is authorized for test-mode processor integration only."""


def billing_error(status_code: int, code: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code})


# ---------------------------------------------------------------------------
# Pricing (reuses pricing_versions / tenant_contracts; integer minor units)
# ---------------------------------------------------------------------------


def pricing_version_hash(pricing_version_id: str, rates_json: Any) -> str:
    """Canonical hash binding a price list's id to its exact rates."""
    return canonical_hash(
        {"pricing_version_id": pricing_version_id, "rates_json": rates_json or {}}
    )


@dataclass(frozen=True)
class PricePin:
    pricing_version_id: str
    pricing_hash: str
    tenant_contract_id: str
    contract_hash: str
    unit_amount_minor: int
    currency: str


def _rate_for(rates: Any, product_code: str) -> Optional[tuple[int, str]]:
    """An MSP rate is {"unit_amount_minor": int >= 0, "currency": "USD"}.

    Anything else (float, bool, negative, missing or malformed currency) is
    invalid, so a legacy float price list can never price an MSP charge.
    """
    entry = (rates or {}).get(product_code) if isinstance(rates, dict) else None
    if not isinstance(entry, dict):
        return None
    amount = entry.get("unit_amount_minor")
    currency = entry.get("currency")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        return None
    if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
        return None
    return amount, currency


def _resolve_price(
    db: Session, *, payer_tenant_id: str, product_code: str, at: datetime
) -> tuple[Optional[PricePin], str]:
    """The payer's contract in force at ``at``, verified against its hashes."""
    from api.billing import _canonical_contract_hash  # noqa: PLC0415 — shared pin

    contract = (
        db.query(TenantContract)
        .filter(
            TenantContract.tenant_id == payer_tenant_id,
            TenantContract.start_at <= at,
            or_(TenantContract.end_at.is_(None), TenantContract.end_at > at),
        )
        .order_by(TenantContract.start_at.desc(), TenantContract.id.desc())
        .first()
    )
    if contract is None:
        return None, PRICING_NOT_FOUND
    if str(contract.contract_hash or "") != _canonical_contract_hash(contract):
        return None, PRICING_CONTRACT_HASH_MISMATCH
    pv = db.get(PricingVersion, contract.pricing_version_id)
    if pv is None:
        return None, PRICING_NOT_FOUND
    expected = pricing_version_hash(pv.pricing_version_id, pv.rates_json)
    if str(pv.sha256_hash) != expected:
        return None, PRICING_HASH_MISMATCH
    rate = _rate_for(pv.rates_json, product_code)
    if rate is None:
        return None, PRICING_RATE_INVALID
    return (
        PricePin(
            pricing_version_id=str(pv.pricing_version_id),
            pricing_hash=expected,
            tenant_contract_id=str(contract.contract_id),
            contract_hash=str(contract.contract_hash),
            unit_amount_minor=rate[0],
            currency=rate[1],
        ),
        RESOLVED,
    )


# ---------------------------------------------------------------------------
# Payer resolution (fail closed; exactly one payer or no charge)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayerResolution:
    reason: str
    assignment: Optional[MspPayerAssignment] = None
    price: Optional[PricePin] = None

    @property
    def billable(self) -> bool:
        return self.reason == RESOLVED


def _in_window(row: Any, at: datetime) -> bool:
    start, end = as_utc(row.effective_at), as_utc(row.expires_at)
    return start is not None and end is not None and start <= at < end


def _in_coverage(row: Any, at: datetime) -> bool:
    """The assignment covered ``at``: inside its window and before any
    termination. Termination keeps ``expires_at``, so it bounds coverage here."""
    terminated = as_utc(getattr(row, "terminated_at", None))
    return _in_window(row, at) and (terminated is None or at < terminated)


def resolve_payer(
    db: Session,
    *,
    customer_tenant_id: str,
    product_code: str,
    at: datetime,
) -> PayerResolution:
    """Resolve the single payer for one unit of ``product_code`` delivered to
    ``customer_tenant_id`` at ``at``. Leaves the session in the customer's
    tenant context. Never raises for business outcomes."""
    if product_code not in PRODUCTS:
        return PayerResolution(UNKNOWN_PRODUCT)
    set_tenant_context(db, customer_tenant_id)
    try:
        rows = (
            db.query(MspPayerAssignment)
            .filter(
                MspPayerAssignment.tenant_id == customer_tenant_id,
                MspPayerAssignment.product_code == product_code,
                MspPayerAssignment.status == "active",
            )
            .all()
        )
        if not rows:
            return PayerResolution(NO_PAYER_ASSIGNMENT)
        if len(rows) > 1:
            return PayerResolution(PAYER_AMBIGUOUS)
        a = rows[0]
        if not _in_window(a, at):
            return PayerResolution(PAYER_ASSIGNMENT_NOT_IN_EFFECT, a)
        if tenant_kind_and_name(db, customer_tenant_id) is None:
            return PayerResolution(CUSTOMER_TENANT_INACTIVE, a)
        rel = load_relationship(db, str(a.relationship_id))
        if (
            rel is None
            or str(rel.tenant_id) != customer_tenant_id
            or str(rel.msp_tenant_id) != str(a.msp_tenant_id)
            or effective_status(rel, at) != "active"
        ):
            return PayerResolution(MSP_RELATIONSHIP_INACTIVE, a)
        set_tenant_context(db, str(a.msp_tenant_id))
        if not msp_organization_active(db, str(a.msp_tenant_id)):
            return PayerResolution(MSP_ORGANIZATION_NOT_ACTIVE, a)
        if not _agreement_in_force(
            db, str(a.subscription_contract_id), str(a.payer_tenant_id), at
        ):
            return PayerResolution(PAYER_AGREEMENT_INVALID, a)
        set_tenant_context(db, str(a.payer_tenant_id))
        price, reason = _resolve_price(
            db, payer_tenant_id=str(a.payer_tenant_id), product_code=product_code, at=at
        )
        if price is None:
            return PayerResolution(reason, a)
        if price.currency != str(a.currency):
            return PayerResolution(PRICING_CURRENCY_MISMATCH, a)
        return PayerResolution(RESOLVED, a, price)
    finally:
        set_tenant_context(db, customer_tenant_id)


def _agreement_in_force(
    db: Session, contract_id: str, payer_tenant_id: str, at: datetime
) -> bool:
    row = db.get(SubscriptionContract, contract_id)
    if row is None or str(row.tenant_id) != payer_tenant_id:
        return False
    if str(row.status) != "active":
        return False
    start, end = as_utc(row.starts_at), as_utc(row.ends_at)
    return start is not None and start <= at and (end is None or at < end)


# ---------------------------------------------------------------------------
# Trusted usage producer: assessment delivered
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UsageOutcome:
    status: Literal["recorded", "duplicate", "not_billable", "not_applicable"]
    reason: str
    usage_event_id: Optional[str] = None


def _parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return as_utc(value)
    if isinstance(value, str) and value:
        try:
            return as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _delivery_evidence(
    db: Session, customer_tenant_id: str, engagement_id: str
) -> Optional[FaEngagementAuditEvent]:
    """The canonical completion record: the engagement is ``delivered`` in this
    tenant and its delivery transition is in the engagement audit trail."""
    eng = db.get(FaEngagement, engagement_id)
    if eng is None or str(eng.tenant_id) != customer_tenant_id:
        return None
    if str(eng.status) != "delivered":
        return None
    events = (
        db.query(FaEngagementAuditEvent)
        .filter(
            FaEngagementAuditEvent.tenant_id == customer_tenant_id,
            FaEngagementAuditEvent.engagement_id == engagement_id,
            FaEngagementAuditEvent.event_type == "engagement.status_transitioned",
        )
        .order_by(FaEngagementAuditEvent.created_at.desc())
        .all()
    )
    for ev in events:
        if (ev.payload or {}).get("new_status") == "delivered":
            return ev
    return None


def usage_idempotency_key(product_code: str, customer: str, source_id: str) -> str:
    return f"{RESERVED_KEY_PREFIX}{product_code}:{customer}:{source_id}"


def _semantic_payload(
    *,
    product_code: str,
    customer: str,
    engagement_id: str,
    source_ref: str,
    resolution: PayerResolution,
) -> dict[str, Any]:
    a = resolution.assignment
    p = resolution.price
    assert a is not None and p is not None
    meter_code, unit = PRODUCTS[product_code]
    quantity = 1
    return {
        "schema_version": USAGE_SCHEMA_VERSION,
        "source_service": TRUSTED_PRODUCER,
        "source_event_id": engagement_id,
        "source_event_ref": source_ref,
        "product_code": product_code,
        "meter_code": meter_code,
        "quantity": quantity,
        "unit": unit,
        "customer_tenant_id": customer,
        "msp_tenant_id": str(a.msp_tenant_id),
        "relationship_id": str(a.relationship_id),
        "payer_assignment_id": str(a.id),
        "payer_tenant_id": str(a.payer_tenant_id),
        "billing_mode": str(a.billing_mode),
        "currency": p.currency,
        "unit_amount_minor": p.unit_amount_minor,
        "amount_minor": quantity * p.unit_amount_minor,
        "pricing_version_id": p.pricing_version_id,
        "pricing_hash": p.pricing_hash,
        "tenant_contract_id": p.tenant_contract_id,
        "contract_hash": p.contract_hash,
    }


def _existing_usage(db: Session, payer: str, key: str) -> Optional[UsageEvent]:
    return (
        db.query(UsageEvent)
        .filter(UsageEvent.tenant_id == payer, UsageEvent.idempotency_key == key)
        .first()
    )


def _same_payload(row: UsageEvent, payload_sha256: str) -> bool:
    return (row.metadata_json or {}).get("payload_sha256") == payload_sha256


def _audit_not_billable(
    db: Session,
    *,
    customer: str,
    engagement_id: str,
    resolution: PayerResolution,
    correlation: Optional[str],
) -> None:
    a = resolution.assignment
    emit_msp_audit(
        db,
        chains=(customer,),
        restore_tenant=customer,
        event_type="tenant.msp.billing_usage_not_billable",
        actor_subject=TRUSTED_PRODUCER,
        membership_id=None,
        reason_code=f"MSP_BILLING_{resolution.reason}",
        msp_tenant_id=str(a.msp_tenant_id) if a is not None else "",
        customer_tenant_id=customer,
        relationship_id=str(a.relationship_id) if a is not None else None,
        operation=f"billing.usage.not_billable.{engagement_id}",
        correlation=correlation,
    )


def record_assessment_delivery_usage(
    db: Session,
    *,
    customer_tenant_id: str,
    engagement_id: str,
    correlation: Optional[str] = None,
    now: Optional[datetime] = None,
) -> UsageOutcome:
    """Record at most one billable usage event for one delivered assessment.

    Called by the canonical completion boundary in the same transaction. The
    customer, the completion and its time are read from the database, never
    from the caller. Leaves the session in the customer's tenant context.
    """
    product = PRODUCT_ASSESSMENT_DELIVERED
    customer = customer_tenant_id
    set_tenant_context(db, customer)
    evidence = _delivery_evidence(db, customer, engagement_id)
    if evidence is None:
        return UsageOutcome("not_billable", "SOURCE_NOT_COMPLETED")
    occurred_at = _parse_ts(evidence.created_at) or (now or utcnow())
    resolution = resolve_payer(
        db, customer_tenant_id=customer, product_code=product, at=occurred_at
    )
    if resolution.reason == NO_PAYER_ASSIGNMENT:
        return UsageOutcome("not_applicable", NO_PAYER_ASSIGNMENT)
    if not resolution.billable:
        _audit_not_billable(
            db,
            customer=customer,
            engagement_id=engagement_id,
            resolution=resolution,
            correlation=correlation,
        )
        return UsageOutcome("not_billable", resolution.reason)

    assert resolution.assignment is not None
    payer = str(resolution.assignment.payer_tenant_id)
    payload = _semantic_payload(
        product_code=product,
        customer=customer,
        engagement_id=engagement_id,
        source_ref=str(evidence.id),
        resolution=resolution,
    )
    payload_sha256 = canonical_hash(payload)
    key = usage_idempotency_key(product, customer, engagement_id)
    meter_code = PRODUCTS[product][0]
    metadata = {
        **payload,
        "payload_sha256": payload_sha256,
        "idempotency_key": key,
        "occurred_at": occurred_at.isoformat(),
        "ingested_at": (now or utcnow()).isoformat(),
        "correlation_id": correlation,
    }

    set_tenant_context(db, payer)
    try:
        existing = _existing_usage(db, payer, key)
        if existing is not None:
            if not _same_payload(existing, payload_sha256):
                raise UsageIdempotencyConflict(key)
            return UsageOutcome("duplicate", RESOLVED, str(existing.id))
        try:
            with db.begin_nested():
                evt = record_usage_event(
                    db,
                    payer,
                    meter_code,
                    str(payload["quantity"]),
                    key,
                    source=TRUSTED_PRODUCER,
                    occurred_at=occurred_at,
                    metadata_json=metadata,
                )
        except ValueError:
            set_tenant_context(db, customer)
            _audit_not_billable(
                db,
                customer=customer,
                engagement_id=engagement_id,
                resolution=PayerResolution(METER_NOT_CONFIGURED, resolution.assignment),
                correlation=correlation,
            )
            return UsageOutcome("not_billable", METER_NOT_CONFIGURED)
        except IntegrityError:
            # A concurrent producer won the (tenant_id, idempotency_key) race.
            set_tenant_context(db, payer)
            winner = _existing_usage(db, payer, key)
            if winner is None or not _same_payload(winner, payload_sha256):
                raise UsageIdempotencyConflict(key)
            return UsageOutcome("duplicate", RESOLVED, str(winner.id))
        emit_msp_audit(
            db,
            chains=(customer, payer),
            restore_tenant=customer,
            event_type="tenant.msp.billing_usage_recorded",
            actor_subject=TRUSTED_PRODUCER,
            membership_id=None,
            reason_code="MSP_BILLING_USAGE_RECORDED",
            msp_tenant_id=str(resolution.assignment.msp_tenant_id),
            customer_tenant_id=customer,
            relationship_id=str(resolution.assignment.relationship_id),
            operation=f"billing.usage.recorded.{evt.id}",
            correlation=correlation,
        )
        return UsageOutcome("recorded", RESOLVED, str(evt.id))
    finally:
        set_tenant_context(db, customer)


def record_delivery_usage_safely(
    db: Session,
    *,
    customer_tenant_id: str,
    engagement_id: str,
    correlation: Optional[str] = None,
) -> Optional[UsageOutcome]:
    """Completion-boundary wrapper: billing never blocks a QA-approved delivery.

    Any failure is rolled back to a savepoint and logged by reason only; the
    delivered engagement without usage is then reported by reconcile_period().
    """
    try:
        with db.begin_nested():
            return record_assessment_delivery_usage(
                db,
                customer_tenant_id=customer_tenant_id,
                engagement_id=engagement_id,
                correlation=correlation,
            )
    except Exception as exc:  # noqa: BLE001 — never fail delivery on billing
        log.warning(
            "msp_billing.usage_not_recorded engagement_id=%s error=%s",
            engagement_id,
            type(exc).__name__,
        )
        set_tenant_context(db, customer_tenant_id)
        return None


# ---------------------------------------------------------------------------
# Processor reporting (test mode only; reuses BillingReconciler)
# ---------------------------------------------------------------------------


def report_pending_usage(db: Session, *, payer_tenant_id: str, provider: Any) -> dict:
    """Report the payer's pending MSP usage through a test-mode provider.

    Refuses anything not explicitly a test-mode adapter: MSP-006 does not
    authorize live charges, and StripeProvider.report_usage calls an API that
    the installed SDK no longer provides (audit finding F10).
    """
    if getattr(provider, "test_mode", False) is not True:
        raise LiveProcessorRefused("only a test-mode provider may be used")
    set_tenant_context(db, payer_tenant_id)
    return BillingReconciler().reconcile_pending_usage(
        db, provider, tenant_id=payer_tenant_id
    )


# ---------------------------------------------------------------------------
# Periods, views and reconciliation
# ---------------------------------------------------------------------------


def parse_period(period: str) -> tuple[datetime, datetime]:
    m = _PERIOD_RE.fullmatch(period or "")
    if m is None:
        raise billing_error(422, BILLING_PERIOD_INVALID)
    year, month = int(m.group(1)), int(m.group(2))
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = (
        datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        if month == 12
        else datetime(year, month + 1, 1, tzinfo=timezone.utc)
    )
    return start, end


def _period_usage(db: Session, payer: str, start: datetime, end: datetime):
    return db.query(UsageEvent).filter(
        UsageEvent.tenant_id == payer,
        UsageEvent.meter_code.in_(sorted(MSP_METERS)),
        UsageEvent.occurred_at >= start,
        UsageEvent.occurred_at < end,
    )


def _iso(v: Any) -> Optional[str]:
    ts = as_utc(v)
    return ts.isoformat() if ts else None


def assignment_view(row: MspPayerAssignment, caller: str) -> dict[str, Any]:
    return {
        "payer_assignment_id": str(row.id),
        "customer_tenant_id": str(row.tenant_id),
        "msp_tenant_id": str(row.msp_tenant_id),
        "relationship_id": str(row.relationship_id),
        "payer_tenant_id": str(row.payer_tenant_id),
        "billing_mode": str(row.billing_mode),
        "product_code": str(row.product_code),
        "currency": str(row.currency),
        "status": str(row.status),
        "effective_at": _iso(row.effective_at),
        "expires_at": _iso(row.expires_at),
        "terminated_at": _iso(row.terminated_at),
        "caller_is_payer": str(row.payer_tenant_id) == caller,
        "version": int(row.version),
    }


def usage_view(row: UsageEvent) -> dict[str, Any]:
    md = row.metadata_json or {}
    return {
        "usage_event_id": str(row.id),
        "product_code": md.get("product_code"),
        "customer_tenant_id": md.get("customer_tenant_id"),
        "relationship_id": md.get("relationship_id"),
        "payer_assignment_id": md.get("payer_assignment_id"),
        "billing_mode": md.get("billing_mode"),
        "quantity": md.get("quantity"),
        "unit": md.get("unit"),
        "unit_amount_minor": md.get("unit_amount_minor"),
        "amount_minor": md.get("amount_minor"),
        "currency": md.get("currency"),
        "pricing_version_id": md.get("pricing_version_id"),
        "occurred_at": _iso(row.occurred_at),
        "billing_status": str(row.billing_status),
    }


_PAYLOAD_KEYS = (
    "schema_version",
    "source_service",
    "source_event_id",
    "source_event_ref",
    "product_code",
    "meter_code",
    "quantity",
    "unit",
    "customer_tenant_id",
    "msp_tenant_id",
    "relationship_id",
    "payer_assignment_id",
    "payer_tenant_id",
    "billing_mode",
    "currency",
    "unit_amount_minor",
    "amount_minor",
    "pricing_version_id",
    "pricing_hash",
    "tenant_contract_id",
    "contract_hash",
)


def _check_record(db: Session, row: UsageEvent, payer: str) -> list[str]:
    """Re-derive one charge from its sources. Returns problem codes (empty = ok)."""
    md = row.metadata_json or {}
    problems: list[str] = []
    payload = {k: md.get(k) for k in _PAYLOAD_KEYS}
    if canonical_hash(payload) != md.get("payload_sha256"):
        problems.append("PAYLOAD_HASH_MISMATCH")
    if md.get("payer_tenant_id") != payer or str(row.tenant_id) != payer:
        problems.append("PAYER_MISMATCH")
    product = md.get("product_code")
    if product not in PRODUCTS or PRODUCTS[product][0] != row.meter_code:
        problems.append("PRODUCT_MISMATCH")
    qty = md.get("quantity")
    if (
        not isinstance(qty, int)
        or isinstance(qty, bool)
        or str(qty) != str(row.quantity)
    ):
        problems.append("QUANTITY_MISMATCH")
    pv = db.get(PricingVersion, md.get("pricing_version_id") or "")
    if pv is None:
        problems.append("PRICING_VERSION_MISSING")
    else:
        if pricing_version_hash(pv.pricing_version_id, pv.rates_json) != md.get(
            "pricing_hash"
        ) or str(pv.sha256_hash) != md.get("pricing_hash"):
            problems.append("PRICING_HASH_MISMATCH")
        rate = _rate_for(pv.rates_json, str(product))
        if rate is None or rate != (md.get("unit_amount_minor"), md.get("currency")):
            problems.append("RATE_MISMATCH")
        elif isinstance(qty, int) and qty * rate[0] != md.get("amount_minor"):
            problems.append("AMOUNT_MISMATCH")
    a = db.get(MspPayerAssignment, md.get("payer_assignment_id") or "")
    if a is None:
        problems.append("PAYER_ASSIGNMENT_MISSING")
    else:
        if str(a.payer_tenant_id) != md.get("payer_tenant_id") or str(
            a.billing_mode
        ) != md.get("billing_mode"):
            problems.append("PAYER_CHANGED")
        if str(a.currency) != md.get("currency"):
            problems.append("CURRENCY_MISMATCH")
    if str(row.billing_status) == "reported" and not row.provider_event_id:
        problems.append("MISSING_PROCESSOR_REFERENCE")
    return problems


def reconcile_period(
    db: Session, *, payer_tenant_id: str, period: str
) -> dict[str, Any]:
    """Deterministic reconciliation of one payer's MSP charges for one month.

    Every charge is reconstructed from its usage record, payer assignment and
    pinned price; duplicates, missing processor references, payer changes,
    webhook replays and deliveries without usage are reported. The same inputs
    always give the same report and ``report_sha256``.
    """
    start, end = parse_period(period)
    set_tenant_context(db, payer_tenant_id)
    rows = (
        _period_usage(db, payer_tenant_id, start, end)
        .order_by(UsageEvent.occurred_at, UsageEvent.id)
        .all()
    )
    charges: list[dict[str, Any]] = []
    totals: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    by_source: dict[tuple[str, str, str], list[str]] = {}
    for row in rows:
        md = row.metadata_json or {}
        problems = _check_record(db, row, payer_tenant_id)
        status = str(row.billing_status)
        status_counts[status] = status_counts.get(status, 0) + 1
        source = (
            str(md.get("customer_tenant_id")),
            str(md.get("product_code")),
            str(md.get("source_event_id")),
        )
        by_source.setdefault(source, []).append(str(row.id))
        if not problems:
            cur = str(md.get("currency"))
            totals[cur] = totals.get(cur, 0) + int(md.get("amount_minor") or 0)
        charges.append(
            {
                "usage_event_id": str(row.id),
                "customer_tenant_id": md.get("customer_tenant_id"),
                "source_event_id": md.get("source_event_id"),
                "amount_minor": md.get("amount_minor"),
                "currency": md.get("currency"),
                "billing_status": status,
                "settlement": (
                    "pending_processor_ack" if status == "pending" else status
                ),
                "problems": problems,
            }
        )
    duplicates = sorted(
        {
            "|".join(source): ids for source, ids in by_source.items() if len(ids) > 1
        }.items()
    )
    replays = (
        db.query(BillingEventLedger.entity_id, func.count(BillingEventLedger.id))
        .filter(BillingEventLedger.entity_type == "stripe_webhook")
        .group_by(BillingEventLedger.entity_id)
        .having(func.count(BillingEventLedger.id) > 1)
        .all()
    )
    missing = _deliveries_without_usage(db, payer_tenant_id, start, end, by_source)
    set_tenant_context(db, payer_tenant_id)
    body = {
        "payer_tenant_id": payer_tenant_id,
        "period": period,
        "charges": charges,
        "totals_minor_by_currency": dict(sorted(totals.items())),
        "billing_status_counts": dict(sorted(status_counts.items())),
        "duplicate_source_references": [
            {"source": k, "usage_event_ids": v} for k, v in duplicates
        ],
        "webhook_replays_recorded": len(replays),
        "deliveries_without_usage": missing,
        "settlement": "NOT_PROVEN",
        "ok": all(not c["problems"] for c in charges)
        and not duplicates
        and not missing,
    }
    return {**body, "report_sha256": canonical_hash(body)}


def _not_billable_decision(db: Session, customer: str, engagement_id: str) -> bool:
    """True when the producer recorded a not-billable decision for this
    delivery on the customer's chain (so it is accounted for, not missing)."""
    return (
        db.query(TenantIdentityAuditEvent.id)
        .filter(
            TenantIdentityAuditEvent.tenant_id == customer,
            TenantIdentityAuditEvent.event_type
            == "tenant.msp.billing_usage_not_billable",
            TenantIdentityAuditEvent.details_json["operation"].as_string()
            == f"billing.usage.not_billable.{engagement_id}",
        )
        .first()
        is not None
    )


def _deliveries_without_usage(
    db: Session,
    payer: str,
    start: datetime,
    end: datetime,
    recorded: dict[tuple[str, str, str], list[str]],
) -> list[dict[str, Any]]:
    """Delivered assessments covered by this payer's assignments with no usage."""
    set_tenant_context(db, payer)
    assignments = (
        db.query(MspPayerAssignment)
        .filter(MspPayerAssignment.payer_tenant_id == payer)
        .order_by(MspPayerAssignment.id)
        .all()
    )
    found: list[dict[str, Any]] = []
    for a in assignments:
        customer = str(a.tenant_id)
        set_tenant_context(db, customer)
        events = (
            db.query(FaEngagementAuditEvent)
            .filter(
                FaEngagementAuditEvent.tenant_id == customer,
                FaEngagementAuditEvent.event_type == "engagement.status_transitioned",
            )
            .all()
        )
        for ev in events:
            if (ev.payload or {}).get("new_status") != "delivered":
                continue
            at = _parse_ts(ev.created_at)
            if at is None or not (start <= at < end) or not _in_coverage(a, at):
                continue
            key = (customer, str(a.product_code), str(ev.engagement_id))
            if key in recorded or _not_billable_decision(
                db, customer, str(ev.engagement_id)
            ):
                continue
            found.append(
                {
                    "customer_tenant_id": customer,
                    "source_event_id": str(ev.engagement_id),
                    "payer_assignment_id": str(a.id),
                }
            )
    set_tenant_context(db, payer)
    return sorted(found, key=lambda d: (d["customer_tenant_id"], d["source_event_id"]))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _bind_console_gateway_tenant(request: Request) -> None:
    _ensure_admin_gateway_tenant_bound(request)


_CONSOLE_BIND = Depends(_bind_console_gateway_tenant)


def _caller_tenant_from_auth(request: Request, actor_ctx: ActorContext) -> str:
    tenant = str(actor_ctx.tenant_id or "").strip()
    if not tenant:
        raise msp_error(403, MSP_ACCESS_DENIED)
    return resolve_authoritative_tenant(request, actor_ctx, tenant)


@router.get(
    "/payer-assignments",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_payer_assignments(
    request: Request,
    limit: int = Query(DEFAULT_PAGE, ge=1, le=MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("billing.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Payer assignments where the caller is the customer or the payer.

    An MSP never sees a customer-paid assignment: the relationship alone
    grants no billing visibility.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    set_tenant_context(db, caller)
    base = db.query(MspPayerAssignment).filter(
        or_(
            MspPayerAssignment.tenant_id == caller,
            MspPayerAssignment.payer_tenant_id == caller,
        )
    )
    total = base.count()
    rows = (
        base.order_by(MspPayerAssignment.created_at.desc(), MspPayerAssignment.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    items = [assignment_view(r, caller) for r in rows]
    return {
        "tenant_id": caller,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": offset + len(items) if offset + len(items) < total else None,
    }


@router.get(
    "/usage",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_billable_usage(
    request: Request,
    period: str = Query(..., min_length=7, max_length=7),
    limit: int = Query(DEFAULT_PAGE, ge=1, le=MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("billing.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The caller's own MSP charges for one month, as payer. Totals cover the
    whole month in integer minor units per currency; items are paginated."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    start, end = parse_period(period)
    set_tenant_context(db, caller)
    base = _period_usage(db, caller, start, end)
    rows_all = base.order_by(UsageEvent.occurred_at, UsageEvent.id).all()
    totals: dict[str, int] = {}
    for r in rows_all:
        md = r.metadata_json or {}
        cur = str(md.get("currency"))
        totals[cur] = totals.get(cur, 0) + int(md.get("amount_minor") or 0)
    page = rows_all[offset : offset + limit]
    total = len(rows_all)
    return {
        "payer_tenant_id": caller,
        "period": period,
        "items": [usage_view(r) for r in page],
        "estimated_total_minor_by_currency": dict(sorted(totals.items())),
        "settlement": "NOT_PROVEN",
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": offset + len(page) if offset + len(page) < total else None,
    }


class CreatePayerAssignmentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_tenant_id: str = Field(..., min_length=1, max_length=128)
    relationship_id: str = Field(..., min_length=1, max_length=36)
    billing_mode: Literal["msp_paid", "customer_paid"]
    product_code: str = Field(..., min_length=1, max_length=64)
    subscription_contract_id: str = Field(..., min_length=1, max_length=128)
    currency: str = Field(..., pattern=r"^[A-Z]{3}$")
    effective_at: Optional[datetime] = None
    expires_at: datetime


class TerminatePayerAssignmentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_tenant_id: str = Field(..., min_length=1, max_length=128)
    expected_version: int = Field(..., ge=1)


@router.post(
    "/payer-assignments",
    dependencies=[
        Depends(require_internal_admin_gateway),
        Depends(require_scopes("admin:write")),
    ],
)
def create_payer_assignment(
    body: CreatePayerAssignmentBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Platform operator binds a payer to an active relationship and the payer's
    active commercial agreement. The payer is derived from ``billing_mode`` and
    the relationship, never supplied by the caller."""
    if body.product_code not in PRODUCTS:
        raise billing_error(422, BILLING_PRODUCT_UNKNOWN)
    now = utcnow()
    effective_at = as_utc(body.effective_at) or now
    expires_at = as_utc(body.expires_at)
    if (
        expires_at is None
        or expires_at <= effective_at
        or expires_at > effective_at + timedelta(days=MAX_ASSIGNMENT_DAYS)
    ):
        raise billing_error(422, BILLING_PAYER_ASSIGNMENT_INVALID)

    # RLS: the relationship is visible only in a party's context, so the
    # customer is named and then verified against the relationship row.
    customer = body.customer_tenant_id
    set_tenant_context(db, customer)
    rel = load_relationship(db, body.relationship_id)
    if rel is None or str(rel.tenant_id) != customer:
        raise billing_error(404, BILLING_RELATIONSHIP_INACTIVE)
    msp = str(rel.msp_tenant_id)
    if effective_status(rel, now) != "active":
        raise billing_error(409, BILLING_RELATIONSHIP_INACTIVE)
    set_tenant_context(db, msp)
    if not msp_organization_active(db, msp):
        raise billing_error(409, BILLING_RELATIONSHIP_INACTIVE)
    payer = msp if body.billing_mode == "msp_paid" else customer
    if not _agreement_in_force(db, body.subscription_contract_id, payer, effective_at):
        raise billing_error(409, BILLING_AGREEMENT_INVALID)

    set_tenant_context(db, customer)
    subject = actor_ctx.subject or "platform"
    row = MspPayerAssignment(
        id=str(uuid.uuid4()),
        tenant_id=customer,
        msp_tenant_id=msp,
        relationship_id=str(rel.id),
        payer_tenant_id=payer,
        billing_mode=body.billing_mode,
        product_code=body.product_code,
        subscription_contract_id=body.subscription_contract_id,
        currency=body.currency,
        status="active",
        effective_at=effective_at,
        expires_at=expires_at,
        approved_by_subject=subject,
        approved_at=now,
        version=1,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise billing_error(409, BILLING_PAYER_ASSIGNMENT_EXISTS)
    emit_msp_audit(
        db,
        chains=(customer, payer),
        restore_tenant=customer,
        event_type="tenant.msp.payer_assigned",
        actor_subject=subject,
        membership_id=None,
        reason_code="MSP_BILLING_PAYER_ASSIGNED",
        msp_tenant_id=msp,
        customer_tenant_id=customer,
        relationship_id=str(rel.id),
        operation=f"billing.payer.assign.{body.billing_mode}",
        correlation=correlation_id(request),
    )
    view = assignment_view(row, payer)
    db.commit()
    return view


@router.post(
    "/payer-assignments/{assignment_id}/terminate",
    dependencies=[
        Depends(require_internal_admin_gateway),
        Depends(require_scopes("admin:write")),
    ],
)
def terminate_payer_assignment(
    assignment_id: str,
    body: TerminatePayerAssignmentBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """End a payer assignment. Recorded usage and history are kept; only future
    deliveries stop resolving to this payer."""
    customer = body.customer_tenant_id
    set_tenant_context(db, customer)
    row = db.get(MspPayerAssignment, assignment_id)
    if row is None or str(row.tenant_id) != customer:
        raise billing_error(404, BILLING_PAYER_ASSIGNMENT_NOT_FOUND)
    payer = str(row.payer_tenant_id)
    if str(row.status) != "active" or int(row.version) != body.expected_version:
        raise billing_error(409, BILLING_PAYER_ASSIGNMENT_INVALID)
    now = utcnow()
    subject = actor_ctx.subject or "platform"
    updated = (
        db.query(MspPayerAssignment)
        .filter(
            MspPayerAssignment.id == assignment_id,
            MspPayerAssignment.version == body.expected_version,
            MspPayerAssignment.status == "active",
        )
        .update(
            {
                "status": "terminated",
                "terminated_by_subject": subject,
                "terminated_at": now,
                "version": body.expected_version + 1,
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        db.rollback()
        raise billing_error(409, BILLING_PAYER_ASSIGNMENT_INVALID)
    emit_msp_audit(
        db,
        chains=(customer, payer),
        restore_tenant=customer,
        event_type="tenant.msp.payer_assignment_terminated",
        actor_subject=subject,
        membership_id=None,
        reason_code="MSP_BILLING_PAYER_TERMINATED",
        msp_tenant_id=str(row.msp_tenant_id),
        customer_tenant_id=customer,
        relationship_id=str(row.relationship_id),
        operation="billing.payer.terminate",
        correlation=correlation_id(request),
    )
    db.commit()
    db.expire_all()
    set_tenant_context(db, customer)
    fresh = db.get(MspPayerAssignment, assignment_id)
    if fresh is None:
        raise billing_error(404, BILLING_PAYER_ASSIGNMENT_NOT_FOUND)
    return assignment_view(fresh, payer)


@router.get(
    "/reconciliation",
    dependencies=[
        Depends(require_internal_admin_gateway),
        Depends(require_scopes("admin:read")),
    ],
)
def get_reconciliation(
    request: Request,
    payer_tenant_id: str = Query(..., min_length=1, max_length=128),
    period: str = Query(..., min_length=7, max_length=7),
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Platform reconciliation report for one payer and month (read-only)."""
    return reconcile_period(db, payer_tenant_id=payer_tenant_id, period=period)


def assert_meter_not_reserved(meter_code: str, idempotency_key: str = "") -> None:
    """Reserved MSP meters and the producer's idempotency namespace accept
    usage only from MSP-006's trusted producer (audit F7; review P1)."""
    if str(meter_code).startswith(RESERVED_METER_PREFIX) or str(
        idempotency_key
    ).startswith(RESERVED_KEY_PREFIX):
        raise billing_error(403, BILLING_METER_RESTRICTED)
