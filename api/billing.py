from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes
from api.db_migrations import _load_migrations
from api.db_models import (
    BillingCountSyncCheckpoint,
    BillingCountSyncCheckpointEvent,
    BillingCoverageDailyState,
    BillingDailyCount,
    BillingDevice,
    BillingIdentityClaim,
    BillingIdentityClaimEvent,
    BillingInvoice,
    BillingInvoiceStateEvent,
    BillingCreditNote,
    BillingDeviceEnrollment,
    BillingDeviceActivityProof,
    BillingRun,
    DeviceCoverageLedger,
    PricingVersion,
    TenantContract,
)
from api.deps import tenant_db_required
from api.security_audit import AuditEvent, EventType, get_auditor
from api.signed_artifacts import canonical_hash, canonical_json

router = APIRouter(prefix="/billing", tags=["billing"])

COVERAGE_DAY_RULE = "UTC"
INVOICE_PERIOD_BOUNDARY = "[period_start, period_end)"
VERIFIER_VERSION = "fg-billing-verify/1"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _canonical_contract_hash(contract: TenantContract) -> str:
    payload = {
        "tenant_id": contract.tenant_id,
        "contract_id": contract.contract_id,
        "pricing_version_id": contract.pricing_version_id,
        "discount_rules_json": contract.discount_rules_json or {},
        "commitment_minimum": float(contract.commitment_minimum or 0.0),
        "start_at": _as_utc(contract.start_at).isoformat() if contract.start_at else None,
        "end_at": _as_utc(contract.end_at).isoformat() if contract.end_at else None,
    }
    return canonical_hash(payload)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _stable_device_key(req: "DeviceUpsertRequest") -> tuple[str, str, int]:
    if req.asset_id and req.asset_verified:
        return "asset_id", f"asset:{req.asset_id}", 100
    if req.agent_stable_id:
        return "agent_stable_id", f"agent:{req.agent_stable_id}", 70
    if req.fingerprint_hash:
        return "fingerprint_hash", f"fingerprint:{req.fingerprint_hash}", 40
    raise HTTPException(
        status_code=400,
        detail=(
            "device identity requires asset_id+verification, agent_stable_id, "
            "or fingerprint_hash"
        ),
    )


def _to_days(start: datetime, end: datetime | None) -> list[date]:
    start_day = _as_utc(start).date()
    if end is None:
        return [start_day]
    end_day = _as_utc(end).date()
    if end_day <= start_day:
        return [start_day]
    days: list[date] = []
    cur = start_day
    while cur < end_day:
        days.append(cur)
        cur += timedelta(days=1)
    return days


def _is_covered(action: str) -> bool:
    return action in {"ADD", "CHANGE", "MERGE"}



def _emit_claim_event(
    db: Session,
    *,
    tenant_id: str,
    claim_id: int,
    transition: str,
    from_state: str | None,
    to_state: str,
    actor: str | None,
    reason: str | None,
) -> BillingIdentityClaimEvent:
    last = (
        db.query(BillingIdentityClaimEvent)
        .filter(
            BillingIdentityClaimEvent.tenant_id == tenant_id,
            BillingIdentityClaimEvent.claim_id == claim_id,
        )
        .order_by(BillingIdentityClaimEvent.sequence.desc())
        .first()
    )
    event = BillingIdentityClaimEvent(
        tenant_id=tenant_id,
        claim_id=claim_id,
        sequence=1 if last is None else (last.sequence + 1),
        transition=transition,
        from_state=from_state,
        to_state=to_state,
        actor=actor,
        reason=reason,
        prev_hash=last.self_hash if last else "GENESIS",
        self_hash="",
        created_at=_utc_now(),
    )
    db.add(event)
    return event


def _resolve_identity_claim(
    db: Session,
    *,
    tenant_id: str,
    device_id: str,
    claim_type: str,
    claim_value: str,
    source_agent_id: str | None,
    source_ip: str | None,
    attestation_level: str,
) -> tuple[str, bool, int]:
    claim = (
        db.query(BillingIdentityClaim)
        .filter(
            BillingIdentityClaim.tenant_id == tenant_id,
            BillingIdentityClaim.claimed_id_type == claim_type,
            BillingIdentityClaim.claimed_id_value == claim_value,
        )
        .one_or_none()
    )
    now = _utc_now()
    if claim is None:
        claim = BillingIdentityClaim(
            tenant_id=tenant_id,
            device_id=device_id,
            claimed_id_type=claim_type,
            claimed_id_value=claim_value,
            first_seen=now,
            last_seen=now,
            source_agent_id=source_agent_id,
            source_ip=source_ip,
            attestation_level=attestation_level,
            conflict_state="clean",
        )
        db.add(claim)
        db.flush()
        _emit_claim_event(
            db,
            tenant_id=tenant_id,
            claim_id=claim.id,
            transition="CLAIM_CREATED",
            from_state=None,
            to_state="clean",
            actor="billing-system",
            reason="new-claim",
        )
        return "clean", False, claim.id

    claim.last_seen = now
    claim.source_agent_id = source_agent_id
    claim.source_ip = source_ip
    claim.attestation_level = attestation_level

    if claim.device_id == device_id and claim.conflict_state in {"clean", "resolved"}:
        return "clean", False, claim.id

    prev = claim.conflict_state
    claim.conflict_state = "conflicted"
    this_device = (
        db.query(BillingDevice)
        .filter(BillingDevice.tenant_id == tenant_id, BillingDevice.device_id == device_id)
        .one_or_none()
    )
    other_device = (
        db.query(BillingDevice)
        .filter(BillingDevice.tenant_id == tenant_id, BillingDevice.device_id == claim.device_id)
        .one_or_none()
    )
    if this_device:
        this_device.billable_state = "non_billable_disputed"
        this_device.collision_signal = True
    if other_device:
        other_device.billable_state = "non_billable_disputed"
        other_device.collision_signal = True
    _emit_claim_event(
        db,
        tenant_id=tenant_id,
        claim_id=claim.id,
        transition="CLAIM_CONFLICT_DETECTED",
        from_state=prev,
        to_state="conflicted",
        actor="billing-system",
        reason=f"conflict-with-device:{claim.device_id}",
    )
    get_auditor().log_event(
        AuditEvent(
            event_type=EventType.ADMIN_ACTION,
            tenant_id=tenant_id,
            request_path="/billing/devices/upsert",
            request_method="POST",
            details={
                "billing_identity_conflict": True,
                "claim_id": claim.id,
                "device_id": device_id,
                "other_device_id": claim.device_id,
                "claimed_id_type": claim_type,
                "claimed_id_value": claim_value,
                "conflict_state": "conflicted",
            },
        )
    )
    return "conflicted", True, claim.id


def _coverage_insert_idempotent(db: Session, event: DeviceCoverageLedger) -> None:
    coverage_state = "covered" if _is_covered(event.action) else "uncovered"
    for day in _to_days(event.effective_from, event.effective_to):
        row = (
            db.query(BillingCoverageDailyState)
            .filter(
                BillingCoverageDailyState.tenant_id == event.tenant_id,
                BillingCoverageDailyState.device_id == event.device_id,
                BillingCoverageDailyState.coverage_day == day,
            )
            .one_or_none()
        )
        if row is None:
            db.add(
                BillingCoverageDailyState(
                    tenant_id=event.tenant_id,
                    device_id=event.device_id,
                    coverage_day=day,
                    coverage_state=coverage_state,
                    plan_id=event.plan_id,
                    source_event_id=event.event_id,
                    source_event_hash=event.self_hash,
                    created_at=_utc_now(),
                )
            )
            continue

        existing = {
            "coverage_state": row.coverage_state,
            "plan_id": row.plan_id,
            "source_event_hash": row.source_event_hash,
        }
        incoming = {
            "coverage_state": coverage_state,
            "plan_id": event.plan_id,
            "source_event_hash": event.self_hash,
        }
        if existing != incoming:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "coverage_day_immutable_conflict",
                    "tenant_id": event.tenant_id,
                    "device_id": event.device_id,
                    "coverage_day": day.isoformat(),
                    "existing": existing,
                    "incoming": incoming,
                },
            )


def _checkpoint_prev_hash(db: Session, tenant_id: str) -> str:
    row = (
        db.query(BillingCountSyncCheckpointEvent)
        .filter(BillingCountSyncCheckpointEvent.tenant_id == tenant_id)
        .order_by(BillingCountSyncCheckpointEvent.sequence.desc())
        .first()
    )
    return row.self_hash if row else "GENESIS"


def _sync_daily_counts_incremental(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 2000,
) -> dict[str, Any]:
    checkpoint = db.get(BillingCountSyncCheckpoint, tenant_id)
    last_ledger_id = checkpoint.last_ledger_id if checkpoint else 0
    events = (
        db.query(DeviceCoverageLedger)
        .filter(
            DeviceCoverageLedger.tenant_id == tenant_id,
            DeviceCoverageLedger.id > last_ledger_id,
        )
        .order_by(DeviceCoverageLedger.id.asc())
        .limit(max(1, limit))
        .all()
    )
    if not events:
        return {
            "processed": 0,
            "last_ledger_id": last_ledger_id,
            "processed_digest": checkpoint.processed_digest if checkpoint else "GENESIS",
        }

    touched_days: set[date] = set()
    for event in events:
        _coverage_insert_idempotent(db, event)
        touched_days.update(_to_days(event.effective_from, event.effective_to))

    for day in sorted(touched_days):
        rows = (
            db.query(BillingCoverageDailyState)
            .join(
                BillingDevice,
                (BillingCoverageDailyState.tenant_id == BillingDevice.tenant_id)
                & (BillingCoverageDailyState.device_id == BillingDevice.device_id),
            )
            .filter(
                BillingCoverageDailyState.tenant_id == tenant_id,
                BillingCoverageDailyState.coverage_day == day,
                BillingCoverageDailyState.coverage_state == "covered",
                BillingDevice.billable_state == "billable",
            )
            .all()
        )
        by_plan: dict[str, set[str]] = defaultdict(set)
        source_hashes_by_plan: dict[str, list[str]] = defaultdict(list)
        for row in rows:
            if row.plan_id:
                by_plan[row.plan_id].add(row.device_id)
                source_hashes_by_plan[row.plan_id].append(row.source_event_hash)

        db.query(BillingDailyCount).filter(
            BillingDailyCount.tenant_id == tenant_id,
            BillingDailyCount.day == day,
        ).delete(synchronize_session=False)

        for plan_id, devices in sorted(by_plan.items()):
            digest = canonical_hash(
                {
                    "tenant_id": tenant_id,
                    "day": day.isoformat(),
                    "plan_id": plan_id,
                    "source_event_hashes": sorted(source_hashes_by_plan[plan_id]),
                }
            )
            db.add(
                BillingDailyCount(
                    tenant_id=tenant_id,
                    day=day,
                    plan_id=plan_id,
                    covered_count=len(devices),
                    computed_from_hash=digest,
                    created_at=_utc_now(),
                )
            )

    processed_digest = canonical_hash(
        {
            "tenant_id": tenant_id,
            "from_ledger_id": last_ledger_id,
            "to_ledger_id": events[-1].id,
            "event_hashes": [event.self_hash for event in events],
            "days": sorted(day.isoformat() for day in touched_days),
        }
    )

    prev_hash = _checkpoint_prev_hash(db, tenant_id)
    last_event = (
        db.query(BillingCountSyncCheckpointEvent)
        .filter(BillingCountSyncCheckpointEvent.tenant_id == tenant_id)
        .order_by(BillingCountSyncCheckpointEvent.sequence.desc())
        .first()
    )
    cp_event = BillingCountSyncCheckpointEvent(
        tenant_id=tenant_id,
        sequence=1 if last_event is None else (last_event.sequence + 1),
        from_ledger_id=last_ledger_id,
        to_ledger_id=events[-1].id,
        processed_digest=processed_digest,
        prev_hash=prev_hash,
        self_hash="",
        created_at=_utc_now(),
    )
    db.add(cp_event)
    db.flush()

    if checkpoint is None:
        checkpoint = BillingCountSyncCheckpoint(
            tenant_id=tenant_id,
            last_ledger_id=events[-1].id,
            processed_digest=processed_digest,
            prev_hash=prev_hash,
            self_hash=cp_event.self_hash,
            updated_at=_utc_now(),
        )
        db.add(checkpoint)
    else:
        checkpoint.prev_hash = checkpoint.self_hash
        checkpoint.self_hash = cp_event.self_hash
        checkpoint.last_ledger_id = events[-1].id
        checkpoint.processed_digest = processed_digest
        checkpoint.updated_at = _utc_now()

    return {
        "processed": len(events),
        "last_ledger_id": events[-1].id,
        "processed_digest": processed_digest,
        "checkpoint_hash": cp_event.self_hash,
    }


def _invoice_daily_rows(
    db: Session,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
) -> tuple[list[dict[str, Any]], str]:
    start_day = _as_utc(period_start).date()
    end_day = _as_utc(period_end).date()
    rows = (
        db.query(BillingDailyCount)
        .filter(
            BillingDailyCount.tenant_id == tenant_id,
            BillingDailyCount.day >= start_day,
            BillingDailyCount.day < end_day,
        )
        .order_by(BillingDailyCount.day.asc(), BillingDailyCount.plan_id.asc())
        .all()
    )
    payload_rows = [
        {
            "day": row.day.isoformat(),
            "plan_id": row.plan_id,
            "covered_count": row.covered_count,
            "computed_from_hash": row.computed_from_hash,
        }
        for row in rows
    ]
    return payload_rows, canonical_hash(payload_rows)


def _pricing_for_invoice(db: Session, pricing_version_id: str) -> PricingVersion:
    row = db.get(PricingVersion, pricing_version_id)
    if row is None:
        raise HTTPException(status_code=404, detail="pricing version not found")
    return row


def _contract_for_invoice(
    db: Session,
    tenant_id: str,
    pricing_version_id: str,
    period_start: datetime,
) -> TenantContract:
    row = (
        db.query(TenantContract)
        .filter(
            TenantContract.tenant_id == tenant_id,
            TenantContract.pricing_version_id == pricing_version_id,
            TenantContract.start_at <= period_start,
            (TenantContract.end_at.is_(None) | (TenantContract.end_at >= period_start)),
        )
        .order_by(TenantContract.start_at.desc())
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="active contract not found")
    expected = _canonical_contract_hash(row)
    if row.contract_hash != expected:
        raise HTTPException(status_code=409, detail="contract_hash_mismatch")
    return row


def _build_invoice_payload(
    *,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    pricing: PricingVersion,
    contract: TenantContract,
    daily_rows: list[dict[str, Any]],
    daily_hash: str,
    config_hash: str,
    policy_hash: str,
) -> dict[str, Any]:
    rates = dict(pricing.rates_json or {})
    line_items: list[dict[str, Any]] = []
    subtotal = 0.0
    for row in daily_rows:
        rate = float(rates.get(row["plan_id"], 0.0))
        amount = round(rate * int(row["covered_count"]), 6)
        subtotal += amount
        line_items.append({**row, "rate": rate, "amount": amount})

    minimum = float(contract.commitment_minimum or 0.0)
    if subtotal < minimum:
        line_items.append(
            {
                "day": _as_utc(period_end).date().isoformat(),
                "plan_id": "commitment_minimum_adjustment",
                "covered_count": 1,
                "computed_from_hash": daily_hash,
                "rate": 1.0,
                "amount": round(minimum - subtotal, 6),
            }
        )
        subtotal = minimum

    return {
        "tenant_id": tenant_id,
        "period_start": _ts(period_start),
        "period_end": _ts(period_end),
        "pricing_version_id": pricing.pricing_version_id,
        "pricing_hash": pricing.sha256_hash,
        "contract_id": contract.contract_id,
        "contract_hash": contract.contract_hash,
        "config_hash": config_hash,
        "policy_hash": policy_hash,
        "daily_rows_hash": daily_hash,
        "line_items": line_items,
        "total": round(subtotal, 6),
    }


class DeviceUpsertRequest(BaseModel):
    tenant_id: str | None = None
    asset_id: str | None = None
    asset_verified: bool = False
    agent_stable_id: str | None = None
    fingerprint_hash: str | None = None
    source_agent_id: str | None = None
    source_ip: str | None = None
    attestation_level: str = "none"
    device_type: str = "unknown"
    status: str = "active"
    labels: dict[str, Any] = Field(default_factory=dict)


class CoverageChangeRequest(BaseModel):
    tenant_id: str | None = None
    event_id: str
    device_id: str
    plan_id: str | None = None
    action: Literal["ADD", "REMOVE", "CHANGE", "RETIRE", "MERGE"]
    effective_from: datetime
    effective_to: datetime | None = None
    pricing_version_id: str | None = None
    config_hash: str
    policy_hash: str
    source: str = "api"


class InvoiceCreateRequest(BaseModel):
    tenant_id: str | None = None
    invoice_id: str
    period_start: datetime
    period_end: datetime
    pricing_version_id: str
    config_hash: str
    policy_hash: str


class InvoiceReproduceResponse(BaseModel):
    invoice_id: str
    recomputed_hash: str
    stored_hash: str
    match: bool


class DisputeResolveRequest(BaseModel):
    tenant_id: str | None = None
    resolved_device_id: str
    reason: str
    ticket_id: str
    resolution_type: Literal["manual_review", "asset_registry_proof", "agent_attestation"]
    resolved_by: str


class BillingRunCreateRequest(BaseModel):
    tenant_id: str | None = None
    run_id: str
    replay_id: str
    pricing_version_id: str
    contract_hash: str
    period_start: datetime
    period_end: datetime


class InvoiceFinalizeRequest(BaseModel):
    tenant_id: str | None = None
    finalized_by: str
    ticket_id: str
    reason: str


class CreditNoteCreateRequest(BaseModel):
    tenant_id: str | None = None
    credit_note_id: str
    amount: float
    currency: str = "USD"
    reason: str
    ticket_id: str
    created_by: str


class DeviceEnrollRequest(BaseModel):
    tenant_id: str | None = None
    device_id: str
    attestation_type: str
    attestation_payload_hash: str
    enrolled_by: str


class DeviceActivityProofRequest(BaseModel):
    tenant_id: str | None = None
    device_id: str
    activity_day: date
    proof_type: str
    proof_hash: str



@router.post("/devices/upsert", dependencies=[Depends(require_scopes("admin:write"))])
def upsert_device(
    req: DeviceUpsertRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    claim_type, device_key, confidence = _stable_device_key(req)
    now = _utc_now()

    device = (
        db.query(BillingDevice)
        .filter(BillingDevice.tenant_id == tenant_id, BillingDevice.device_key == device_key)
        .one_or_none()
    )
    if device is None:
        device = BillingDevice(
            tenant_id=tenant_id,
            device_key=device_key,
            device_type=req.device_type,
            status=req.status,
            labels=req.labels,
            identity_confidence=confidence,
            collision_signal=False,
            billable_state="billable",
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(device)
        db.flush()
    else:
        device.device_type = req.device_type
        device.status = req.status
        device.labels = req.labels
        device.identity_confidence = confidence
        device.last_seen_at = now

    conflict_state, collision, claim_id = _resolve_identity_claim(
        db,
        tenant_id=tenant_id,
        device_id=device.device_id,
        claim_type=claim_type,
        claim_value=device_key,
        source_agent_id=req.source_agent_id,
        source_ip=req.source_ip,
        attestation_level=req.attestation_level,
    )
    device.collision_signal = collision
    if collision:
        device.billable_state = "non_billable_disputed"

    db.commit()
    return {
        "tenant_id": tenant_id,
        "device_id": device.device_id,
        "claim_id": claim_id,
        "device_key": device_key,
        "claimed_id_type": claim_type,
        "identity_confidence": confidence,
        "conflict_state": conflict_state,
        "billable_state": device.billable_state,
    }


@router.get("/identity/disputes", dependencies=[Depends(require_scopes("admin:read"))])
def list_identity_disputes(
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
    max_age_days: int = 7,
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    threshold = _utc_now() - timedelta(days=max_age_days)
    rows = (
        db.query(BillingIdentityClaim)
        .filter(
            BillingIdentityClaim.tenant_id == effective_tenant,
            BillingIdentityClaim.conflict_state == "conflicted",
        )
        .order_by(BillingIdentityClaim.last_seen.asc())
        .all()
    )
    escalated = [
        row
        for row in rows
        if row.last_seen and _as_utc(row.last_seen) <= threshold
    ]
    if escalated:
        get_auditor().log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                tenant_id=effective_tenant,
                request_path="/billing/identity/disputes",
                request_method="GET",
                details={
                    "billing_dispute_sla_breached": True,
                    "count": len(escalated),
                    "max_age_days": max_age_days,
                    "claim_ids": [row.id for row in escalated],
                },
            )
        )
    return {
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
        "items": [
            {
                "claim_id": row.id,
                "device_id": row.device_id,
                "claimed_id_type": row.claimed_id_type,
                "claimed_id_value": row.claimed_id_value,
                "first_seen": _ts(row.first_seen),
                "last_seen": _ts(row.last_seen),
                "conflict_state": row.conflict_state,
                "sla_breached": bool(row.last_seen and _as_utc(row.last_seen) <= threshold),
            }
            for row in rows
        ]
    }


@router.post(
    "/identity/disputes/{claim_id}/resolve",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def resolve_identity_dispute(
    claim_id: int,
    req: DisputeResolveRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    claim = (
        db.query(BillingIdentityClaim)
        .filter(BillingIdentityClaim.tenant_id == tenant_id, BillingIdentityClaim.id == claim_id)
        .one_or_none()
    )
    if claim is None:
        raise HTTPException(status_code=404, detail="claim not found")
    if claim.conflict_state != "conflicted":
        raise HTTPException(status_code=409, detail="claim_not_in_conflicted_state")
    if not req.reason.strip() or not req.ticket_id.strip() or not req.resolved_by.strip():
        raise HTTPException(status_code=400, detail="reason, ticket_id and resolved_by are required")
    previous = claim.conflict_state
    claim.device_id = req.resolved_device_id
    claim.conflict_state = "resolved"
    winner = (
        db.query(BillingDevice)
        .filter(BillingDevice.tenant_id == tenant_id, BillingDevice.device_id == req.resolved_device_id)
        .one_or_none()
    )
    if winner is None:
        raise HTTPException(status_code=404, detail="resolved_device_id not found")
    winner.billable_state = "billable"
    winner.collision_signal = False
    _emit_claim_event(
        db,
        tenant_id=tenant_id,
        claim_id=claim.id,
        transition="CLAIM_RESOLVED",
        from_state=previous,
        to_state="resolved",
        actor="tenant-admin",
        reason=f"{req.resolution_type}:{req.ticket_id}:{req.reason}",
    )
    resolved_at = _utc_now()
    get_auditor().log_event(
        AuditEvent(
            event_type=EventType.ADMIN_ACTION,
            tenant_id=tenant_id,
            request_path=f"/billing/identity/disputes/{claim_id}/resolve",
            request_method="POST",
            details={
                "claim_id": claim_id,
                "resolved_device_id": req.resolved_device_id,
                "reason": req.reason,
                "ticket_id": req.ticket_id,
                "resolution_type": req.resolution_type,
                "resolved_by": req.resolved_by,
                "resolved_at": _ts(resolved_at),
                "previous_state": previous,
                "new_state": "resolved",
            },
        )
    )
    db.commit()
    return {"claim_id": claim.id, "conflict_state": claim.conflict_state}


@router.post("/coverage/change", dependencies=[Depends(require_scopes("admin:write"))])
def coverage_change(
    req: CoverageChangeRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    device = (
        db.query(BillingDevice)
        .filter(BillingDevice.tenant_id == tenant_id, BillingDevice.device_id == req.device_id)
        .one_or_none()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="device not found for tenant")

    prev = (
        db.query(DeviceCoverageLedger)
        .filter(DeviceCoverageLedger.tenant_id == tenant_id)
        .order_by(DeviceCoverageLedger.id.desc())
        .first()
    )
    row = DeviceCoverageLedger(
        tenant_id=tenant_id,
        event_id=req.event_id,
        device_id=req.device_id,
        plan_id=req.plan_id,
        action=req.action,
        effective_from=_as_utc(req.effective_from),
        effective_to=_as_utc(req.effective_to) if req.effective_to else None,
        pricing_version_id=req.pricing_version_id,
        config_hash=req.config_hash,
        policy_hash=req.policy_hash,
        source=req.source,
        created_at=_utc_now(),
        prev_hash=prev.self_hash if prev else "GENESIS",
        self_hash="",
    )
    db.add(row)
    db.flush()
    sync_result = _sync_daily_counts_incremental(db, tenant_id=tenant_id)
    db.commit()
    return {
        "tenant_id": tenant_id,
        "event_id": row.event_id,
        "self_hash": row.self_hash,
        "prev_hash": row.prev_hash,
        "sync_result": sync_result,
    }


@router.post("/daily-counts/sync", dependencies=[Depends(require_scopes("admin:write"))])
def sync_daily_counts(
    tenant_id: str,
    request: Request,
    limit: int = 2000,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    result = _sync_daily_counts_incremental(db, tenant_id=effective_tenant, limit=limit)
    db.commit()
    return {"tenant_id": effective_tenant, **result}


@router.get("/devices", dependencies=[Depends(require_scopes("admin:read"))])
def list_devices(
    tenant_id: str,
    request: Request,
    status: str | None = None,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    query = db.query(BillingDevice).filter(BillingDevice.tenant_id == effective_tenant)
    if status:
        query = query.filter(BillingDevice.status == status)
    rows = query.order_by(BillingDevice.last_seen_at.desc(), BillingDevice.device_key.asc()).all()
    return {
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
        "items": [
            {
                "device_id": row.device_id,
                "device_key": row.device_key,
                "device_type": row.device_type,
                "status": row.status,
                "billable_state": row.billable_state,
                "first_seen_at": _ts(row.first_seen_at),
                "last_seen_at": _ts(row.last_seen_at),
                "labels": row.labels,
                "identity_confidence": row.identity_confidence,
                "collision_signal": row.collision_signal,
            }
            for row in rows
        ]
    }


@router.get(
    "/devices/{device_id}/coverage-timeline",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def coverage_timeline(
    device_id: str,
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    rows = (
        db.query(DeviceCoverageLedger)
        .filter(
            DeviceCoverageLedger.tenant_id == effective_tenant,
            DeviceCoverageLedger.device_id == device_id,
        )
        .order_by(DeviceCoverageLedger.effective_from.asc(), DeviceCoverageLedger.id.asc())
        .all()
    )
    return {
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
        "items": [
            {
                "event_id": row.event_id,
                "action": row.action,
                "plan_id": row.plan_id,
                "effective_from": _ts(row.effective_from),
                "effective_to": _ts(row.effective_to),
                "pricing_version_id": row.pricing_version_id,
                "config_hash": row.config_hash,
                "policy_hash": row.policy_hash,
                "self_hash": row.self_hash,
                "prev_hash": row.prev_hash,
            }
            for row in rows
        ]
    }


@router.post("/runs", dependencies=[Depends(require_scopes("admin:write"))])
def create_billing_run(
    req: BillingRunCreateRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    period_start = _as_utc(req.period_start)
    period_end = _as_utc(req.period_end)
    idem_key = canonical_hash({
        "tenant_id": tenant_id,
        "period_start": _ts(period_start),
        "period_end": _ts(period_end),
        "pricing_version_id": req.pricing_version_id,
        "contract_hash": req.contract_hash,
    })
    existing = (
        db.query(BillingRun)
        .filter(BillingRun.tenant_id == tenant_id, BillingRun.idempotency_key == idem_key)
        .one_or_none()
    )
    if existing is not None:
        return {
            "run_id": existing.run_id,
            "replay_id": existing.replay_id,
            "idempotency_key": existing.idempotency_key,
            "status": existing.status,
            "period_start": _ts(existing.period_start),
            "period_end": _ts(existing.period_end),
            "existing": True,
        }

    run = BillingRun(
        tenant_id=tenant_id,
        run_id=req.run_id,
        replay_id=req.replay_id,
        idempotency_key=idem_key,
        pricing_version_id=req.pricing_version_id,
        contract_hash=req.contract_hash,
        period_start=period_start,
        period_end=period_end,
        status="scheduled",
        created_at=_utc_now(),
    )
    db.add(run)
    db.commit()
    return {
        "run_id": run.run_id,
        "replay_id": run.replay_id,
        "idempotency_key": run.idempotency_key,
        "status": run.status,
        "period_start": _ts(run.period_start),
        "period_end": _ts(run.period_end),
        "existing": False,
    }


@router.get("/runs", dependencies=[Depends(require_scopes("admin:read"))])
def list_billing_runs(
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    rows = (
        db.query(BillingRun)
        .filter(BillingRun.tenant_id == effective_tenant)
        .order_by(BillingRun.created_at.desc())
        .all()
    )
    return {
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
        "items": [
            {
                "run_id": row.run_id,
                "replay_id": row.replay_id,
                "status": row.status,
                "idempotency_key": row.idempotency_key,
                "pricing_version_id": row.pricing_version_id,
                "contract_hash": row.contract_hash,
                "invoice_id": row.invoice_id,
                "export_path": row.export_path,
                "period_start": _ts(row.period_start),
                "period_end": _ts(row.period_end),
            }
            for row in rows
        ]
    }


def _emit_invoice_state_event(
    db: Session,
    *,
    tenant_id: str,
    invoice_id: str,
    transition: str,
    from_state: str | None,
    to_state: str,
    actor: str,
    authority_ticket_id: str,
    reason: str,
) -> BillingInvoiceStateEvent:
    last = (
        db.query(BillingInvoiceStateEvent)
        .filter(
            BillingInvoiceStateEvent.tenant_id == tenant_id,
            BillingInvoiceStateEvent.invoice_id == invoice_id,
        )
        .order_by(BillingInvoiceStateEvent.sequence.desc())
        .first()
    )
    event = BillingInvoiceStateEvent(
        tenant_id=tenant_id,
        invoice_id=invoice_id,
        sequence=1 if last is None else (last.sequence + 1),
        transition=transition,
        from_state=from_state,
        to_state=to_state,
        actor=actor,
        authority_ticket_id=authority_ticket_id,
        reason=reason,
        prev_hash=last.self_hash if last else "GENESIS",
        self_hash="",
        created_at=_utc_now(),
    )
    db.add(event)
    return event


@router.post("/devices/enroll", dependencies=[Depends(require_scopes("admin:write"))])
def enroll_device(
    req: DeviceEnrollRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    device = (
        db.query(BillingDevice)
        .filter(BillingDevice.tenant_id == tenant_id, BillingDevice.device_id == req.device_id)
        .one_or_none()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")

    existing = (
        db.query(BillingDeviceEnrollment)
        .filter(
            BillingDeviceEnrollment.tenant_id == tenant_id,
            BillingDeviceEnrollment.device_id == req.device_id,
        )
        .one_or_none()
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="device_already_enrolled")

    enroll = BillingDeviceEnrollment(
        tenant_id=tenant_id,
        device_id=req.device_id,
        attestation_type=req.attestation_type,
        attestation_payload_hash=req.attestation_payload_hash,
        enrolled_by=req.enrolled_by,
        enrolled_at=_utc_now(),
    )
    db.add(enroll)
    db.commit()
    return {"tenant_id": tenant_id, "device_id": req.device_id, "enrolled_at": _ts(enroll.enrolled_at)}


@router.post("/devices/activity", dependencies=[Depends(require_scopes("admin:write"))])
def record_device_activity_proof(
    req: DeviceActivityProofRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    device = (
        db.query(BillingDevice)
        .filter(BillingDevice.tenant_id == tenant_id, BillingDevice.device_id == req.device_id)
        .one_or_none()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")

    proof = (
        db.query(BillingDeviceActivityProof)
        .filter(
            BillingDeviceActivityProof.tenant_id == tenant_id,
            BillingDeviceActivityProof.device_id == req.device_id,
            BillingDeviceActivityProof.activity_day == req.activity_day,
            BillingDeviceActivityProof.proof_hash == req.proof_hash,
        )
        .one_or_none()
    )
    if proof is None:
        proof = BillingDeviceActivityProof(
            tenant_id=tenant_id,
            device_id=req.device_id,
            activity_day=req.activity_day,
            proof_type=req.proof_type,
            proof_hash=req.proof_hash,
            observed_at=_utc_now(),
        )
        db.add(proof)
        db.commit()
    return {"tenant_id": tenant_id, "device_id": req.device_id, "activity_day": req.activity_day.isoformat(), "proof_hash": req.proof_hash}



@router.post("/invoices", dependencies=[Depends(require_scopes("admin:write"))])
def create_invoice(
    req: InvoiceCreateRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    _sync_daily_counts_incremental(db, tenant_id=tenant_id)

    pricing = _pricing_for_invoice(db, req.pricing_version_id)
    contract = _contract_for_invoice(db, tenant_id, req.pricing_version_id, req.period_start)
    daily_rows, daily_hash = _invoice_daily_rows(db, tenant_id, req.period_start, req.period_end)
    payload = _build_invoice_payload(
        tenant_id=tenant_id,
        period_start=req.period_start,
        period_end=req.period_end,
        pricing=pricing,
        contract=contract,
        daily_rows=daily_rows,
        daily_hash=daily_hash,
        config_hash=req.config_hash,
        policy_hash=req.policy_hash,
    )
    invoice_hash = canonical_hash(payload)

    existing_invoice = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == tenant_id, BillingInvoice.invoice_id == req.invoice_id)
        .one_or_none()
    )
    if existing_invoice is not None:
        raise HTTPException(status_code=409, detail="invoice_id_already_exists")

    row = BillingInvoice(
        tenant_id=tenant_id,
        invoice_id=req.invoice_id,
        period_start=_as_utc(req.period_start),
        period_end=_as_utc(req.period_end),
        pricing_version_id=pricing.pricing_version_id,
        pricing_hash=pricing.sha256_hash,
        contract_hash=contract.contract_hash,
        config_hash=req.config_hash,
        policy_hash=req.policy_hash,
        invoice_json=payload,
        invoice_sha256=invoice_hash,
        invoice_state="draft",
        created_at=_utc_now(),
    )
    db.add(row)
    _emit_invoice_state_event(
        db,
        tenant_id=tenant_id,
        invoice_id=req.invoice_id,
        transition="INVOICE_CREATED",
        from_state=None,
        to_state="draft",
        actor="billing-system",
        authority_ticket_id="system",
        reason="invoice-created",
    )

    run = (
        db.query(BillingRun)
        .filter(
            BillingRun.tenant_id == tenant_id,
            BillingRun.period_start == _as_utc(req.period_start),
            BillingRun.period_end == _as_utc(req.period_end),
            BillingRun.pricing_version_id == req.pricing_version_id,
            BillingRun.contract_hash == contract.contract_hash,
            BillingRun.status == "scheduled",
        )
        .order_by(BillingRun.created_at.desc())
        .first()
    )
    if run:
        run.invoice_id = row.invoice_id
        run.status = "completed"

    db.commit()
    return {
        "invoice_id": row.invoice_id,
        "invoice_sha256": row.invoice_sha256,
        "total": payload["total"],
        "pricing_version_id": row.pricing_version_id,
        "pricing_hash": row.pricing_hash,
        "contract_hash": row.contract_hash,
        "config_hash": row.config_hash,
        "policy_hash": row.policy_hash,
        "finalized_at": _ts(row.finalized_at),
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
    }


@router.post(
    "/invoices/{invoice_id}/reproduce",
    dependencies=[Depends(require_scopes("admin:read"))],
    response_model=InvoiceReproduceResponse,
)
def reproduce_invoice(
    invoice_id: str,
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> InvoiceReproduceResponse:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    row = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == effective_tenant, BillingInvoice.invoice_id == invoice_id)
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")

    pricing = _pricing_for_invoice(db, row.pricing_version_id)
    contract = _contract_for_invoice(db, effective_tenant, row.pricing_version_id, row.period_start)
    daily_rows, daily_hash = _invoice_daily_rows(db, effective_tenant, row.period_start, row.period_end)
    payload = _build_invoice_payload(
        tenant_id=effective_tenant,
        period_start=row.period_start,
        period_end=row.period_end,
        pricing=pricing,
        contract=contract,
        daily_rows=daily_rows,
        daily_hash=daily_hash,
        config_hash=row.config_hash,
        policy_hash=row.policy_hash,
    )
    recomputed = canonical_hash(payload)
    if recomputed != row.invoice_sha256:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "invoice_hash_mismatch",
                "stored_hash": row.invoice_sha256,
                "recomputed_hash": recomputed,
            },
        )
    return InvoiceReproduceResponse(
        invoice_id=invoice_id,
        recomputed_hash=recomputed,
        stored_hash=row.invoice_sha256,
        match=True,
    )


@router.get("/invoices", dependencies=[Depends(require_scopes("admin:read"))])
def list_invoices(
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    rows = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == effective_tenant)
        .order_by(BillingInvoice.created_at.desc())
        .all()
    )
    return {
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
        "items": [
            {
                "invoice_id": row.invoice_id,
                "period_start": _ts(row.period_start),
                "period_end": _ts(row.period_end),
                "invoice_sha256": row.invoice_sha256,
                "pricing_version_id": row.pricing_version_id,
                "pricing_hash": row.pricing_hash,
                "contract_hash": row.contract_hash,
                "config_hash": row.config_hash,
                "policy_hash": row.policy_hash,
                "created_at": _ts(row.created_at),
            }
            for row in rows
        ]
    }


@router.get("/invoices/{invoice_id}", dependencies=[Depends(require_scopes("admin:read"))])
def invoice_details(
    invoice_id: str,
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    row = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == effective_tenant, BillingInvoice.invoice_id == invoice_id)
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    credits = db.query(BillingCreditNote).filter(BillingCreditNote.tenant_id == effective_tenant, BillingCreditNote.invoice_id == invoice_id).all()
    credit_total = round(sum(float(c.amount) for c in credits), 6)
    invoice_total = float((row.invoice_json or {}).get("total", 0.0))
    return {
        "invoice_id": row.invoice_id,
        "period_start": _ts(row.period_start),
        "period_end": _ts(row.period_end),
        "pricing_version_id": row.pricing_version_id,
        "pricing_hash": row.pricing_hash,
        "contract_hash": row.contract_hash,
        "config_hash": row.config_hash,
        "policy_hash": row.policy_hash,
        "invoice_sha256": row.invoice_sha256,
        "invoice_state": row.invoice_state,
        "finalized_at": _ts(row.finalized_at),
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
        "credit_total": credit_total,
        "net_total": round(invoice_total - credit_total, 6),
        "invoice": row.invoice_json,
        "evidence_path": row.evidence_path,
    }


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _attest(payload: bytes) -> tuple[str, str]:
    secret = (os.getenv("FG_BILLING_EVIDENCE_HMAC_KEY") or "billing-dev-key").encode("utf-8")
    sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return sig, "hmac-sha256:key_id=fg_billing_default"


@router.post("/invoices/{invoice_id}/evidence", dependencies=[Depends(require_scopes("admin:read"))])
def export_evidence(
    invoice_id: str,
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    invoice = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == effective_tenant, BillingInvoice.invoice_id == invoice_id)
        .one_or_none()
    )
    if invoice is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if invoice.finalized_at is not None:
        raise HTTPException(status_code=409, detail="invoice_finalized_evidence_frozen")

    daily_counts = (
        db.query(BillingDailyCount)
        .filter(
            BillingDailyCount.tenant_id == effective_tenant,
            BillingDailyCount.day >= _as_utc(invoice.period_start).date(),
            BillingDailyCount.day < _as_utc(invoice.period_end).date(),
        )
        .order_by(BillingDailyCount.day.asc(), BillingDailyCount.plan_id.asc())
        .all()
    )
    coverage_rows = (
        db.query(BillingCoverageDailyState)
        .filter(
            BillingCoverageDailyState.tenant_id == effective_tenant,
            BillingCoverageDailyState.coverage_day >= _as_utc(invoice.period_start).date(),
            BillingCoverageDailyState.coverage_day < _as_utc(invoice.period_end).date(),
        )
        .order_by(BillingCoverageDailyState.coverage_day.asc(), BillingCoverageDailyState.device_id.asc())
        .all()
    )

    files: dict[str, bytes] = {
        "invoice.json": canonical_json(invoice.invoice_json),
        "daily_counts.json": canonical_json(
            [
                {
                    "day": row.day.isoformat(),
                    "plan_id": row.plan_id,
                    "covered_count": row.covered_count,
                    "computed_from_hash": row.computed_from_hash,
                }
                for row in daily_counts
            ]
        ),
        "coverage_proof.json": canonical_json(
            [
                {
                    "coverage_day": row.coverage_day.isoformat(),
                    "device_id": row.device_id,
                    "coverage_state": row.coverage_state,
                    "plan_id": row.plan_id,
                    "source_event_id": row.source_event_id,
                    "source_event_hash": row.source_event_hash,
                }
                for row in coverage_rows
            ]
        ),
        "server_build_info.json": canonical_json(
            {
                "git_sha": _git_commit(),
                "schema_migrations": [m.version for m in _load_migrations()],
                "service_version": os.getenv("FG_SERVICE_VERSION", "unknown"),
                "python_version": os.sys.version,
                "schema_hash": canonical_hash([m.version for m in _load_migrations()]),
                "verifier_version": VERIFIER_VERSION,
                "expected_pubkey_kid": "fg_billing_default",
                "runtime_flags": {
                    "FG_ENV": os.getenv("FG_ENV", ""),
                    "FG_AUTH_ENABLED": os.getenv("FG_AUTH_ENABLED", ""),
                },
            }
        ),
    }
    files["verification.txt"] = (
        "Offline verification:\n"
        "  python scripts/fg_billing_verify.py <bundle_dir> --pubkey <bundle_dir>/attestation.pub\n"
        f"Verifier version: {VERIFIER_VERSION}\n"
        "Expected pubkey KID: fg_billing_default\n"
        f"Expected invoice hash: {invoice.invoice_sha256}\n"
    ).encode("utf-8")

    manifest_entries = []
    for name, payload in sorted(files.items()):
        manifest_entries.append(
            {
                "path": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    manifest = {
        "billing_evidence_spec_version": "v1",
        "invoice_id": invoice_id,
        "tenant_id": effective_tenant,
        "pricing_version_id": invoice.pricing_version_id,
        "pricing_hash": invoice.pricing_hash,
        "contract_hash": invoice.contract_hash,
        "config_hash": invoice.config_hash,
        "policy_hash": invoice.policy_hash,
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
        "verifier_version": VERIFIER_VERSION,
        "expected_pubkey_kid": "fg_billing_default",
        "files": manifest_entries,
        "signature": None,
    }
    manifest_json = canonical_json(manifest)
    sig, pub = _attest(manifest_json)

    files["manifest.json"] = manifest_json
    files["attestation.sig"] = sig.encode("utf-8")
    files["attestation.pub"] = pub.encode("utf-8")

    out_dir = Path("artifacts") / "billing" / effective_tenant / invoice_id
    for name, payload in files.items():
        _atomic_write(out_dir / name, payload)

    invoice.evidence_path = str(out_dir / "manifest.json")
    run = (
        db.query(BillingRun)
        .filter(BillingRun.tenant_id == effective_tenant, BillingRun.invoice_id == invoice_id)
        .order_by(BillingRun.created_at.desc())
        .first()
    )
    if run:
        run.export_path = str(out_dir)
    db.commit()

    return {
        "invoice_id": invoice_id,
        "evidence_path": invoice.evidence_path,
        "bundle_dir": str(out_dir),
        "manifest_path": str(out_dir / "manifest.json"),
        "attestation_sig_path": str(out_dir / "attestation.sig"),
    }


@router.post("/invoices/{invoice_id}/credits", dependencies=[Depends(require_scopes("admin:write"))])
def create_credit_note(
    invoice_id: str,
    req: CreditNoteCreateRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    invoice = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == tenant_id, BillingInvoice.invoice_id == invoice_id)
        .one_or_none()
    )
    if invoice is None:
        raise HTTPException(status_code=404, detail="invoice not found")

    payload = {
        "tenant_id": tenant_id,
        "credit_note_id": req.credit_note_id,
        "invoice_id": invoice_id,
        "amount": round(float(req.amount), 6),
        "currency": req.currency,
        "reason": req.reason,
        "ticket_id": req.ticket_id,
        "created_by": req.created_by,
    }
    sha = canonical_hash(payload)
    note = BillingCreditNote(
        tenant_id=tenant_id,
        credit_note_id=req.credit_note_id,
        invoice_id=invoice_id,
        amount=round(float(req.amount), 6),
        currency=req.currency,
        reason=req.reason,
        ticket_id=req.ticket_id,
        created_by=req.created_by,
        credit_json=payload,
        credit_sha256=sha,
        created_at=_utc_now(),
    )
    db.add(note)

    prev_state = invoice.invoice_state
    invoice.invoice_state = "credited"
    _emit_invoice_state_event(
        db,
        tenant_id=tenant_id,
        invoice_id=invoice_id,
        transition="CREDIT_NOTE_CREATED",
        from_state=prev_state,
        to_state="credited",
        actor=req.created_by,
        authority_ticket_id=req.ticket_id,
        reason=req.reason,
    )
    db.commit()
    return {"credit_note_id": note.credit_note_id, "credit_sha256": note.credit_sha256, "invoice_state": invoice.invoice_state}


@router.get("/invoices/{invoice_id}/credits", dependencies=[Depends(require_scopes("admin:read"))])
def list_credit_notes(
    invoice_id: str,
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    rows = (
        db.query(BillingCreditNote)
        .filter(BillingCreditNote.tenant_id == effective_tenant, BillingCreditNote.invoice_id == invoice_id)
        .order_by(BillingCreditNote.created_at.asc())
        .all()
    )
    return {"items": [{"credit_note_id": r.credit_note_id, "amount": r.amount, "currency": r.currency, "reason": r.reason, "ticket_id": r.ticket_id, "created_by": r.created_by, "credit_sha256": r.credit_sha256} for r in rows]}


@router.post("/credits/{credit_note_id}/evidence", dependencies=[Depends(require_scopes("admin:read"))])
def export_credit_note_evidence(
    credit_note_id: str,
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    note = (
        db.query(BillingCreditNote)
        .filter(BillingCreditNote.tenant_id == effective_tenant, BillingCreditNote.credit_note_id == credit_note_id)
        .one_or_none()
    )
    if note is None:
        raise HTTPException(status_code=404, detail="credit note not found")

    out_dir = Path("artifacts") / "billing" / effective_tenant / "credits" / credit_note_id
    credit_payload = canonical_json(note.credit_json)
    manifest = {
        "billing_evidence_spec_version": "v1",
        "credit_note_id": credit_note_id,
        "invoice_id": note.invoice_id,
        "credit_sha256": note.credit_sha256,
        "verifier_version": VERIFIER_VERSION,
        "expected_pubkey_kid": "fg_billing_default",
        "files": [{"path": "credit_note.json", "sha256": hashlib.sha256(credit_payload).hexdigest(), "size": len(credit_payload)}],
    }
    manifest_json = canonical_json(manifest)
    sig, pub = _attest(manifest_json)
    _atomic_write(out_dir / "credit_note.json", credit_payload)
    _atomic_write(out_dir / "manifest.json", manifest_json)
    _atomic_write(out_dir / "attestation.sig", sig.encode("utf-8"))
    _atomic_write(out_dir / "attestation.pub", pub.encode("utf-8"))
    note.evidence_path = str(out_dir / "manifest.json")
    db.commit()
    return {"credit_note_id": credit_note_id, "evidence_path": note.evidence_path}


@router.post("/invoices/{invoice_id}/finalize", dependencies=[Depends(require_scopes("admin:write"))])
def finalize_invoice(
    invoice_id: str,
    req: InvoiceFinalizeRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, req.tenant_id, require_explicit_for_unscoped=True)
    invoice = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == tenant_id, BillingInvoice.invoice_id == invoice_id)
        .one_or_none()
    )
    if invoice is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if invoice.finalized_at is not None:
        return {"invoice_id": invoice_id, "finalized_at": _ts(invoice.finalized_at), "invoice_state": invoice.invoice_state, "already_finalized": True}

    invoice.finalized_at = _utc_now()
    prev_state = invoice.invoice_state
    invoice.invoice_state = "finalized"
    _emit_invoice_state_event(
        db,
        tenant_id=tenant_id,
        invoice_id=invoice_id,
        transition="INVOICE_FINALIZED",
        from_state=prev_state,
        to_state="finalized",
        actor=req.finalized_by,
        authority_ticket_id=req.ticket_id,
        reason=req.reason,
    )
    get_auditor().log_event(
        AuditEvent(
            event_type=EventType.ADMIN_ACTION,
            tenant_id=tenant_id,
            request_path=f"/billing/invoices/{invoice_id}/finalize",
            request_method="POST",
            details={
                "invoice_id": invoice_id,
                "finalized_by": req.finalized_by,
                "reason": req.reason,
                "finalized_at": _ts(invoice.finalized_at),
            },
        )
    )
    db.commit()
    return {"invoice_id": invoice_id, "finalized_at": _ts(invoice.finalized_at), "invoice_state": invoice.invoice_state, "already_finalized": False}


@router.get("/invoices/{invoice_id}/evidence", dependencies=[Depends(require_scopes("admin:read"))])
def invoice_evidence(
    invoice_id: str,
    tenant_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    effective_tenant = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    row = (
        db.query(BillingInvoice)
        .filter(BillingInvoice.tenant_id == effective_tenant, BillingInvoice.invoice_id == invoice_id)
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    return {
        "invoice_id": invoice_id,
        "evidence_path": row.evidence_path,
        "pricing_version_id": row.pricing_version_id,
        "pricing_hash": row.pricing_hash,
        "contract_hash": row.contract_hash,
        "config_hash": row.config_hash,
        "policy_hash": row.policy_hash,
        "finalized_at": _ts(row.finalized_at),
        "coverage_day_rule": COVERAGE_DAY_RULE,
        "invoice_period_boundary": INVOICE_PERIOD_BOUNDARY,
    }
