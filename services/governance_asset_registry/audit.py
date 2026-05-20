"""Governance Asset Registry — tamper-evident chained audit event emission.

Uses the same chain_hash(prev_chain_hash, entry_hash) construction already
proven in SecurityAuditLog and the attestation approval chain.

Chain model:
  chain_id  = f"ga-{tenant_id}"   (one chain per tenant across all assets)
  entry_hash = canonical_hash(event_payload_json)
  chain_hash_val = chain_hash(prev_chain_hash, entry_hash)
  chain_signature = sign_hash(chain_hash_val)   (Ed25519, optional if no key)

Tamper detection: replay rows ordered by seq, recompute chain_hash at each
step, verify signature.  Any modification to a past row invalidates all
subsequent chain_hash_val values.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_assets import GaAssetAuditEvent
from api.signed_artifacts import (
    GENESIS_CHAIN_HASH,
    canonical_hash,
    chain_hash,
    sign_hash,
    signing_key_id,
)
from services.canonical import utc_iso8601_z_now

log = logging.getLogger("frostgate.governance_assets.audit")


def _chain_id(tenant_id: str) -> str:
    return f"ga-{tenant_id}"


def _next_seq(db: Session, chain_id: str) -> tuple[int, str]:
    """Return (next_seq, prev_chain_hash) for the chain."""
    stmt = (
        select(GaAssetAuditEvent.seq, GaAssetAuditEvent.chain_hash_val)
        .where(GaAssetAuditEvent.chain_id == chain_id)
        .order_by(GaAssetAuditEvent.seq.desc())
        .limit(1)
    )
    row = db.execute(stmt).first()
    if row is None:
        return 1, GENESIS_CHAIN_HASH
    return row.seq + 1, row.chain_hash_val


def emit_asset_audit_event(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    event_type: str,
    actor_email: str,
    payload: dict[str, Any],
) -> str:
    """Append a chained, signed audit event.  Returns audit_id.

    Never updates existing rows — append-only contract.
    chain_signature is best-effort; if signing key is unavailable the event
    is still recorded (chain integrity without signature, not ideal for prod
    but prevents audit gaps during key rotation).
    """
    cid = _chain_id(tenant_id)
    seq, prev_hash = _next_seq(db, cid)

    entry_h = canonical_hash(payload)
    chain_h = chain_hash(prev_hash, entry_h)

    sig: str | None = None
    key_id: str | None = None
    try:
        key_id = signing_key_id()
        sig = sign_hash(chain_h)
    except Exception as exc:
        log.warning("ga_audit: signing unavailable — %s", exc)

    audit_id = uuid.uuid4().hex

    db.add(
        GaAssetAuditEvent(
            audit_id=audit_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            chain_id=cid,
            seq=seq,
            event_type=event_type,
            actor_email=actor_email,
            event_payload_json=payload,
            entry_hash=entry_h,
            prev_hash=prev_hash,
            chain_hash_val=chain_h,
            chain_signature=sig,
            key_id=key_id,
            schema_version="1.0",
            created_at=utc_iso8601_z_now(),
        )
    )
    db.flush()
    return audit_id


def verify_asset_audit_chain(db: Session, *, tenant_id: str) -> dict[str, Any]:
    """Replay the entire tenant audit chain and verify integrity.

    Returns:
      {verified: bool, events_checked: int, first_break_seq: int|None, reason: str|None}
    """
    from api.signed_artifacts import verify_hash_signature

    cid = _chain_id(tenant_id)
    stmt = (
        select(GaAssetAuditEvent)
        .where(GaAssetAuditEvent.chain_id == cid)
        .order_by(GaAssetAuditEvent.seq.asc())
    )
    rows = db.execute(stmt).scalars().all()

    prev = GENESIS_CHAIN_HASH
    for row in rows:
        computed_entry = canonical_hash(row.event_payload_json)
        if computed_entry != row.entry_hash:
            return {
                "verified": False,
                "events_checked": row.seq,
                "first_break_seq": row.seq,
                "reason": "entry_hash_mismatch",
            }
        computed_chain = chain_hash(prev, row.entry_hash)
        if computed_chain != row.chain_hash_val:
            return {
                "verified": False,
                "events_checked": row.seq,
                "first_break_seq": row.seq,
                "reason": "chain_hash_mismatch",
            }
        if row.chain_signature and row.key_id:
            ok, reason = verify_hash_signature(
                row.chain_hash_val, row.chain_signature, row.key_id
            )
            if not ok:
                return {
                    "verified": False,
                    "events_checked": row.seq,
                    "first_break_seq": row.seq,
                    "reason": f"signature_invalid:{reason}",
                }
        prev = row.chain_hash_val

    return {
        "verified": True,
        "events_checked": len(rows),
        "first_break_seq": None,
        "reason": None,
    }
