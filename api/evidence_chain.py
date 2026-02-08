from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from api.db_models import DecisionRecord

# Public constants expected by tests / other modules
GENESIS_HASH = "GENESIS"

DEFAULT_CHAIN_ALG = "sha256/canonical-json/v1"
CHAIN_ALG = DEFAULT_CHAIN_ALG

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sanitize_hashish(value: Any) -> Optional[str]:
    """
    Accept hash-like fields from DB that might be str/bytes/memoryview.
    Fail-closed on anything else.

    Returns:
      - GENESIS_HASH
      - 64-char lowercase hex sha256
      - None (invalid/unusable)
    """
    if value is None:
        return None

    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", errors="strict")
        except Exception:
            return None

    if not isinstance(value, str):
        return None

    v = value.strip()
    if not v:
        return None
    if v.startswith("tampered-"):
        return None
    if v == GENESIS_HASH:
        return v
    if not _HEX64_RE.match(v):
        return None
    return v


def build_chain_payload(
    *,
    tenant_id: str,
    event_id: str,
    chain_ts: datetime,
    threat_level: str,
    request_json: Any,
    response_json: Any,
    chain_alg: str = CHAIN_ALG,
) -> dict[str, Any]:
    """
    Canonical payload used for chain hashing.
    NOTE: prev_hash is NOT inside the payload; it is chained externally.
    This matches tests + avoids duplicating prev_hash in the hash input.
    """
    return {
        "alg": chain_alg,
        "tenant_id": tenant_id,
        "event_id": event_id,
        "chain_ts": chain_ts.isoformat(),
        "threat_level": threat_level,
        "request_json": request_json,
        "response_json": response_json,
    }


def compute_chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """
    Contract expected by tests / ui_dashboards:
    compute SHA-256 over: prev_hash + canonical_json(payload)
    """
    prev_b = prev_hash.encode("utf-8", errors="strict")
    payload_b = _canonical_json_bytes(payload)
    return hashlib.sha256(prev_b + b"|" + payload_b).hexdigest()


def _latest_chain_hash_for_tenant(db: Session, tenant_id: str) -> Optional[str]:
    """
    Return the most recent usable chain_hash for the tenant.

    IMPORTANT:
    - Do NOT depend on chain_ts ordering. chain_ts can be NULL or behave
      differently across DBs/backends. Tests expect the last inserted record.
    - Prefer monotonic id ordering and require chain_hash to be non-NULL.
    """
    rec = (
        db.query(DecisionRecord)
        .filter(DecisionRecord.tenant_id == tenant_id)
        .filter(DecisionRecord.chain_hash.isnot(None))
        .order_by(desc(DecisionRecord.id), desc(DecisionRecord.created_at))
        .limit(1)
        .one_or_none()
    )
    if rec is None:
        return None
    return _sanitize_hashish(getattr(rec, "chain_hash", None))


def chain_fields_for_decision(
    db: Session,
    *,
    tenant_id: str,
    request_json: Any,
    response_json: Any,
    threat_level: str,
    chain_ts: datetime,
    event_id: str,
    chain_alg: str = CHAIN_ALG,
) -> dict[str, Any]:
    prev = _latest_chain_hash_for_tenant(db, tenant_id) or GENESIS_HASH

    payload = build_chain_payload(
        tenant_id=tenant_id,
        event_id=event_id,
        chain_ts=chain_ts,
        threat_level=threat_level,
        request_json=request_json,
        response_json=response_json,
        chain_alg=chain_alg,
    )
    chain_hash = compute_chain_hash(prev, payload)

    return {
        "prev_hash": prev,
        "chain_hash": chain_hash,
        "chain_alg": chain_alg,
        "chain_ts": chain_ts,
    }


def verify_chain_for_tenant(
    db: Session, tenant_id: str, limit: int | None = None
) -> dict[str, Any]:
    """
    Must:
    - be per-tenant
    - optionally limit results
    - use constant-time compare_digest for comparisons
    - never crash on None/weird types (fail closed)

    Also: tests may pass a fake iterable query object without .all().
    """
    q = (
        db.query(DecisionRecord)
        .filter(DecisionRecord.tenant_id == tenant_id)
        .order_by(
            DecisionRecord.chain_ts.asc(),
            DecisionRecord.created_at.asc(),
            DecisionRecord.id.asc(),
        )
    )
    if limit is not None:
        q = q.limit(limit)

    # Support both real SA queries (.all) and test fakes (iterable only).
    if hasattr(q, "all"):
        rows = q.all()
    else:
        rows = list(q)
        if limit is not None:
            rows = rows[:limit]

    expected_prev: str = GENESIS_HASH
    checked = 0

    for rec in rows:
        checked += 1

        rec_prev = _sanitize_hashish(getattr(rec, "prev_hash", None))
        if (
            not isinstance(rec_prev, str)
            or not isinstance(expected_prev, str)
            or not hmac.compare_digest(rec_prev, expected_prev)
        ):
            return {
                "ok": False,
                "checked": checked,
                "first_bad_id": rec.id,
                "reason": (
                    f"prev_hash_mismatch expected={expected_prev} "
                    f"got={getattr(rec, 'prev_hash', None)}"
                ),
            }

        payload = build_chain_payload(
            tenant_id=rec.tenant_id,
            event_id=str(getattr(rec, "event_id", "")),
            chain_ts=rec.chain_ts or rec.created_at,
            threat_level=rec.threat_level,
            request_json=rec.request_json,
            response_json=rec.response_json,
            chain_alg=rec.chain_alg or CHAIN_ALG,
        )
        expected_hash = compute_chain_hash(expected_prev, payload)

        rec_hash = _sanitize_hashish(getattr(rec, "chain_hash", None))
        if (
            not isinstance(rec_hash, str)
            or not isinstance(expected_hash, str)
            or not hmac.compare_digest(rec_hash, expected_hash)
        ):
            return {
                "ok": False,
                "checked": checked,
                "first_bad_id": rec.id,
                "reason": "chain_hash_mismatch",
            }

        expected_prev = expected_hash

    return {"ok": True, "checked": checked, "first_bad_id": None, "reason": ""}
