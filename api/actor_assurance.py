"""api/actor_assurance.py — Enterprise Identity Assurance & Trust Levels routes.

Five endpoints:
  GET  /actor-assurance/{actor_id}            — current assurance record
  GET  /actor-assurance/{actor_id}/history    — paginated event history
  GET  /actor-assurance/{actor_id}/snapshot   — latest immutable snapshot
  GET  /actor-assurance/{actor_id}/trust      — trust score summary + band
  POST /actor-assurance/recalculate           — recompute assurance (assurance:write)

All routes:
  - tenant-bound via require_bound_tenant()
  - scope-gated via require_scopes("assurance.read" | "assurance.write")
  - filter by tenant_id on every query (defence-in-depth alongside PG RLS)
  - 404 shape: {"code": "ASSURANCE_NOT_FOUND", "message": "assurance record not found"}
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_bound_tenant, require_scopes
from api.db import get_engine, set_tenant_context
from api.db_models_identity_assurance import (
    ActorAssuranceHistory,
    ActorAssuranceSnapshot,
    ActorIdentityAssurance,
    ActorTrustMetrics,  # noqa: F401 — imported so init_db sees the table
)
from services.identity_assurance.engine import (
    build_assurance_decision,
    chain_hash,
    normalize_provider_claims,
    trust_band_for_score,
)
from services.identity_assurance.metrics import (
    ACTOR_ASSURANCE_CHANGES,
    ACTOR_ASSURANCE_TOTAL,
    ACTOR_TRUST_DISTRIBUTION,
    ASSURANCE_FAILURES,
    HIGH_TRUST_ACTIONS,
    IDENTITY_PROVIDER_USAGE,
    LOW_TRUST_ACTIONS,
)
from services.identity_assurance.models import (
    IdentityProvider,
)

router = APIRouter(tags=["actor-assurance"])

# ---------------------------------------------------------------------------
# Prometheus metrics — endpoint-level counters
# ---------------------------------------------------------------------------

from prometheus_client import Counter  # noqa: E402

ASSURANCE_GET_TOTAL = Counter(
    "frostgate_actor_assurance_get_total", "GET actor assurance requests"
)
ASSURANCE_HISTORY_GET_TOTAL = Counter(
    "frostgate_actor_assurance_history_get_total",
    "GET actor assurance history requests",
)
ASSURANCE_SNAPSHOT_GET_TOTAL = Counter(
    "frostgate_actor_assurance_snapshot_get_total",
    "GET actor assurance snapshot requests",
)
ASSURANCE_TRUST_GET_TOTAL = Counter(
    "frostgate_actor_assurance_trust_get_total",
    "GET actor assurance trust summary requests",
)
ASSURANCE_RECALC_TOTAL = Counter(
    "frostgate_actor_assurance_recalculate_total",
    "POST actor assurance recalculate requests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HIGH_TRUST_MIN = 81
_LOW_TRUST_MAX = 40
_NOT_FOUND_DETAIL = {
    "code": "ASSURANCE_NOT_FOUND",
    "message": "assurance record not found",
}


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or "unknown"
    )


def _iso(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return value.isoformat()
    except Exception:
        return str(value)


def _new_id() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record_dict(row: ActorIdentityAssurance) -> dict:
    band = trust_band_for_score(int(row.trust_score))
    return {
        "actor_id": row.actor_id,
        "tenant_id": row.tenant_id,
        "assurance_level": row.assurance_level,
        "trust_score": int(row.trust_score),
        "trust_band": band.value,
        "identity_provider": row.identity_provider,
        "authentication_method": row.authentication_method,
        "decision_fingerprint": row.decision_fingerprint,
        "chain_hash": row.chain_hash,
        "previous_assurance_level": row.previous_assurance_level,
        "provider_claims_hash": row.provider_claims_hash,
        "is_current": bool(row.is_current),
        "computed_at": _iso(row.computed_at),
        "created_at": _iso(row.created_at),
        "schema_version": row.schema_version,
    }


def _snapshot_dict(row: ActorAssuranceSnapshot) -> dict:
    return {
        "snapshot_id": row.id,
        "actor_id": row.actor_id,
        "tenant_id": row.tenant_id,
        "sequence_number": int(row.sequence_number),
        "previous_assurance_level": row.previous_assurance_level,
        "new_assurance_level": row.new_assurance_level,
        "trust_score": int(row.trust_score),
        "trust_band": trust_band_for_score(int(row.trust_score)).value,
        "identity_provider": row.identity_provider,
        "authentication_method": row.authentication_method,
        "reason": row.reason,
        "snapshot_fingerprint": row.snapshot_fingerprint,
        "chain_hash": row.chain_hash,
        "created_at": _iso(row.created_at),
        "schema_version": row.schema_version,
    }


def _history_dict(row: ActorAssuranceHistory) -> dict:
    return {
        "event_id": row.id,
        "actor_id": row.actor_id,
        "tenant_id": row.tenant_id,
        "event_type": row.event_type,
        "assurance_level": row.assurance_level,
        "trust_score": int(row.trust_score),
        "triggered_by": row.triggered_by,
        "metadata": row.event_metadata,
        "created_at": _iso(row.created_at),
        "schema_version": row.schema_version,
    }


def _record_metrics(
    level: Optional[str],
    score: Optional[int],
    provider: Optional[str],
) -> None:
    try:
        if level:
            ACTOR_ASSURANCE_TOTAL.labels(level=level).inc()
        if provider:
            IDENTITY_PROVIDER_USAGE.labels(provider=provider).inc()
        if score is not None:
            ACTOR_TRUST_DISTRIBUTION.observe(int(score))
            if int(score) >= _HIGH_TRUST_MIN:
                HIGH_TRUST_ACTIONS.inc()
            elif int(score) <= _LOW_TRUST_MAX:
                LOW_TRUST_ACTIONS.inc()
    except Exception:
        # Metrics never break the request path.
        pass


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RecalculateBody(BaseModel):
    actor_id: str
    reason: Optional[str] = None
    provider: Optional[str] = None
    claims: Optional[dict] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/actor-assurance/{actor_id}",
    dependencies=[Depends(require_scopes("assurance.read"))],
)
def get_actor_assurance(actor_id: str, request: Request) -> dict:
    """Return the current assurance record for an actor."""
    tenant_id = require_bound_tenant(request)
    ASSURANCE_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        set_tenant_context(db, tenant_id)
        row = (
            db.query(ActorIdentityAssurance)
            .filter(
                ActorIdentityAssurance.actor_id == actor_id,
                ActorIdentityAssurance.tenant_id == tenant_id,
                ActorIdentityAssurance.is_current.is_(True),
            )
            .order_by(ActorIdentityAssurance.created_at.desc())
            .first()
        )
        if row is None:
            # Fall back to most recent record regardless of is_current in case
            # the flag is not yet set (defence-in-depth against schema drift).
            row = (
                db.query(ActorIdentityAssurance)
                .filter(
                    ActorIdentityAssurance.actor_id == actor_id,
                    ActorIdentityAssurance.tenant_id == tenant_id,
                )
                .order_by(ActorIdentityAssurance.created_at.desc())
                .first()
            )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_DETAIL)
    body = _record_dict(row)
    _record_metrics(
        body["assurance_level"], body["trust_score"], body["identity_provider"]
    )
    return body


@router.get(
    "/actor-assurance/{actor_id}/history",
    dependencies=[Depends(require_scopes("assurance.read"))],
)
def get_actor_assurance_history(
    actor_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Return paginated assurance history for an actor.

    Returns empty pages (not 404) when no history exists — history is a
    permission-side-effect stream and absence is a legitimate observation.
    """
    tenant_id = require_bound_tenant(request)
    ASSURANCE_HISTORY_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        set_tenant_context(db, tenant_id)
        base_q = db.query(ActorAssuranceHistory).filter(
            ActorAssuranceHistory.actor_id == actor_id,
            ActorAssuranceHistory.tenant_id == tenant_id,
        )
        total = base_q.count()
        rows = (
            base_q.order_by(ActorAssuranceHistory.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
    return {
        "actor_id": actor_id,
        "tenant_id": tenant_id,
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": [_history_dict(r) for r in rows],
    }


@router.get(
    "/actor-assurance/{actor_id}/snapshot",
    dependencies=[Depends(require_scopes("assurance.read"))],
)
def get_actor_assurance_snapshot(actor_id: str, request: Request) -> dict:
    """Return the latest immutable snapshot in the assurance chain."""
    tenant_id = require_bound_tenant(request)
    ASSURANCE_SNAPSHOT_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        set_tenant_context(db, tenant_id)
        row = (
            db.query(ActorAssuranceSnapshot)
            .filter(
                ActorAssuranceSnapshot.actor_id == actor_id,
                ActorAssuranceSnapshot.tenant_id == tenant_id,
            )
            .order_by(ActorAssuranceSnapshot.sequence_number.desc())
            .first()
        )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_DETAIL)
    return _snapshot_dict(row)


@router.get(
    "/actor-assurance/{actor_id}/trust",
    dependencies=[Depends(require_scopes("assurance.read"))],
)
def get_actor_trust_summary(actor_id: str, request: Request) -> dict:
    """Return a trust-score summary for an actor."""
    tenant_id = require_bound_tenant(request)
    ASSURANCE_TRUST_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        set_tenant_context(db, tenant_id)
        row = (
            db.query(ActorIdentityAssurance)
            .filter(
                ActorIdentityAssurance.actor_id == actor_id,
                ActorIdentityAssurance.tenant_id == tenant_id,
                ActorIdentityAssurance.is_current.is_(True),
            )
            .order_by(ActorIdentityAssurance.created_at.desc())
            .first()
        )
        if row is None:
            row = (
                db.query(ActorIdentityAssurance)
                .filter(
                    ActorIdentityAssurance.actor_id == actor_id,
                    ActorIdentityAssurance.tenant_id == tenant_id,
                )
                .order_by(ActorIdentityAssurance.created_at.desc())
                .first()
            )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_DETAIL)
    score = int(row.trust_score)
    band = trust_band_for_score(score)
    return {
        "actor_id": row.actor_id,
        "tenant_id": row.tenant_id,
        "trust_score": score,
        "trust_band": band.value,
        "assurance_level": row.assurance_level,
        "score_breakdown": {
            "base_score": score,
            "assurance_level": row.assurance_level,
            "max_possible": 100,
        },
    }


@router.post(
    "/actor-assurance/recalculate",
    dependencies=[Depends(require_scopes("assurance.write"))],
)
def recalculate_actor_assurance(body: RecalculateBody, request: Request) -> dict:
    """Recompute the assurance for an actor and append snapshot + history rows.

    Deterministic: given the same claims + tenant + actor, the resulting
    ``decision_fingerprint`` and ``computed_at_sequence`` will match a prior
    recomputation exactly.
    """
    tenant_id = require_bound_tenant(request)
    ASSURANCE_RECALC_TOTAL.inc()
    actor_id = body.actor_id
    if not actor_id:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "ASSURANCE_BAD_REQUEST",
                "message": "actor_id is required",
            },
        )

    # Normalize provider (default: SYSTEM for system-triggered recalculations).
    raw_claims = body.claims or {}
    try:
        provider_enum = (
            IdentityProvider(body.provider.upper())
            if body.provider
            else IdentityProvider.SYSTEM
        )
    except Exception:
        provider_enum = IdentityProvider.UNKNOWN

    # Route through the provider-specific adapter so that provider-native claim
    # names (e.g. Okta amr:["mfa"], Entra oid, Keycloak realm_access) are
    # translated before the assurance engine evaluates them.  Inject actor_id
    # as the subject fallback before normalisation so the adapter can use it.
    if "sub" not in raw_claims and "subject" not in raw_claims:
        raw_claims = {**raw_claims, "sub": actor_id}
    try:
        provider_claims = normalize_provider_claims(raw_claims, provider_enum)
    except Exception:
        ASSURANCE_FAILURES.inc()
        raise HTTPException(
            status_code=400,
            detail={
                "code": "ASSURANCE_BAD_REQUEST",
                "message": "invalid provider claims",
            },
        )

    try:
        decision = build_assurance_decision(provider_claims, tenant_id, actor_id)
    except Exception:
        ASSURANCE_FAILURES.inc()
        raise HTTPException(
            status_code=400,
            detail={
                "code": "ASSURANCE_BAD_REQUEST",
                "message": "assurance decision could not be built",
            },
        )

    triggered_by = _actor(request)
    now = _now()

    with Session(get_engine()) as db:
        set_tenant_context(db, tenant_id)
        # Locate the most recent current record (if any) for chain continuity.
        prev = (
            db.query(ActorIdentityAssurance)
            .filter(
                ActorIdentityAssurance.actor_id == actor_id,
                ActorIdentityAssurance.tenant_id == tenant_id,
                ActorIdentityAssurance.is_current.is_(True),
            )
            .order_by(ActorIdentityAssurance.created_at.desc())
            .first()
        )

        # Determine sequence number.
        last_snap = (
            db.query(ActorAssuranceSnapshot)
            .filter(
                ActorAssuranceSnapshot.actor_id == actor_id,
                ActorAssuranceSnapshot.tenant_id == tenant_id,
            )
            .order_by(ActorAssuranceSnapshot.sequence_number.desc())
            .first()
        )
        next_seq = 0 if last_snap is None else int(last_snap.sequence_number) + 1

        prev_level = prev.assurance_level if prev is not None else None
        prev_chain = prev.chain_hash if prev is not None else None
        new_chain = chain_hash(prev_chain, decision.fingerprint)

        # Flip existing current rows to is_current=False.
        if prev is not None and prev.decision_fingerprint != decision.fingerprint:
            db.query(ActorIdentityAssurance).filter(
                ActorIdentityAssurance.actor_id == actor_id,
                ActorIdentityAssurance.tenant_id == tenant_id,
                ActorIdentityAssurance.is_current.is_(True),
            ).update({ActorIdentityAssurance.is_current: False})

        # Idempotency: if the current record already matches the fingerprint,
        # keep it and only append history — no new snapshot.
        if prev is not None and prev.decision_fingerprint == decision.fingerprint:
            current_row = prev
            is_change = False
        else:
            current_row = ActorIdentityAssurance(
                id=_new_id(),
                tenant_id=tenant_id,
                actor_id=actor_id,
                assurance_level=decision.assurance_level.value,
                trust_score=int(decision.trust_score),
                identity_provider=decision.provider.value,
                authentication_method=decision.authentication_method,
                provider_claims_hash=decision.provider_claims_hash,
                decision_fingerprint=decision.fingerprint,
                chain_hash=new_chain,
                previous_assurance_level=prev_level,
                is_current=True,
                computed_at=now,
                schema_version="1.0",
            )
            db.add(current_row)
            is_change = prev is None or prev.assurance_level != decision.assurance_level

            snapshot_fp = hashlib.sha256(
                f"{decision.fingerprint}:{next_seq}:{new_chain}".encode("utf-8")
            ).hexdigest()

            snap = ActorAssuranceSnapshot(
                id=_new_id(),
                tenant_id=tenant_id,
                actor_id=actor_id,
                sequence_number=next_seq,
                previous_assurance_level=prev_level,
                new_assurance_level=decision.assurance_level.value,
                trust_score=int(decision.trust_score),
                identity_provider=decision.provider.value,
                authentication_method=decision.authentication_method,
                reason=body.reason,
                snapshot_fingerprint=snapshot_fp,
                chain_hash=new_chain,
                schema_version="1.0",
            )
            db.add(snap)

        history = ActorAssuranceHistory(
            id=_new_id(),
            tenant_id=tenant_id,
            actor_id=actor_id,
            event_type=(
                "assurance_changed" if is_change else "recalculation_requested"
            ),
            assurance_level=decision.assurance_level.value,
            trust_score=int(decision.trust_score),
            triggered_by=triggered_by,
            event_metadata={
                "reason": body.reason,
                "fingerprint": decision.fingerprint,
                "computed_at_sequence": decision.computed_at_sequence,
                "provider": decision.provider.value,
            },
            schema_version="1.0",
        )
        db.add(history)
        db.commit()
        db.refresh(current_row)

        if is_change:
            ACTOR_ASSURANCE_CHANGES.inc()
        _record_metrics(
            current_row.assurance_level,
            int(current_row.trust_score),
            current_row.identity_provider,
        )

        return _record_dict(current_row)
