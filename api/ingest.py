from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from prometheus_client import Counter
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes
from api.db import set_tenant_context
from api.db_models import DecisionRecord
from api.deps import tenant_db_session
from api.evidence_chain import chain_fields_for_decision
from api.evidence_artifacts import emit_decision_evidence
from api.decision_diff import (
    compute_decision_diff,
    snapshot_from_current,
    snapshot_from_record,
)
from api.ingest_schemas import IngestRequest, IngestResponse
from api.schemas import TelemetryInput
from engine.pipeline import PipelineInput, TieD, evaluate as pipeline_evaluate
from engine.policy_fingerprint import get_active_policy_fingerprint

log = logging.getLogger("frostgate.ingest")


class _NoopCounter:
    def inc(self) -> None:
        return


def _build_replay_counter():
    try:
        return Counter(
            "frostgate_ingest_idempotent_replays_total",
            "Count of /ingest requests returned via idempotent replay",
        )
    except ValueError:
        return _NoopCounter()


INGEST_IDEMPOTENT_REPLAYS = _build_replay_counter()

_EVENT_ID_MAX_LEN = 128
_EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")

router = APIRouter(prefix="/ingest", tags=["ingest"])


# ---- rate limit guard: keep stable, do not invent new paths mid-MVP ----
try:
    from api.ratelimit import rate_limit_guard  # your known path earlier

    _RATE_LIMIT_DEP = Depends(rate_limit_guard)
except Exception:  # pragma: no cover

    async def _noop():
        return None

    _RATE_LIMIT_DEP = Depends(_noop)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _isoz(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, separators=(",", ":"), default=str)
    except Exception:
        return json.dumps({"_unserializable": str(obj)}, separators=(",", ":"))


def _resolve_tenant_id(
    req: TelemetryInput, x_tenant_id: Optional[str], request: Request
) -> str:
    """
    INV-002: Reject silent 'unknown' tenant writes for unscoped keys unless tenant_id is explicit.
    Prefer header X-Tenant-Id, then body tenant_id.
    """
    requested = (x_tenant_id or req.tenant_id or "").strip() or None

    # HARDENING: require explicit tenant id when the API key is unscoped.
    tid = bind_tenant_id(request, requested, require_explicit_for_unscoped=True)

    # Make tenancy explicit everywhere downstream.
    req.tenant_id = tid
    request.state.tenant_id = tid
    return tid


def _resolve_source(req: TelemetryInput) -> str:
    src = (req.source or "").strip()
    return src or "agent"


def _extract_event_id(req: IngestRequest) -> str:
    eid = (getattr(req, "event_id", None) or "").strip()
    if not eid:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INGEST_EVENT_ID_REQUIRED",
                "message": "event_id is required",
            },
        )
    if len(eid) > _EVENT_ID_MAX_LEN:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INGEST_EVENT_ID_INVALID",
                "message": f"event_id exceeds max length {_EVENT_ID_MAX_LEN}",
            },
        )
    if not _EVENT_ID_PATTERN.fullmatch(eid):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INGEST_EVENT_ID_INVALID",
                "message": "event_id contains invalid characters",
            },
        )
    return eid


def _is_event_id_uniqueness_violation(exc: IntegrityError) -> bool:
    msg = str(getattr(exc, "orig", exc)).lower()
    return "uq_decisions_tenant_event_id" in msg or (
        "unique constraint failed" in msg
        and "decisions.tenant_id" in msg
        and "decisions.event_id" in msg
    )


def _existing_ingest_response(
    db: Session,
    *,
    tenant_id: str,
    event_id: str,
    fallback: IngestResponse,
) -> Optional[IngestResponse]:
    existing = (
        db.query(DecisionRecord)
        .filter(
            DecisionRecord.tenant_id == tenant_id,
            DecisionRecord.event_id == event_id,
        )
        .order_by(DecisionRecord.id.desc())
        .first()
    )
    if existing is None:
        return None
    existing_response = getattr(existing, "response_json", None)
    if isinstance(existing_response, dict):
        return IngestResponse(**existing_response)
    return fallback


def _extract_event_type(req: TelemetryInput) -> str:
    et = (req.event_type or "").strip()
    return et or "unknown"


def _extract_actor_target(
    payload: dict[str, Any],
) -> tuple[Optional[str], Optional[str]]:
    actor = (
        payload.get("actor")
        or payload.get("username")
        or payload.get("user")
        or payload.get("principal")
    )
    target = (
        payload.get("target")
        or payload.get("resource")
        or payload.get("dst")
        or payload.get("dst_ip")
    )
    return (
        str(actor) if actor is not None else None,
        str(target) if target is not None else None,
    )


def _extract_src_ip(payload: dict[str, Any]) -> Optional[str]:
    src_ip = payload.get("src_ip") or payload.get("source_ip") or payload.get("ip")
    return str(src_ip) if src_ip is not None else None


@router.post(
    "",
    response_model=IngestResponse,
    responses={
        400: {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "object",
                                "properties": {
                                    "code": {
                                        "type": "string",
                                        "enum": [
                                            "INGEST_EVENT_ID_REQUIRED",
                                            "INGEST_EVENT_ID_INVALID",
                                        ],
                                    },
                                    "message": {"type": "string"},
                                },
                                "required": ["code", "message"],
                            }
                        },
                        "required": ["detail"],
                    }
                }
            },
        }
    },
    dependencies=[
        Depends(require_scopes("ingest:write")),
        _RATE_LIMIT_DEP,
    ],
)
async def ingest(
    req: IngestRequest,
    request: Request,
    response: Response,
    db: Session = Depends(tenant_db_session),
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
) -> IngestResponse:
    """
    Ingest telemetry, evaluate, persist.
    This endpoint should not hard-crash on evaluation/persistence errors.
    """
    t0 = time.time()
    ts = _utcnow()

    tenant_id = _resolve_tenant_id(req, x_tenant_id, request)
    set_tenant_context(db, tenant_id)
    source = _resolve_source(req)

    event_id = _extract_event_id(req)
    response.headers["Idempotency-Key"] = event_id
    response.headers["Idempotent-Replay"] = "false"
    event_type = _extract_event_type(req)

    payload: dict[str, Any] = req.payload or {}
    actor, target = _extract_actor_target(payload)
    src_ip = _extract_src_ip(payload)

    canonical_request: dict[str, Any] = {
        "tenant_id": tenant_id,
        "source": source,
        "timestamp": _isoz(ts),
        "event_id": event_id,
        "event_type": event_type,
        "src_ip": src_ip,
        "actor": actor,
        "target": target,
        "payload": payload,
        "meta": getattr(req, "meta", None),
        "classification": getattr(req, "classification", None),
        "persona": getattr(req, "persona", None),
    }

    # ---- evaluate (never crash ingest) ----
    try:
        pipeline_input = PipelineInput(
            tenant_id=tenant_id,
            source=source,
            event_type=event_type,
            payload=payload,
            timestamp=getattr(req, "timestamp", None) or _isoz(ts),
            persona=getattr(req, "persona", None),
            classification=getattr(req, "classification", None),
            event_id=event_id,
            meta=getattr(req, "meta", None),
            path="/ingest",
        )
        result = pipeline_evaluate(pipeline_input)
        decision = result.to_dict()
        decision["summary"] = result.explanation_brief
        decision["rules"] = list(result.rules_triggered or [])
        decision["pq_fallback"] = False
    except Exception:
        log.exception("evaluation failed")
        fingerprint = get_active_policy_fingerprint()
        fallback_summary = "evaluation error; defaulted to low threat"
        fallback_tie_d = TieD(policy_hash=fingerprint.policy_hash)
        decision = {
            "tenant_id": tenant_id,
            "source": source,
            "event_type": event_type,
            "threat_level": "low",
            "mitigations": [],
            "rules_triggered": ["rule:evaluate_exception"],
            "rules": ["rule:evaluate_exception"],
            "score": 0,
            "anomaly_score": 0.0,
            "ai_adversarial_score": 0.0,
            "tie_d": fallback_tie_d.to_dict(),
            "event_id": event_id,
            "clock_drift_ms": 0,
            "explanation_brief": fallback_summary,
            "summary": fallback_summary,
            "policy_hash": fingerprint.policy_hash,
            "policy": {"allow": False, "reasons": ["evaluation_error"]},
            "pq_fallback": False,
        }

    threat_level = str(decision.get("threat_level") or "low").lower()
    latency_ms = int((time.time() - t0) * 1000)

    resp = IngestResponse(
        status="ok",
        event_id=event_id,
        tenant_id=tenant_id,
        source=source,
        event_type=event_type,
        decision=decision,
        threat_level=threat_level,
        latency_ms=latency_ms,
        persisted=True,
    )

    # ---- persist (best effort) ----
    try:
        rules = decision.get("rules_triggered") or decision.get("rules") or []
        policy_hash = None
        if isinstance(decision, dict):
            policy_hash = decision.get("policy_hash")
            if not policy_hash:
                tie_d = decision.get("tie_d") or {}
                if isinstance(tie_d, dict):
                    policy_hash = tie_d.get("policy_hash")

        # --- Decision Diff (compute + persist) ---
        try:
            prev = (
                db.query(DecisionRecord)
                .filter(
                    DecisionRecord.tenant_id == tenant_id,
                    DecisionRecord.source == source,
                    DecisionRecord.event_type == event_type,
                )
                .order_by(DecisionRecord.id.desc())
                .first()
            )
            prev_snapshot = snapshot_from_record(prev) if prev is not None else None
            curr_snapshot = snapshot_from_current(
                threat_level=threat_level,
                rules_triggered=rules,
                score=decision.get("score"),
            )
            decision_diff_obj = compute_decision_diff(prev_snapshot, curr_snapshot)
        except Exception:
            decision_diff_obj = None
        # --- end Decision Diff ---

        rec = DecisionRecord(
            tenant_id=tenant_id,
            source=source,
            event_id=event_id,
            event_type=event_type,
            policy_hash=policy_hash,
            threat_level=threat_level,
            anomaly_score=float(decision.get("anomaly_score") or 0.0),
            ai_adversarial_score=float(decision.get("ai_adversarial_score") or 0.0),
            pq_fallback=bool(decision.get("pq_fallback") or False),
            # IMPORTANT: these field names MUST match your model/table
            request_json=canonical_request,
            response_json=resp.model_dump(),
            rules_triggered_json=rules,
            decision_diff_json=decision_diff_obj,
        )
        if (
            hasattr(DecisionRecord, "prev_hash")
            and hasattr(DecisionRecord, "chain_hash")
            and hasattr(DecisionRecord, "chain_alg")
            and hasattr(DecisionRecord, "chain_ts")
        ):
            chain_fields = chain_fields_for_decision(
                db,
                tenant_id=tenant_id,
                request_json=canonical_request,
                response_json=resp.model_dump(),
                threat_level=threat_level,
                chain_ts=datetime.now(timezone.utc),
                event_id=event_id,
            )
            rec.prev_hash = chain_fields["prev_hash"]
            rec.chain_hash = chain_fields["chain_hash"]
            rec.chain_alg = chain_fields["chain_alg"]
            rec.chain_ts = chain_fields["chain_ts"]
        try:
            db.add(rec)
            db.flush()
            emit_decision_evidence(db, rec)
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if not _is_event_id_uniqueness_violation(exc):
                raise

            replay = _existing_ingest_response(
                db,
                tenant_id=tenant_id,
                event_id=event_id,
                fallback=resp,
            )
            if replay is None:
                raise

            response.headers["Idempotent-Replay"] = "true"
            INGEST_IDEMPOTENT_REPLAYS.inc()
            log.info(
                "ingest idempotent replay tenant_id=%s event_id=%s idempotent_replay=true",
                tenant_id,
                event_id,
            )
            return replay
    except Exception:
        resp.persisted = False
        log.exception("failed to persist decision")
        try:
            db.rollback()
        except Exception:
            pass

    return resp
