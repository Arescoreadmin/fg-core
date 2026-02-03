# api/persist.py
import json
import time
import logging
from datetime import datetime, timezone
from sqlalchemy import text
from .db import engine
from api.evidence_chain import CHAIN_ALG, build_chain_payload, compute_chain_hash, GENESIS_HASH

log = logging.getLogger("frostgate.persist")


def persist_decision(
    *,
    tenant_id: str,
    source: str,
    event_id: str,
    event_type: str,
    threat_level: str,
    anomaly_score: float,
    ai_adversarial_score: float,
    pq_fallback: bool,
    rules_triggered: list[str],
    explain_summary: str,
    latency_ms: int,
    request_obj: dict,
    response_obj: dict,
) -> None:
    started = time.time()
    payload = dict(
        tenant_id=tenant_id,
        source=source,
        event_id=event_id,
        event_type=event_type,
        threat_level=threat_level,
        anomaly_score=float(anomaly_score or 0.0),
        ai_adversarial_score=float(ai_adversarial_score or 0.0),
        pq_fallback=bool(pq_fallback),
        rules_triggered_json=json.dumps(rules_triggered or []),
        explain_summary=explain_summary or "",
        latency_ms=int(latency_ms or 0),
        request_json=json.dumps(request_obj or {}),
        response_json=json.dumps(response_obj or {}),
    )

    chain_ts = datetime.now(timezone.utc)

    prev_hash = GENESIS_HASH
    try:
        with engine.begin() as c:
            row = c.execute(
                text(
                    """
                    SELECT chain_hash FROM decisions
                    WHERE tenant_id = :tenant_id
                    ORDER BY created_at DESC, id DESC
                    LIMIT 1
                    """
                ),
                {"tenant_id": tenant_id},
            ).fetchone()
            if row and row[0]:
                prev_hash = row[0]
    except Exception:
        log.exception("FAILED to load previous chain hash for tenant_id=%s", tenant_id)
        raise

    chain_payload = build_chain_payload(
        tenant_id=tenant_id,
        request_json=request_obj,
        response_json=response_obj,
        threat_level=threat_level,
        chain_ts=chain_ts,
        event_id=event_id,
    )
    payload.update(
        {
            "prev_hash": prev_hash,
            "chain_hash": compute_chain_hash(prev_hash, chain_payload),
            "chain_alg": CHAIN_ALG,
            "chain_ts": chain_ts,
        }
    )

    sql = text("""
        INSERT INTO decisions
        (tenant_id, source, event_id, event_type, threat_level,
         anomaly_score, ai_adversarial_score, pq_fallback,
         rules_triggered_json, explain_summary, latency_ms,
         request_json, response_json, prev_hash, chain_hash, chain_alg, chain_ts)
        VALUES
        (:tenant_id, :source, :event_id, :event_type, :threat_level,
         :anomaly_score, :ai_adversarial_score, :pq_fallback,
         :rules_triggered_json, :explain_summary, :latency_ms,
         :request_json, :response_json, :prev_hash, :chain_hash, :chain_alg, :chain_ts)
    """)

    try:
        with engine.begin() as c:
            c.execute(sql, payload)
        log.info(
            "persisted decision event_id=%s in %dms",
            event_id,
            int((time.time() - started) * 1000),
        )
    except Exception:
        log.exception(
            "FAILED to persist decision event_id=%s payload_keys=%s",
            event_id,
            list(payload.keys()),
        )
        raise
