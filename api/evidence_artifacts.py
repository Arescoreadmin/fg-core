from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from api.db_models import DecisionEvidenceArtifact, DecisionRecord

DECISION_EVIDENCE_SCHEMA_VERSION = "1.0"
DECISION_EVIDENCE_SCHEMA_ID = "decision_evidence.v1.0"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(obj: Any) -> str:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _artifact_root() -> Path:
    return Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts")).resolve()


def build_decision_evidence_payload(record: DecisionRecord) -> dict[str, Any]:
    return {
        "schema_version": DECISION_EVIDENCE_SCHEMA_VERSION,
        "decision_id": int(record.id),
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "tenant_id": record.tenant_id,
        "event_id": record.event_id,
        "event_type": record.event_type,
        "source": record.source,
        "threat_level": record.threat_level,
        "policy_hash": record.policy_hash,
        "request": record.request_json,
        "response": record.response_json,
        "rules_triggered": record.rules_triggered_json,
        "decision_diff": record.decision_diff_json,
        "chain_hash": record.chain_hash,
        "prev_hash": record.prev_hash,
        "chain_alg": record.chain_alg,
        "chain_ts": record.chain_ts.isoformat() if record.chain_ts else None,
    }


def emit_decision_evidence(
    db: Session, record: DecisionRecord
) -> DecisionEvidenceArtifact:
    if record.id is None:
        raise ValueError("DecisionRecord must be flushed before evidence emission")

    payload = build_decision_evidence_payload(record)
    payload_json = _canonical_json(payload)
    digest = _sha256_hex(payload_json)

    root = _artifact_root() / "decision_evidence"
    root.mkdir(parents=True, exist_ok=True)
    filename = f"{record.id}.json"
    storage_path = root / filename
    storage_path.write_text(payload_json, encoding="utf-8")

    artifact = DecisionEvidenceArtifact(
        created_at=_utcnow(),
        tenant_id=record.tenant_id,
        decision_id=int(record.id),
        evidence_sha256=digest,
        storage_path=str(storage_path),
        payload_json=payload,
    )
    db.add(artifact)
    return artifact
