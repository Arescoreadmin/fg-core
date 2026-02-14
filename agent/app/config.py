from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os

EVENT_BUCKET_SECONDS = 5
EVENT_ID_CANON_VERSION = "2"


@dataclass(frozen=True)
class AgentConfig:
    tenant_id: str
    agent_id: str
    agent_version: str
    flush_interval_s: float
    batch_size: int
    queue_path: str
    queue_max_size: int
    poll_interval_s: float


def load_config() -> AgentConfig:
    return AgentConfig(
        tenant_id=os.environ["FG_TENANT_ID"],
        agent_id=os.environ["FG_AGENT_ID"],
        agent_version=os.getenv("FG_AGENT_VERSION", "1.0.0"),
        flush_interval_s=float(os.getenv("FG_FLUSH_INTERVAL_SECONDS", "5")),
        batch_size=int(os.getenv("FG_BATCH_SIZE", "100")),
        queue_path=os.getenv("FG_QUEUE_PATH", "/tmp/fg-agent-queue.db"),
        queue_max_size=int(os.getenv("FG_QUEUE_MAX_SIZE", "50000")),
        poll_interval_s=float(os.getenv("FG_COMMAND_POLL_INTERVAL_SECONDS", "10")),
    )


def utc_bucket(ts: datetime, bucket_seconds: int = EVENT_BUCKET_SECONDS) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    unix_ts = int(ts.astimezone(timezone.utc).timestamp())
    bucket_start = unix_ts - (unix_ts % bucket_seconds)
    return str(bucket_start)


def _legacy_canonical_payload(
    tenant_id: str,
    agent_id: str,
    event_type: str,
    subject: str,
    bucket: str,
    features: dict,
) -> str:
    payload = {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "event_type": event_type,
        "subject": subject,
        "bucket": bucket,
        "features": features,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _v2_canonical_payload(
    tenant_id: str,
    agent_id: str,
    event_type: str,
    subject: str,
    bucket: str,
    features: dict,
) -> str:
    payload = {
        "canon_v": EVENT_ID_CANON_VERSION,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "event_type": event_type,
        "subject": subject,
        "bucket": bucket,
        "features": features,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _event_id_keys() -> tuple[str, list[str]]:
    current = os.getenv("FG_EVENT_ID_KEY_CURRENT", "").strip()
    extras = [x.strip() for x in os.getenv("FG_EVENT_ID_KEYS", "").split(",") if x.strip()]
    prev = os.getenv("FG_EVENT_ID_KEY_PREV", "").strip()
    accepted = list(extras)
    if prev:
        accepted.append(prev)
    return current, accepted


def deterministic_event_id(
    tenant_id: str,
    agent_id: str,
    event_type: str,
    subject: str,
    bucket: str,
    features: dict,
) -> str:
    mode = os.getenv("FG_EVENT_ID_MODE", "hmac_v2").strip().lower()
    if mode == "legacy":
        canonical = _legacy_canonical_payload(
            tenant_id, agent_id, event_type, subject, bucket, features
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if mode != "hmac_v2":
        raise ValueError("FG_EVENT_ID_MODE must be one of: legacy, hmac_v2")

    current_key, _accepted_keys = _event_id_keys()
    # Server migration expectation: ingestion should accept IDs generated from CURRENT and PREV keys.
    if not current_key:
        raise ValueError("FG_EVENT_ID_KEY_CURRENT is required when FG_EVENT_ID_MODE=hmac_v2")
    canonical = _v2_canonical_payload(
        tenant_id, agent_id, event_type, subject, bucket, features
    )
    digest = hmac.new(
        current_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"ev2_{digest}"


def config_fingerprint(cfg: AgentConfig) -> str:
    stable = {
        "batch_size": cfg.batch_size,
        "flush_interval_s": cfg.flush_interval_s,
        "poll_interval_s": cfg.poll_interval_s,
        "queue_max_size": cfg.queue_max_size,
    }
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
