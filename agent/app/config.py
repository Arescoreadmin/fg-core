from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os

EVENT_BUCKET_SECONDS = 5
EVENT_ID_CANON_VERSION = 2  # v2 HMAC canonical payload version


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


def _event_id_keys() -> tuple[str, str | None, list[str]]:
    current = os.getenv("FG_EVENT_ID_KEY_CURRENT", "").strip()
    prev = os.getenv("FG_EVENT_ID_KEY_PREV", "").strip() or None
    from_list = [
        v.strip() for v in os.getenv("FG_EVENT_ID_KEYS", "").split(",") if v.strip()
    ]
    return current, prev, from_list


def deterministic_event_id(
    tenant_id: str,
    agent_id: str,
    event_type: str,
    subject: str,
    bucket: str,
    features: dict,
) -> str:
    """Generate deterministic event IDs.

    Migration note: Core should accept both legacy SHA256 IDs and v2 HMAC IDs during cutover.
    """
    mode = os.getenv("FG_EVENT_ID_MODE", "hmac_v2").strip().lower()

    if mode == "legacy":
        # Legacy v1: SHA256 of canonical JSON (sorted keys, compact separators), NO canon_v.
        legacy_payload = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "event_type": event_type,
            "subject": subject,
            "bucket": bucket,
            "features": features,
        }
        legacy_bytes = json.dumps(
            legacy_payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(legacy_bytes).hexdigest()

    if mode != "hmac_v2":
        raise ValueError("FG_EVENT_ID_MODE must be either 'hmac_v2' or 'legacy'")

    # v2: canonical JSON + HMAC-SHA256, prefixed with ev2_
    payload = {
        "canon_v": EVENT_ID_CANON_VERSION,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "event_type": event_type,
        "subject": subject,
        "bucket": bucket,
        "features": features,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )

    current_key, _prev_key, keys = _event_id_keys()
    signing_key = current_key or (keys[0] if keys else "")
    if not signing_key:
        raise ValueError(
            "FG_EVENT_ID_MODE=hmac_v2 requires FG_EVENT_ID_KEY_CURRENT (preferred) or FG_EVENT_ID_KEYS"
        )

    digest = hmac.new(
        signing_key.encode("utf-8"), canonical, hashlib.sha256
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
