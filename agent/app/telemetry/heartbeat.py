from __future__ import annotations

from datetime import datetime, timezone
import platform

from agent.app.config import deterministic_event_id, utc_bucket


def heartbeat_event(tenant_id: str, agent_id: str) -> dict:
    now = datetime.now(timezone.utc)
    bucket = utc_bucket(now)
    features = {"alive": True}
    return {
        "event_id": deterministic_event_id(
            tenant_id, agent_id, "heartbeat", agent_id, bucket, features
        ),
        "event_type": "heartbeat",
        "subject": agent_id,
        "features": features,
        "occurred_at": now.isoformat(),
    }


def agent_boot_event(
    tenant_id: str, agent_id: str, version: str, config_hash: str
) -> dict:
    now = datetime.now(timezone.utc)
    bucket = utc_bucket(now)
    features = {
        "version": version,
        "platform": platform.system().lower(),
        "config_hash": config_hash,
    }
    return {
        "event_id": deterministic_event_id(
            tenant_id, agent_id, "agent_boot", agent_id, bucket, features
        ),
        "event_type": "agent_boot",
        "subject": agent_id,
        "features": features,
        "occurred_at": now.isoformat(),
    }
