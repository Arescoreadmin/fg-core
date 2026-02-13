from __future__ import annotations

import hashlib


def rate_limit_key(tenant_id: str, agent_id: str, route: str, api_key: str) -> str:
    hashed = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    return f"tenant:{tenant_id}|agent:{agent_id}|route:{route}|api_key_hash:{hashed}"
