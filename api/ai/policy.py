from __future__ import annotations

import os
from dataclasses import dataclass

from sqlalchemy.orm import Session

from api.db_models import TenantAIConfig

_TRUE = {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class AISettings:
    disabled: bool
    model: str
    max_tokens: int
    temperature: float
    rag_enabled: bool
    model_allowlist: tuple[str, ...]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in _TRUE


def get_ai_settings() -> AISettings:
    allowlist_raw = (os.getenv("FG_AI_MODEL_ALLOWLIST") or "gpt-4o-mini,gpt-4o").strip()
    allowlist = tuple(m.strip() for m in allowlist_raw.split(",") if m.strip()) or (
        "gpt-4o-mini",
    )
    configured_model = (
        os.getenv("FG_AI_MODEL") or "gpt-4o-mini"
    ).strip() or "gpt-4o-mini"
    return AISettings(
        disabled=_env_bool("FG_AI_DISABLED", default=False),
        model=configured_model,
        max_tokens=max(32, min(int(os.getenv("FG_AI_MAX_TOKENS", "512")), 2048)),
        temperature=max(0.0, min(float(os.getenv("FG_AI_TEMPERATURE", "0.2")), 1.0)),
        rag_enabled=_env_bool("FG_RAG_ENABLED", default=False),
        model_allowlist=allowlist,
    )


def is_tenant_ai_enabled(db: Session, tenant_id: str) -> bool:
    cfg = db.get(TenantAIConfig, tenant_id)
    if cfg is None:
        return False
    return bool(cfg.ai_enabled)


def is_model_allowed(*, settings: AISettings, tenant_id: str) -> bool:
    """Centralized server-side model policy enforcement.

    Current behavior: global allowlist only. Tenant-specific override can be
    layered here later without touching routing logic. This policy module is
    also the intended attachment point for future per-tenant breaker/pacing
    behavior; current breaker scope is process-local.
    """
    _ = tenant_id
    return settings.model in set(settings.model_allowlist)
