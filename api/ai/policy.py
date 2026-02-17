from __future__ import annotations

import os
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from api.db_models import ConfigVersion, TenantActiveConfig


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on", "y"}


def ai_globally_disabled() -> bool:
    return _env_bool("FG_AI_DISABLED", default=False)


def rag_enabled() -> bool:
    return _env_bool("FG_RAG_ENABLED", default=False)


def ai_model_name() -> str:
    return (os.getenv("FG_AI_MODEL") or "gpt-4o-mini").strip() or "gpt-4o-mini"


def ai_temperature() -> float:
    raw = (os.getenv("FG_AI_TEMPERATURE") or "0.2").strip()
    try:
        value = float(raw)
    except ValueError:
        return 0.2
    return min(1.0, max(0.0, value))


def ai_max_tokens() -> int:
    raw = (os.getenv("FG_AI_MAX_TOKENS") or "512").strip()
    try:
        value = int(raw)
    except ValueError:
        return 512
    return min(2048, max(1, value))


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> HTTPException:
    payload: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    return HTTPException(status_code=status_code, detail=payload)


def assert_ai_enabled(db: Session, tenant_id: str) -> None:
    if ai_globally_disabled():
        raise error_response(503, "AI_DISABLED", "AI routes are disabled")

    active = db.get(TenantActiveConfig, tenant_id)
    if active is None or not active.active_config_hash:
        raise error_response(
            403,
            "AI_TENANT_DISABLED",
            "AI is not enabled for this tenant",
        )

    row = (
        db.query(ConfigVersion.config_json)
        .filter(
            ConfigVersion.tenant_id == tenant_id,
            ConfigVersion.config_hash == str(active.active_config_hash),
        )
        .first()
    )
    config_json: dict[str, Any] = (
        dict(row[0]) if row and isinstance(row[0], dict) else {}
    )
    ai_enabled = bool(config_json.get("ai_enabled", False))
    if not ai_enabled:
        raise error_response(
            403,
            "AI_TENANT_DISABLED",
            "AI is not enabled for this tenant",
        )
