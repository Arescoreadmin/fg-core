from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from api.db_models import ConfigVersion, TenantActiveConfig

CONFIG_HASH_NOT_FOUND = "CONFIG_HASH_NOT_FOUND"
CONFIG_ACTIVE_MISSING = "CONFIG_ACTIVE_MISSING"
LEGACY_CONFIG_HASH = "legacy_config_hash"


def _config_error(
    *,
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> HTTPException:
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details:
        payload["error"]["details"] = details
    return HTTPException(status_code=status_code, detail=payload)


def _normalize_for_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize_for_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_for_json(v) for v in value]
    if isinstance(value, tuple):
        return [_normalize_for_json(v) for v in value]
    if isinstance(value, float):
        # normalize -0.0 to 0.0 for deterministic hashes
        if value == 0.0:
            return 0.0
        return value
    return value


def canonicalize_config(obj: Any) -> str:
    normalized = _normalize_for_json(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def hash_config(canonical_str: str) -> str:
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def verify_config_hash_integrity(*, config_payload: dict[str, Any], config_hash: str) -> bool:
    """Replay-safety invariant: hash must match canonical JSON of stored payload."""
    return hash_config(canonicalize_config(config_payload)) == config_hash


def create_config_version(
    db: Session,
    *,
    tenant_id: str,
    config_payload: dict[str, Any],
    created_by: str | None = None,
    parent_hash: str | None = None,
    set_active: bool = True,
) -> ConfigVersion:
    canonical = canonicalize_config(config_payload)
    config_hash = hash_config(canonical)
    if config_hash == LEGACY_CONFIG_HASH:
        raise _config_error(
            status_code=400,
            code=CONFIG_HASH_NOT_FOUND,
            message="requested config hash was not found",
        )

    version = (
        db.query(ConfigVersion)
        .filter(
            ConfigVersion.tenant_id == tenant_id,
            ConfigVersion.config_hash == config_hash,
        )
        .first()
    )
    if version is None:
        version = ConfigVersion(
            tenant_id=tenant_id,
            config_hash=config_hash,
            created_at=datetime.now(timezone.utc),
            created_by=created_by,
            config_json=config_payload,
            config_json_canonical=canonical,
            parent_hash=parent_hash,
        )
        db.add(version)
        db.flush()

    if set_active:
        active = db.get(TenantActiveConfig, tenant_id)
        if active is None:
            active = TenantActiveConfig(
                tenant_id=tenant_id,
                active_config_hash=config_hash,
                updated_at=datetime.now(timezone.utc),
            )
            db.add(active)
        else:
            active.active_config_hash = config_hash
            active.updated_at = datetime.now(timezone.utc)
        db.flush()

    return version


def resolve_config_hash(db: Session, *, tenant_id: str, requested_hash: str | None) -> str:
    if requested_hash:
        config_hash = requested_hash.strip()
        if not config_hash:
            raise _config_error(
                status_code=400,
                code=CONFIG_HASH_NOT_FOUND,
                message="requested config hash was not found",
            )
    else:
        active = db.get(TenantActiveConfig, tenant_id)
        if active is None or not active.active_config_hash:
            raise _config_error(
                status_code=503,
                code=CONFIG_ACTIVE_MISSING,
                message="active tenant config is missing",
            )
        config_hash = str(active.active_config_hash)

    exists = (
        db.query(ConfigVersion.config_hash)
        .filter(
            ConfigVersion.tenant_id == tenant_id,
            ConfigVersion.config_hash == config_hash,
        )
        .first()
    )
    if exists is None:
        raise _config_error(
            status_code=400,
            code=CONFIG_HASH_NOT_FOUND,
            message="requested config hash was not found",
            details={"config_hash": config_hash},
        )
    return config_hash


def load_config_version(db: Session, *, tenant_id: str, config_hash: str) -> ConfigVersion:
    version = (
        db.query(ConfigVersion)
        .filter(
            ConfigVersion.tenant_id == tenant_id,
            ConfigVersion.config_hash == config_hash,
        )
        .first()
    )
    if version is None:
        raise _config_error(
            status_code=400,
            code=CONFIG_HASH_NOT_FOUND,
            message="requested config hash was not found",
            details={"config_hash": config_hash},
        )
    return version
