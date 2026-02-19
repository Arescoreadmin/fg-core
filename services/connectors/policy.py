from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models import ConnectorTenantState
from services.canonical import canonical_json_bytes
from services.connectors.registry import list_connector_manifests
from services.schema_validation import validate_payload_against_schema

_POLICY_SCHEMA = Path("contracts/connectors/schema/policy.schema.json")
_POLICY_DIR = Path("contracts/connectors/policies")
_POLICY_SENTINEL = "__policy__"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _known_connector_ids() -> set[str]:
    return {str(item.get("id")) for item in list_connector_manifests() if item.get("id")}


def policy_changed_fields(old_policy: dict[str, Any], new_policy: dict[str, Any]) -> list[str]:
    keys = sorted(set(old_policy.keys()) | set(new_policy.keys()))
    changed: list[str] = []
    for key in keys:
        if old_policy.get(key) != new_policy.get(key):
            changed.append(key)
    return changed


def _validate_policy(payload: dict[str, Any]) -> None:
    schema = _load_json(_POLICY_SCHEMA)
    validate_payload_against_schema(payload, schema)

    known = _known_connector_ids()
    for cid in payload.get("enabled_connectors", []):
        if cid not in known:
            raise ValueError(f"UNKNOWN_CONNECTOR_REFERENCE:{cid}")

    scopes = payload.get("connector_scopes", {})
    for cid in scopes:
        if cid not in known:
            raise ValueError(f"UNKNOWN_CONNECTOR_REFERENCE:{cid}")


def _policy_path_for_version(version: str) -> Path:
    safe = str(version).strip()
    if not safe:
        raise ValueError("POLICY_VERSION_REQUIRED")
    path = _POLICY_DIR / f"{safe}.json"
    if not path.exists():
        raise ValueError("POLICY_VERSION_NOT_FOUND")
    return path


def tenant_policy_version(db: Session, tenant_id: str) -> str:
    row = db.execute(
        select(ConnectorTenantState).where(
            ConnectorTenantState.tenant_id == tenant_id,
            ConnectorTenantState.connector_id == _POLICY_SENTINEL,
        )
    ).scalar_one_or_none()
    if row is None:
        return "default"
    return str(row.config_hash)


def set_tenant_policy_version(
    db: Session, tenant_id: str, *, version: str, actor: str
) -> tuple[str, str]:
    _ = actor
    policy = load_policy(version)
    new_hash = policy_hash(policy)
    row = db.execute(
        select(ConnectorTenantState).where(
            ConnectorTenantState.tenant_id == tenant_id,
            ConnectorTenantState.connector_id == _POLICY_SENTINEL,
        )
    ).scalar_one_or_none()
    if row is None:
        row = ConnectorTenantState(
            tenant_id=tenant_id,
            connector_id=_POLICY_SENTINEL,
            enabled=True,
            config_hash=version,
        )
        db.add(row)
    else:
        row.config_hash = version
        row.enabled = True
    db.flush()
    return version, new_hash


def load_policy(version: str) -> dict[str, Any]:
    payload = _load_json(_policy_path_for_version(version))
    _validate_policy(payload)
    return payload


def load_tenant_policy(db: Session, tenant_id: str) -> tuple[str, dict[str, Any]]:
    version = tenant_policy_version(db, tenant_id)
    try:
        return version, load_policy(version)
    except Exception as exc:
        raise HTTPException(status_code=403, detail="CONNECTOR_POLICY_DENY") from exc


def policy_hash(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(policy)).hexdigest()


def enforce_connector_allowed(
    db: Session, tenant_id: str, connector_id: str
) -> dict[str, Any]:
    _version, policy = load_tenant_policy(db, tenant_id)
    enabled = set(policy.get("enabled_connectors") or [])
    if connector_id not in enabled:
        raise HTTPException(status_code=403, detail="CONNECTOR_DISABLED")
    return policy
