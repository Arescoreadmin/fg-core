# tools/tenants/registry.py

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

# Resolve project root: tools/tenants -> tools -> project_root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

# Allow override in tests / ops via env
DEFAULT_REGISTRY_PATH = STATE_DIR / "tenants.json"
REGISTRY_PATH = Path(os.getenv("FG_TENANT_REGISTRY_PATH", str(DEFAULT_REGISTRY_PATH)))


@dataclass
class TenantRecord:
    tenant_id: str
    name: str
    api_key: str
    status: str  # "active" | "revoked"
    created_at: str
    updated_at: str

    @classmethod
    def from_dict(cls, d: Dict) -> "TenantRecord":
        return cls(
            tenant_id=d["tenant_id"],
            name=d.get("name", d["tenant_id"]),
            api_key=d["api_key"],
            status=d.get("status", "active"),
            created_at=d.get("created_at", d.get("updated_at") or _now_iso()),
            updated_at=d.get("updated_at", _now_iso()),
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_raw() -> Dict[str, Dict]:
    if not REGISTRY_PATH.exists():
        return {}
    try:
        data = json.loads(REGISTRY_PATH.read_text())
        if not isinstance(data, dict):
            logger.warning("tenant_registry_invalid_root", path=str(REGISTRY_PATH))
            return {}
        return data
    except Exception as exc:
        logger.error("tenant_registry_read_error", path=str(REGISTRY_PATH), error=str(exc))
        return {}


def _save_raw(data: Dict[str, Dict]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = REGISTRY_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp_path.replace(REGISTRY_PATH)


def load_registry() -> Dict[str, TenantRecord]:
    raw = _load_raw()
    out: Dict[str, TenantRecord] = {}
    for tenant_id, payload in raw.items():
        try:
            out[tenant_id] = TenantRecord.from_dict(
                {"tenant_id": tenant_id, **payload}
            )
        except Exception as exc:
            logger.error(
                "tenant_registry_entry_invalid",
                tenant_id=tenant_id,
                error=str(exc),
            )
    return out


def save_registry(records: Dict[str, TenantRecord]) -> None:
    raw: Dict[str, Dict] = {tid: asdict(rec) for tid, rec in records.items()}
    # Strip tenant_id inside payload; keep keys as truth
    for tid, payload in raw.items():
        payload.pop("tenant_id", None)
    _save_raw(raw)


def generate_api_key() -> str:
    # Simple, strong, opaque key for headers/envs
    import secrets

    return secrets.token_urlsafe(32)


def ensure_tenant(
    tenant_id: str,
    name: Optional[str] = None,
    api_key: Optional[str] = None,
) -> TenantRecord:
    """
    Idempotent "upsert" for a tenant:
      - if exists: returns existing (no rotation)
      - if not: creates with generated api_key (or provided one)
    """
    records = load_registry()

    if tenant_id in records:
        return records[tenant_id]

    now = _now_iso()
    rec = TenantRecord(
        tenant_id=tenant_id,
        name=name or tenant_id,
        api_key=api_key or generate_api_key(),
        status="active",
        created_at=now,
        updated_at=now,
    )
    records[tenant_id] = rec
    save_registry(records)
    logger.info("tenant_created", tenant_id=tenant_id)
    return rec


def rotate_api_key(tenant_id: str) -> TenantRecord:
    records = load_registry()
    if tenant_id not in records:
        raise KeyError(f"Unknown tenant_id: {tenant_id}")

    rec = records[tenant_id]
    rec.api_key = generate_api_key()
    rec.updated_at = _now_iso()
    records[tenant_id] = rec
    save_registry(records)
    logger.info("tenant_key_rotated", tenant_id=tenant_id)
    return rec


def revoke_tenant(tenant_id: str) -> TenantRecord:
    records = load_registry()
    if tenant_id not in records:
        raise KeyError(f"Unknown tenant_id: {tenant_id}")

    rec = records[tenant_id]
    rec.status = "revoked"
    rec.updated_at = _now_iso()
    records[tenant_id] = rec
    save_registry(records)
    logger.info("tenant_revoked", tenant_id=tenant_id)
    return rec


def list_tenants(include_revoked: bool = True) -> List[TenantRecord]:
    records = load_registry()
    items = list(records.values())
    if not include_revoked:
        items = [r for r in items if r.status != "revoked"]
    return sorted(items, key=lambda r: r.tenant_id)
