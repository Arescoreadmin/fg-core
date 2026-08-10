#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

if str(Path(__file__).resolve().parents[2]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dataclasses import dataclass
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
DEFAULT_TENANT_ID = "tenant-seed-primary"
DEFAULT_ADMIN_KEY = "seedadmin_primary_key_000000000000"
DEFAULT_AGENT_KEY = "seedagent_primary_key_000000000000"
DEFAULT_AUDIT_HMAC_KEY = "seed-audit-hmac-key-material-000000"
DEFAULT_AUDIT_HMAC_KEY_ID = "seed-ak1"
DEFAULT_KEY_PEPPER = "seed-local-key-pepper-material-000000"
SEED_CREDENTIAL_TTL_SECONDS = 0
SEED_CREDENTIAL_SPECS = {
    "admin": {
        "slot": "seed-admin-key",
        "scopes": [
            "admin:read",
            "admin:write",
            "audit:read",
            "audit:export",
            "decisions:read",
            "defend:write",
            "ingest:write",
            "keys:read",
            "keys:write",
        ],
    },
    "agent": {
        "slot": "seed-agent-key",
        "scopes": [
            "decisions:read",
            "ingest:write",
        ],
    },
    "audit": {
        "slot": "seed-audit-gateway-key",
        "scopes": [
            "audit:read",
            "audit:export",
        ],
    },
}


class SeedBootstrapError(RuntimeError):
    pass


@dataclass(frozen=True)
class SeedConfig:
    sqlite_path: str
    registry_path: str
    state_path: str
    tenant_id: str


def _seed_key_prefix_identity(raw: str) -> str:
    return raw.split("_", 1)[0] + "_"


def _assert_distinct_key_prefixes(admin_key: str, agent_key: str) -> None:
    admin_prefix = _seed_key_prefix_identity(admin_key)
    agent_prefix = _seed_key_prefix_identity(agent_key)
    if admin_prefix == agent_prefix:
        raise SeedBootstrapError(
            "SEED_CONFLICT:key_prefix_collision "
            f"admin_prefix={admin_prefix} agent_prefix={agent_prefix}"
        )


def _json_dump(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _set_default_env() -> SeedConfig:
    sqlite_path = os.getenv("FG_SQLITE_PATH") or str(ROOT / "state" / "frostgate.db")
    registry_path = os.getenv("FG_TENANT_REGISTRY_PATH") or str(
        ROOT / "state" / "tenants.json"
    )
    state_path = os.getenv("FG_SEED_STATE_PATH") or str(
        ROOT / "state" / "seed" / "bootstrap_state.json"
    )
    tenant_id = os.getenv("FG_SEED_TENANT_ID") or DEFAULT_TENANT_ID

    os.environ["FG_SQLITE_PATH"] = sqlite_path
    os.environ["FG_TENANT_REGISTRY_PATH"] = registry_path
    os.environ.setdefault("FG_ADMIN_KEY", DEFAULT_ADMIN_KEY)
    os.environ.setdefault("FG_AGENT_KEY", DEFAULT_AGENT_KEY)
    _assert_distinct_key_prefixes(
        admin_key=os.environ["FG_ADMIN_KEY"],
        agent_key=os.environ["FG_AGENT_KEY"],
    )
    os.environ.setdefault("FG_AUDIT_HMAC_KEY_CURRENT", DEFAULT_AUDIT_HMAC_KEY)
    os.environ.setdefault("FG_AUDIT_HMAC_KEY_ID_CURRENT", DEFAULT_AUDIT_HMAC_KEY_ID)
    os.environ.setdefault("FG_KEY_PEPPER", DEFAULT_KEY_PEPPER)
    return SeedConfig(
        sqlite_path=sqlite_path,
        registry_path=registry_path,
        state_path=state_path,
        tenant_id=tenant_id,
    )


def _validate_existing_seed(config: SeedConfig) -> None:
    from api.db import get_engine
    from api.db_models import AuditLedgerRecord
    from sqlalchemy.orm import Session
    from tools.tenants.registry import load_registry

    marker = Path(config.state_path)
    if not marker.exists():
        return

    payload = _load_json(marker)
    expected = {
        "tenant_id": config.tenant_id,
        "sqlite_path": config.sqlite_path,
        "registry_path": config.registry_path,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise SeedBootstrapError(
                f"SEED_CONFLICT:{key} expected={value} found={payload.get(key)}"
            )

    registry = load_registry()
    if config.tenant_id not in registry:
        raise SeedBootstrapError("SEED_CONFLICT:tenant missing from registry on rerun")

    with Session(get_engine()) as db:
        has_ledger = (
            db.query(AuditLedgerRecord.id)
            .filter(AuditLedgerRecord.tenant_id == config.tenant_id)
            .first()
            is not None
        )
        if not has_ledger:
            raise SeedBootstrapError("SEED_CONFLICT:audit ledger rows missing on rerun")


def _ensure_seed_tenant_row(config: SeedConfig) -> None:
    from api.db import ensure_tenant_canonical_row, get_engine
    from api.tenant_repository import TenantRepository

    engine = get_engine()
    if engine.dialect.name == "sqlite":
        sqlite_path = engine.url.database or config.sqlite_path
        if sqlite_path and sqlite_path != ":memory:":
            ensure_tenant_canonical_row(str(sqlite_path), config.tenant_id)
        return

    TenantRepository(engine).upsert(
        config.tenant_id,
        "Primary Seed Tenant",
        lifecycle_state="active",
        tenant_kind="validation",
        migration_source="tools.seed.run_seed",
        migration_version="r4.11",
    )


def _seed_credential_is_valid(
    engine: Any,
    *,
    raw_key: str,
    tenant_id: str,
    role: str,
    scopes: list[str],
) -> bool:
    from api.credential_authority import validate_credential

    try:
        principal = validate_credential(engine, raw_key)
    except Exception:
        return False
    return (
        principal.tenant_id == tenant_id
        and principal.credential_slot == SEED_CREDENTIAL_SPECS[role]["slot"]
        and set(scopes).issubset(principal.scopes)
    )


def _issue_or_rotate_seed_credential(
    engine: Any,
    *,
    tenant_id: str,
    role: str,
    slot: str,
    scopes: list[str],
) -> str:
    from api.credential_authority import (
        CredentialStateError,
        issue_credential,
        rotate_credential,
    )

    try:
        result = issue_credential(
            engine,
            tenant_id=tenant_id,
            credential_type="tenant_api_key",
            credential_slot=slot,
            scopes=scopes,
            metadata={"seed_role": role},
            expires_in_seconds=SEED_CREDENTIAL_TTL_SECONDS,
            actor_id="tools.seed.run_seed",
        )
    except CredentialStateError:
        result = rotate_credential(
            engine,
            tenant_id=tenant_id,
            credential_type="tenant_api_key",
            credential_slot=slot,
            actor_id="tools.seed.run_seed",
            expires_in_seconds=SEED_CREDENTIAL_TTL_SECONDS,
        )

    if result.plaintext_secret is None:
        raise SeedBootstrapError(f"SEED_CONFLICT:{role} seed credential replayed")
    return result.plaintext_secret


def _ensure_seed_credentials(
    config: SeedConfig, payload: dict[str, Any]
) -> dict[str, Any]:
    from api.db import get_engine

    _ensure_seed_tenant_row(config)

    engine = get_engine()
    existing = payload.get("seed_credentials")
    credentials: dict[str, str] = dict(existing) if isinstance(existing, dict) else {}
    credential_status: dict[str, str] = {}

    for role, spec in SEED_CREDENTIAL_SPECS.items():
        field = f"{role}_api_key"
        scopes = list(spec["scopes"])
        current = credentials.get(field)
        if isinstance(current, str) and _seed_credential_is_valid(
            engine,
            raw_key=current,
            tenant_id=config.tenant_id,
            role=role,
            scopes=scopes,
        ):
            credential_status[role] = "existing"
            continue

        credentials[field] = _issue_or_rotate_seed_credential(
            engine,
            tenant_id=config.tenant_id,
            role=role,
            slot=str(spec["slot"]),
            scopes=scopes,
        )
        credential_status[role] = "issued" if current is None else "rotated"

    payload["seed_credentials"] = credentials
    payload["seed_credential_status"] = credential_status
    payload["ag_core_api_key"] = credentials["audit_api_key"]
    return payload


def _seed_once(config: SeedConfig) -> dict[str, Any]:
    from api.db import init_db, reset_engine_cache
    from services.audit_engine.engine import AuditEngine
    from tools.tenants.registry import ensure_tenant

    seed_marker = Path(config.state_path)
    if seed_marker.exists():
        _validate_existing_seed(config)
        payload = _load_json(seed_marker)
        payload = _ensure_seed_credentials(config, payload)
        payload["status"] = "already_seeded"
        seed_marker.write_text(_json_dump(payload), encoding="utf-8")
        return payload

    seed_marker.parent.mkdir(parents=True, exist_ok=True)

    reset_engine_cache()
    init_db(sqlite_path=config.sqlite_path)

    ensure_tenant(
        tenant_id=config.tenant_id,
        name="Primary Seed Tenant",
        api_key=os.environ["FG_ADMIN_KEY"],
    )
    _ensure_seed_tenant_row(config)

    engine = AuditEngine()
    session_id = engine.run_cycle("light", tenant_id=config.tenant_id)
    repro = engine.reproduce_session(session_id=session_id, tenant_id=config.tenant_id)
    if not repro.get("ok"):
        raise SeedBootstrapError(
            f"SEED_SMOKE_FAILED:reproduce_session:{_json_dump(repro)}"
        )

    export = engine.export_bundle(
        start="1970-01-01T00:00:00Z",
        end="9999-12-31T23:59:59Z",
        app_openapi={"openapi": "3.1.0"},
        tenant_id=config.tenant_id,
    )

    payload = {
        "export_path": export["path"],
        "registry_path": config.registry_path,
        "session_id": session_id,
        "sqlite_path": config.sqlite_path,
        "tenant_id": config.tenant_id,
    }
    payload = _ensure_seed_credentials(config, payload)
    seed_marker.write_text(_json_dump(payload), encoding="utf-8")
    return {**payload, "status": "seeded"}


def _internal_main() -> int:
    config = _set_default_env()
    result = _seed_once(config)
    print(_json_dump(result))
    return 0


def main() -> int:
    if "--internal" not in sys.argv:
        if not VENV_PYTHON.exists():
            print(
                f"SEED_PREREQ_FAILED:missing virtualenv interpreter at {VENV_PYTHON}",
                file=sys.stderr,
            )
            return 2
        proc = subprocess.run([str(VENV_PYTHON), str(Path(__file__)), "--internal"])
        return int(proc.returncode)

    try:
        return _internal_main()
    except SeedBootstrapError as exc:
        print(str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
