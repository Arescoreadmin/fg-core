from __future__ import annotations

import logging
import sqlite3
import uuid
from typing import Optional

from api.config_versioning import canonicalize_config, hash_config

log = logging.getLogger("frostgate")


def mint_key(
    *scopes: str,
    tenant_id: Optional[str] = None,
    **_ignored,
) -> str:
    """Issue a canonical tenant_api_key via the credential authority.

    Test-only shim replacing the legacy api_keys-backed mint_key.
    Uses issue_credential() with scopes embedded in the credential slot name.
    The plaintext_secret is returned in the same fgk.<token>.<secret> format.

    tenant_id defaults to 'tenant-test' when omitted so that tests that call
    mint_key() without an explicit tenant continue to work.
    """
    from api.credential_authority import issue_credential
    from api.db import ensure_tenant_canonical_row, get_engine, init_db

    resolved_tenant = tenant_id or "tenant-test"
    engine = get_engine()

    # Ensure SQLite schema and tenant row exist before calling issue_credential.
    # init_db() is idempotent; this handles callers that run before app lifespan fires.
    import os

    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if sqlite_path and engine.dialect.name == "sqlite":
        init_db()
        ensure_tenant_canonical_row(sqlite_path, resolved_tenant)

    scopes_tag = ",".join(scopes) if scopes else "none"
    slot = f"test-key:{scopes_tag}:{uuid.uuid4()}"
    result = issue_credential(
        engine,
        tenant_id=resolved_tenant,
        credential_type="tenant_api_key",
        credential_slot=slot,
        scopes=list(scopes) if scopes else None,
    )
    return result.plaintext_secret


def _ensure_default_config_for_tenant(sqlite_path: str, tenant_id: str) -> None:
    if not tenant_id:
        return

    canonical = canonicalize_config({})
    config_hash = hash_config(canonical)

    con = sqlite3.connect(sqlite_path)
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS config_versions (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                config_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                created_by TEXT,
                config_json JSON NOT NULL DEFAULT '{}',
                config_json_canonical TEXT NOT NULL,
                parent_hash TEXT,
                CONSTRAINT uq_config_versions_tenant_hash UNIQUE (tenant_id, config_hash)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_config_active (
                tenant_id TEXT PRIMARY KEY,
                active_config_hash TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )

        con.execute(
            """
            INSERT OR IGNORE INTO config_versions(
                tenant_id, config_hash, created_by, config_json, config_json_canonical
            ) VALUES (?, ?, 'mint_key', '{}', ?)
            """,
            (tenant_id, config_hash, canonical),
        )
        con.execute(
            """
            INSERT OR IGNORE INTO tenant_config_active(tenant_id, active_config_hash)
            VALUES (?, ?)
            """,
            (tenant_id, config_hash),
        )
        con.commit()
    finally:
        con.close()
