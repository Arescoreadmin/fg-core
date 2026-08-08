"""
api/auth_scopes/store.py

Retained after R4.9 for the probe_auth_store() connectivity check used by
startup validation and the readiness probe. All api_keys write functions
(insert_key_row, update_key_enabled, update_key_usage, list_key_rows) were
removed in R4.9 — they wrote dead-end data to api_keys that the Postgres auth
path could not verify (SHA-256 vs Argon2id mismatch; fallback cut in R4.8).

The probe now queries tenant_credentials, which is the canonical auth store.
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import text

log = logging.getLogger("frostgate")


def _resolve_backend() -> str:
    backend = (os.getenv("FG_DB_BACKEND") or "").strip().lower()
    return "postgres" if backend == "postgres" else "sqlite"


def _pg_engine():
    from api.db import get_engine

    return get_engine()


def probe_auth_store() -> tuple[bool, str]:
    """Probe the canonical credential store. Returns (ok, reason).

    Used by startup validation and readiness probe. Queries tenant_credentials
    (the canonical auth store since R4.9) without setting app.tenant_id, which
    returns 0 rows under RLS but confirms table existence and connectivity.
    """
    if _resolve_backend() != "postgres":
        return False, "not_postgres_backend"

    try:
        engine = _pg_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM tenant_credentials LIMIT 1"))
        return True, "auth_store_backend_ok"
    except Exception as exc:
        reason = type(exc).__name__
        if "UndefinedTable" in reason or "relation" in str(exc).lower():
            return False, "auth_store_schema_missing"
        return False, f"auth_store_unreachable:{reason}"
