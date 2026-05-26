"""
api/auth_scopes/store.py

Backend-dispatch key store for auth-scoped API keys.

Dispatches between Postgres (FG_DB_BACKEND=postgres) and SQLite
(FG_DB_BACKEND=sqlite or unset). SQLite reads are handled directly in
resolution.py / mapping.py for backward compatibility; this module
provides the Postgres implementation and the dispatch helpers.

Postgres path:
  - Uses SQLAlchemy engine from api.db.get_engine().
  - Parameterized text() queries only — no f-string SQL with user values.
  - All writes require tenant_id (NOT NULL constraint + RLS).
  - All reads require tenant_id_hint to satisfy the api_keys RLS policy.
    The hint comes from the token payload (decoded before DB lookup).
    Cryptographic verification (key_hash/key_lookup HMAC) is the real
    security gate; the RLS context only prevents cross-tenant row leakage.
  - No raw keys, secrets, peppers, hashes, or lookup hashes in logs.

Why this module writes directly rather than delegating to api/db/api_keys_store.py:
  api/db/api_keys_store.py::insert_api_key() takes a raw_key and re-hashes it.
  Auth-scopes minting already holds the pre-computed key_hash, key_lookup,
  hash_alg, hash_params, and the full column set (tenant_id, expires_at,
  version, use_count). Delegating would require re-hashing or a divergent
  signature. The two writers are acknowledged here: insert_api_key() is the
  admin-panel write helper; this module is the auth-scoped write path.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Literal, Optional

from sqlalchemy import text

log = logging.getLogger("frostgate")

# Static Postgres column set derived from migrations 0001–0004.
# PRAGMA introspection is not available in Postgres; column set is fixed.
_POSTGRES_STATIC_COLS: frozenset[str] = frozenset(
    {
        "id",
        "prefix",
        "key_hash",
        "key_lookup",
        "hash_alg",
        "hash_params",
        "scopes_csv",
        "enabled",
        "tenant_id",
        "expires_at",
        "last_used_at",
        "use_count",
        "created_at",
        "version",
    }
)

_PG_SELECT_COLS = ", ".join(sorted(_POSTGRES_STATIC_COLS))


def _resolve_backend() -> Literal["postgres", "sqlite"]:
    backend = (os.getenv("FG_DB_BACKEND") or "").strip().lower()
    return "postgres" if backend == "postgres" else "sqlite"


def _pg_engine():
    from api.db import get_engine

    return get_engine()


def _set_pg_tenant(conn, tenant_id: str) -> None:
    """Set app.tenant_id for the current transaction (satisfies RLS policy)."""
    conn.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": tenant_id},
    )


def get_key_row(
    *,
    prefix: str,
    lookup_hash: Optional[str],
    legacy_hash: Optional[str],
    tenant_id_hint: Optional[str] = None,
) -> tuple[dict | None, str | None, set[str]]:
    """Look up an api_keys row by prefix + lookup_hash or legacy_hash.

    Returns (row_dict or None, identifier_col used, available_col_names).

    Postgres: requires tenant_id_hint to set app.tenant_id for RLS.
    The hint is extracted from the token payload before this call; it is
    not yet cryptographically verified — verification happens after lookup.
    Without a valid tenant_id_hint, the RLS policy filters all rows and
    this returns (None, None, col_set).

    SQLite: caller handles this directly (resolution.py). Raises
    NotImplementedError if called in sqlite mode.
    """
    if _resolve_backend() != "postgres":
        raise NotImplementedError(
            "SQLite get_key_row is handled directly in resolution.py"
        )
    return _get_key_row_postgres(
        prefix=prefix,
        lookup_hash=lookup_hash,
        legacy_hash=legacy_hash,
        tenant_id_hint=tenant_id_hint,
    )


def _get_key_row_postgres(
    *,
    prefix: str,
    lookup_hash: Optional[str],
    legacy_hash: Optional[str],
    tenant_id_hint: Optional[str],
) -> tuple[dict | None, str | None, set[str]]:
    if not tenant_id_hint:
        # Cannot set RLS context without tenant_id; return not-found.
        return None, None, _POSTGRES_STATIC_COLS

    engine = _pg_engine()
    try:
        with engine.begin() as conn:
            _set_pg_tenant(conn, tenant_id_hint)

            if lookup_hash:
                row = (
                    conn.execute(
                        text(
                            f"SELECT {_PG_SELECT_COLS} FROM api_keys "
                            "WHERE prefix = :prefix AND key_lookup = :lookup LIMIT 1"
                        ),
                        {"prefix": prefix, "lookup": lookup_hash},
                    )
                    .mappings()
                    .first()
                )
                if row:
                    return dict(row), "key_lookup", _POSTGRES_STATIC_COLS

            if legacy_hash:
                row = (
                    conn.execute(
                        text(
                            f"SELECT {_PG_SELECT_COLS} FROM api_keys "
                            "WHERE prefix = :prefix AND key_hash = :keyhash LIMIT 1"
                        ),
                        {"prefix": prefix, "keyhash": legacy_hash},
                    )
                    .mappings()
                    .first()
                )
                if row:
                    return dict(row), "key_hash", _POSTGRES_STATIC_COLS

        return None, None, _POSTGRES_STATIC_COLS
    except Exception:
        log.exception(
            "Postgres get_key_row failed for prefix=%s",
            (prefix or "")[:8],
        )
        return None, None, _POSTGRES_STATIC_COLS


def _to_pg_timestamp(
    value: Optional[int | float | str | datetime],
) -> Optional[datetime]:
    """Convert SQLite INTEGER epoch or string to timezone-aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None
    return None


def _to_pg_hash_params(value) -> Optional[dict]:
    """Convert hash_params TEXT JSON string or dict to a Python dict for JSONB."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else None
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def insert_key_row(row: dict) -> None:
    """Insert a pre-built api_keys row into Postgres.

    Expects row to contain: prefix, key_hash, key_lookup, hash_alg,
    hash_params (dict or JSON string), scopes_csv, enabled, tenant_id
    (required — NOT NULL in Postgres), and optionally: name, created_at
    (INTEGER epoch or datetime), expires_at, version, use_count.

    Raises ValueError if tenant_id is missing.
    """
    if _resolve_backend() != "postgres":
        raise NotImplementedError("insert_key_row is Postgres-only")

    tenant_id = (row.get("tenant_id") or "").strip()
    if not tenant_id:
        raise ValueError("tenant_id is required for Postgres key insert")

    name = row.get("name") or "default"
    prefix = row["prefix"]
    key_hash = row["key_hash"]
    key_lookup = row.get("key_lookup")
    hash_alg = row.get("hash_alg", "argon2id")
    hash_params = _to_pg_hash_params(row.get("hash_params"))
    scopes_csv = row.get("scopes_csv", "")
    enabled_raw = row.get("enabled", 1)
    enabled = (
        bool(enabled_raw) if isinstance(enabled_raw, bool) else bool(int(enabled_raw))
    )
    created_at = _to_pg_timestamp(row.get("created_at")) or datetime.now(
        tz=timezone.utc
    )
    expires_at = _to_pg_timestamp(row.get("expires_at"))
    version = int(row.get("version") or 1)
    use_count = int(row.get("use_count") or 0)

    engine = _pg_engine()
    with engine.begin() as conn:
        _set_pg_tenant(conn, tenant_id)
        conn.execute(
            text(
                """
                INSERT INTO api_keys
                  (name, prefix, key_hash, key_lookup, hash_alg, hash_params,
                   scopes_csv, enabled, tenant_id, created_at, expires_at,
                   version, use_count)
                VALUES
                  (:name, :prefix, :key_hash, :key_lookup, :hash_alg, :hash_params,
                   :scopes_csv, :enabled, :tenant_id, :created_at, :expires_at,
                   :version, :use_count)
                """
            ),
            {
                "name": name,
                "prefix": prefix,
                "key_hash": key_hash,
                "key_lookup": key_lookup,
                "hash_alg": hash_alg,
                "hash_params": hash_params,
                "scopes_csv": scopes_csv,
                "enabled": enabled,
                "tenant_id": tenant_id,
                "created_at": created_at,
                "expires_at": expires_at,
                "version": version,
                "use_count": use_count,
            },
        )


def update_key_enabled(
    *,
    prefix: str,
    key_hash: Optional[str],
    enabled: bool,
    tenant_id: Optional[str] = None,
) -> int:
    """Set enabled on matching api_keys rows. Returns rowcount.

    Postgres: tenant_id required for RLS context.
    SQLite: tenant_id used as an optional filter (unchanged semantics).
    """
    if _resolve_backend() != "postgres":
        raise NotImplementedError("SQLite update_key_enabled handled in mapping.py")

    if not tenant_id:
        log.warning("update_key_enabled called without tenant_id in Postgres mode")
        return 0

    engine = _pg_engine()
    try:
        with engine.begin() as conn:
            _set_pg_tenant(conn, tenant_id)
            if key_hash:
                result = conn.execute(
                    text(
                        "UPDATE api_keys SET enabled = :enabled "
                        "WHERE prefix = :prefix AND key_hash = :key_hash "
                        "AND tenant_id = :tenant_id"
                    ),
                    {
                        "enabled": enabled,
                        "prefix": prefix,
                        "key_hash": key_hash,
                        "tenant_id": tenant_id,
                    },
                )
            else:
                result = conn.execute(
                    text(
                        "UPDATE api_keys SET enabled = :enabled "
                        "WHERE prefix = :prefix AND tenant_id = :tenant_id"
                    ),
                    {"enabled": enabled, "prefix": prefix, "tenant_id": tenant_id},
                )
            return result.rowcount
    except Exception:
        log.exception(
            "Postgres update_key_enabled failed for prefix=%s", (prefix or "")[:8]
        )
        return 0


def update_key_usage(
    *,
    prefix: str,
    identifier_col: str,
    identifier: str,
    tenant_id: Optional[str] = None,
) -> None:
    """Update last_used_at and use_count after successful auth (best-effort).

    Failure does not invalidate a successfully verified key.
    """
    if _resolve_backend() != "postgres":
        raise NotImplementedError("SQLite update_key_usage handled in mapping.py")

    if not tenant_id:
        return

    if identifier_col not in ("key_lookup", "key_hash"):
        log.warning(
            "update_key_usage: unexpected identifier_col=%s, skipping",
            identifier_col,
        )
        return

    engine = _pg_engine()
    try:
        with engine.begin() as conn:
            _set_pg_tenant(conn, tenant_id)
            now_dt = datetime.now(tz=timezone.utc)
            if identifier_col == "key_lookup":
                conn.execute(
                    text(
                        "UPDATE api_keys SET last_used_at = :now, "
                        "use_count = use_count + 1 "
                        "WHERE prefix = :prefix AND key_lookup = :identifier "
                        "AND tenant_id = :tenant_id"
                    ),
                    {
                        "now": now_dt,
                        "prefix": prefix,
                        "identifier": identifier,
                        "tenant_id": tenant_id,
                    },
                )
            else:
                conn.execute(
                    text(
                        "UPDATE api_keys SET last_used_at = :now, "
                        "use_count = use_count + 1 "
                        "WHERE prefix = :prefix AND key_hash = :identifier "
                        "AND tenant_id = :tenant_id"
                    ),
                    {
                        "now": now_dt,
                        "prefix": prefix,
                        "identifier": identifier,
                        "tenant_id": tenant_id,
                    },
                )
    except Exception:
        log.warning(
            "Postgres update_key_usage failed for prefix=%s (non-fatal)",
            (prefix or "")[:8],
        )


def list_key_rows(
    *,
    tenant_id: Optional[str] = None,
    include_disabled: bool = False,
) -> list[dict]:
    """List api_keys rows for a tenant. Postgres-only."""
    if _resolve_backend() != "postgres":
        raise NotImplementedError("SQLite list_key_rows handled in mapping.py")

    if not tenant_id:
        return []

    engine = _pg_engine()
    try:
        cols = "prefix, name, scopes_csv, enabled, tenant_id, created_at, expires_at, last_used_at, use_count"
        conditions = ["tenant_id = :tenant_id"]
        params: dict = {"tenant_id": tenant_id}

        if not include_disabled:
            conditions.append("enabled = true")

        where = " AND ".join(conditions)

        with engine.begin() as conn:
            _set_pg_tenant(conn, tenant_id)
            rows = (
                conn.execute(
                    text(
                        f"SELECT {cols} FROM api_keys WHERE {where} ORDER BY created_at DESC"
                    ),
                    params,
                )
                .mappings()
                .all()
            )

        result = []
        for row in rows:
            item = dict(row)
            scopes_csv = item.pop("scopes_csv", "") or ""
            item["scopes"] = [s.strip() for s in scopes_csv.split(",") if s.strip()]
            for ts_field in ("created_at", "expires_at", "last_used_at"):
                if ts_field in item and item[ts_field] is not None:
                    v = item[ts_field]
                    if isinstance(v, datetime):
                        item[ts_field] = v.isoformat()
                    else:
                        item[ts_field] = str(v)
            result.append(item)
        return result
    except Exception:
        log.exception("Postgres list_key_rows failed for tenant")
        return []


def probe_auth_store() -> tuple[bool, str]:
    """Probe the Postgres auth store. Returns (ok, reason).

    Used by startup validation and readiness probe.
    Runs SELECT 1 FROM api_keys LIMIT 1 without setting app.tenant_id,
    which returns 0 rows under RLS but confirms table existence and
    connectivity (no exception = table reachable).
    """
    if _resolve_backend() != "postgres":
        return False, "not_postgres_backend"

    try:
        engine = _pg_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM api_keys LIMIT 1"))
        return True, "auth_store_backend_ok"
    except Exception as exc:
        reason = type(exc).__name__
        if "UndefinedTable" in reason or "relation" in str(exc).lower():
            return False, "auth_store_schema_missing"
        return False, f"auth_store_unreachable:{reason}"
