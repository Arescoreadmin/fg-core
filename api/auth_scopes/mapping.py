from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import time
from typing import Optional

from api.config_versioning import canonicalize_config, hash_config
from api.db import _resolve_sqlite_path, init_db

from .definitions import DEFAULT_TTL_SECONDS
from .helpers import (
    _b64url,
    hash_key,
)

log = logging.getLogger("frostgate")


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


def _update_key_usage(
    sqlite_path: str,
    prefix: str,
    identifier_col: str,
    identifier: str,
    tenant_id: Optional[str] = None,
) -> None:
    """Atomically update last_used_at and use_count for a key (best effort)."""
    if (os.getenv("FG_DB_BACKEND") or "").strip().lower() == "postgres":
        try:
            from .store import update_key_usage as _pg_update_key_usage

            _pg_update_key_usage(
                prefix=prefix,
                identifier_col=identifier_col,
                identifier=identifier,
                tenant_id=tenant_id,
            )
        except Exception:
            pass
        return

    # SQLite path (unchanged)
    try:
        con = sqlite3.connect(sqlite_path, timeout=5.0)
        try:
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            if (
                "last_used_at" in col_names
                and "use_count" in col_names
                and identifier_col in col_names
            ):
                now_ts = int(time.time())
                con.execute(
                    """UPDATE api_keys
                       SET last_used_at = ?, use_count = use_count + 1
                       WHERE prefix = ? AND {col} = ?""".format(col=identifier_col),
                    (now_ts, prefix, identifier),
                )
                con.commit()
        finally:
            con.close()
    except Exception:
        pass


def mint_key(
    *scopes: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    tenant_id: Optional[str] = None,
    now: Optional[int] = None,
    secret: Optional[str] = None,
) -> str:
    """
    Mint a key and persist it into api_keys (legacy surface; R4.8 grandfathered).

    Dispatches to Postgres when FG_DB_BACKEND=postgres; SQLite otherwise.

    Returned key format:
      <prefix>.<token>.<secret>
    """
    now_i = int(now) if now is not None else int(time.time())
    exp_i = now_i + int(ttl_seconds)

    if secret is None:
        secret = secrets.token_urlsafe(32)

    prefix = "fgk"
    payload = {
        "scopes": list(scopes),
        "tenant_id": tenant_id,
        "iat": now_i,
        "exp": exp_i,
    }

    token = _b64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    key_hash, hash_alg, hash_params, key_lookup = hash_key(secret)
    scopes_csv = ",".join(scopes)

    if (os.getenv("FG_DB_BACKEND") or "").strip().lower() == "postgres":
        return _mint_key_postgres(
            scopes=scopes,
            prefix=prefix,
            token=token,
            secret=secret,
            key_hash=key_hash,
            hash_alg=hash_alg,
            hash_params=hash_params,
            key_lookup=key_lookup,
            scopes_csv=scopes_csv,
            tenant_id=tenant_id,
            now_i=now_i,
            exp_i=exp_i,
        )

    return _mint_key_sqlite(
        scopes=scopes,
        prefix=prefix,
        token=token,
        secret=secret,
        key_hash=key_hash,
        hash_alg=hash_alg,
        hash_params=hash_params,
        key_lookup=key_lookup,
        scopes_csv=scopes_csv,
        tenant_id=tenant_id,
        now_i=now_i,
        exp_i=exp_i,
    )


def _mint_key_postgres(
    *,
    scopes,
    prefix: str,
    token: str,
    secret: str,
    key_hash: str,
    hash_alg: str,
    hash_params: dict,
    key_lookup: str,
    scopes_csv: str,
    tenant_id: Optional[str],
    now_i: int,
    exp_i: int,
) -> str:
    if not tenant_id:
        raise ValueError(
            "tenant_id is required for Postgres key minting (FG_DB_BACKEND=postgres)"
        )

    from .store import insert_key_row

    insert_key_row(
        {
            "name": ("minted:" + (scopes_csv or "none"))[:128],
            "prefix": prefix,
            "key_hash": key_hash,
            "key_lookup": key_lookup,
            "hash_alg": hash_alg,
            "hash_params": hash_params,
            "scopes_csv": scopes_csv,
            "enabled": True,
            "tenant_id": tenant_id,
            "created_at": now_i,
            "expires_at": exp_i,
            "version": 1,
            "use_count": 0,
        }
    )
    return f"{prefix}.{token}.{secret}"


def _mint_key_sqlite(
    *,
    scopes,
    prefix: str,
    token: str,
    secret: str,
    key_hash: str,
    hash_alg: str,
    hash_params: dict,
    key_lookup: str,
    scopes_csv: str,
    tenant_id: Optional[str],
    now_i: int,
    exp_i: int,
) -> str:
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        sqlite_path = str(_resolve_sqlite_path())

    try:
        init_db(sqlite_path=sqlite_path)
    except Exception:
        log.exception("init_db failed in mint_key (best effort)")

    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        names = [r[1] for r in cols]
        notnull = {r[1] for r in cols if int(r[3] or 0) == 1 and r[4] is None}

        if (
            "hash_alg" not in names
            or "hash_params" not in names
            or "key_lookup" not in names
        ):
            raise RuntimeError("api_keys schema missing hash columns; run migrations")

        values = {
            "prefix": prefix,
            "key_hash": key_hash,
            "key_lookup": key_lookup,
            "hash_alg": hash_alg,
            "hash_params": json.dumps(
                hash_params, separators=(",", ":"), sort_keys=True
            ),
            "scopes_csv": scopes_csv,
            "enabled": 1,
        }

        if "name" in names:
            values["name"] = "minted:" + (scopes_csv or "none")

        if "tenant_id" in names:
            values["tenant_id"] = tenant_id
        if "created_at" in names and "created_at" in notnull:
            values["created_at"] = now_i
        if "expires_at" in names:
            values["expires_at"] = exp_i
        if "version" in names:
            values["version"] = 1
        if "use_count" in names:
            values["use_count"] = 0

        ordered = [
            c
            for c in (
                "name",
                "prefix",
                "key_hash",
                "key_lookup",
                "hash_alg",
                "hash_params",
                "scopes_csv",
                "tenant_id",
                "created_at",
                "expires_at",
                "enabled",
                "version",
                "use_count",
            )
            if c in names and c in values
        ]
        if not ordered:
            raise RuntimeError("api_keys table has no usable columns for insert")

        qcols = ",".join(ordered)
        qmarks = ",".join(["?"] * len(ordered))
        params = tuple(values[c] for c in ordered)
        con.execute(f"INSERT INTO api_keys({qcols}) VALUES({qmarks})", params)
        con.commit()
    finally:
        con.close()

    if tenant_id:
        _ensure_default_config_for_tenant(sqlite_path, tenant_id)

    return f"{prefix}.{token}.{secret}"


def revoke_api_key(
    key_prefix: str,
    tenant_id: Optional[str] = None,
    key_hash: Optional[str] = None,
) -> bool:
    if (os.getenv("FG_DB_BACKEND") or "").strip().lower() == "postgres":
        from .store import update_key_enabled

        rowcount = update_key_enabled(
            prefix=key_prefix,
            key_hash=key_hash,
            enabled=False,
            tenant_id=tenant_id,
        )
        revoked = rowcount > 0
        if revoked:
            from .resolution import _log_auth_event

            _log_auth_event("key_revoked", success=True, key_prefix=key_prefix)
        return revoked

    # SQLite path (unchanged)
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        return False

    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        col_names = {r[1] for r in cols}
        if tenant_id and "tenant_id" not in col_names:
            return False

        if key_hash:
            query = "UPDATE api_keys SET enabled=0 WHERE prefix=? AND key_hash=?"
            params = [key_prefix, key_hash]
        else:
            query = "UPDATE api_keys SET enabled=0 WHERE prefix=?"
            params = [key_prefix]

        if tenant_id:
            query += " AND tenant_id=?"
            params.append(tenant_id)

        cur = con.execute(query, params)
        con.commit()
        revoked = cur.rowcount > 0

        if revoked:
            from .resolution import _log_auth_event

            _log_auth_event("key_revoked", success=True, key_prefix=key_prefix)

        return revoked
    except Exception:
        log.exception("Failed to revoke API key")
        return False
    finally:
        con.close()


def list_api_keys(
    tenant_id: Optional[str] = None,
    include_disabled: bool = False,
) -> list[dict]:
    if (os.getenv("FG_DB_BACKEND") or "").strip().lower() == "postgres":
        from .store import list_key_rows

        return list_key_rows(tenant_id=tenant_id, include_disabled=include_disabled)

    # SQLite path (unchanged)
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        return []

    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        col_names = {r[1] for r in cols}

        select_cols = ["prefix", "scopes_csv", "enabled"]
        if "name" in col_names:
            select_cols.insert(1, "name")
        if "created_at" in col_names:
            select_cols.append("created_at")
        if "tenant_id" in col_names:
            select_cols.append("tenant_id")
        if "expires_at" in col_names:
            select_cols.append("expires_at")
        if "last_used_at" in col_names:
            select_cols.append("last_used_at")
        if "use_count" in col_names:
            select_cols.append("use_count")

        query = f"SELECT {','.join(select_cols)} FROM api_keys"
        conditions = []
        params: list[object] = []

        if not include_disabled:
            conditions.append("enabled=1")

        if tenant_id:
            if "tenant_id" not in col_names:
                return []
            conditions.append("tenant_id=?")
            params.append(tenant_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        rows = con.execute(query, params).fetchall()

        result = []
        for row in rows:
            item = dict(zip(select_cols, row))
            for ts_field in ("created_at", "expires_at", "last_used_at"):
                if ts_field in item and item[ts_field] is not None:
                    item[ts_field] = str(item[ts_field])

            scopes_csv = item.get("scopes_csv", "")
            item["scopes"] = [
                s.strip() for s in (scopes_csv or "").split(",") if s.strip()
            ]
            del item["scopes_csv"]
            result.append(item)

        return result
    except Exception:
        log.exception("Failed to list API keys")
        return []
    finally:
        con.close()
