from __future__ import annotations

import json
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.engine import Engine

from api.auth_scopes import hash_key


def insert_api_key(
    engine: Engine,
    *,
    name: str | None,
    raw_key: str,
    scopes: Iterable[str] | str,
    enabled: bool = True,
) -> dict:
    """
    Insert an API key row into api_keys using current schema:
      prefix (NOT NULL), key_hash (NOT NULL), scopes_csv (NOT NULL), enabled (NOT NULL)

    Returns: dict of inserted row (id/prefix/key_hash/scopes_csv/enabled), best effort.
    """
    raw_key = str(raw_key).strip()
    if not raw_key:
        raise ValueError("raw_key cannot be empty")

    # prefix: everything before first '_' + '_' fallback first 8 chars + '_'
    if "_" in raw_key:
        prefix = raw_key.split("_", 1)[0] + "_"
    else:
        prefix = raw_key[:8] + "_"

    key_hash, hash_alg, hash_params, key_lookup = hash_key(raw_key)
    hash_params_json = json.dumps(hash_params, separators=(",", ":"), sort_keys=True)

    if isinstance(scopes, str):
        scopes_csv = scopes.strip()
    else:
        scopes_csv = ",".join(
            sorted({s.strip() for s in scopes if s and str(s).strip()})
        )

    sql = text(
        """
        INSERT INTO api_keys (name, prefix, key_hash, key_lookup, hash_alg, hash_params, scopes_csv, enabled)
        VALUES (:name, :prefix, :key_hash, :key_lookup, :hash_alg, :hash_params, :scopes_csv, :enabled)
        RETURNING id, name, prefix, key_hash, key_lookup, hash_alg, hash_params, scopes_csv, enabled
        """
    )

    with engine.begin() as conn:
        row = (
            conn.execute(
                sql,
                dict(
                    name=name,
                    prefix=prefix,
                    key_hash=key_hash,
                    key_lookup=key_lookup,
                    hash_alg=hash_alg,
                    hash_params=hash_params_json,
                    scopes_csv=scopes_csv,
                    enabled=enabled,
                ),
            )
            .mappings()
            .first()
        )

    return (
        dict(row)
        if row
        else {
            "prefix": prefix,
            "key_hash": key_hash,
            "key_lookup": key_lookup,
            "hash_alg": hash_alg,
            "hash_params": hash_params_json,
            "scopes_csv": scopes_csv,
            "enabled": enabled,
        }
    )
