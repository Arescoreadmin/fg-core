#!/usr/bin/env python3
from __future__ import annotations

import os
import sqlite3
from typing import Iterable, Tuple

from api.db import init_db
from api.db_models import hash_api_key


def _raw_key(s: str) -> str:
    """
    Accept either raw key or "RAW|scopes".
    We only want RAW.
    """
    return (s or "").strip().split("|", 1)[0].strip()


def _pairs_from_env() -> Iterable[Tuple[str, str]]:
    """
    Prefer explicit seed vars; fall back to FG_ADMIN_KEY/FG_AGENT_KEY.
    Scopes are pinned here, not in .env strings.
    """
    admin = _raw_key(os.getenv("FG_ADMIN_KEY", ""))
    agent = _raw_key(os.getenv("FG_AGENT_KEY", ""))
    audit_gw = _raw_key(os.getenv("FG_AUDIT_GW_KEY", "seedauditgwkey0_000000000000"))

    if not admin or not agent:
        raise SystemExit("Missing FG_ADMIN_KEY and/or FG_AGENT_KEY in env.")

    return [
        (admin, "decisions:read,defend:write,ingest:write"),
        (agent, "decisions:read,ingest:write"),
        (audit_gw, "audit:read,audit:export"),
    ]


def _prefix(raw: str) -> str:
    return raw.split("_", 1)[0] + "_"


def upsert_key(raw: str, scopes_csv: str) -> None:
    """
    Upsert a seeded API key using raw sqlite3 to avoid SQLAlchemy ORM type
    conversion errors (e.g. DateTime coercion when last_used_at is an integer
    set by _update_key_usage). Always idempotent.
    """
    init_db()
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        raise SystemExit("FG_SQLITE_PATH not set — cannot upsert seed keys.")

    prefix = _prefix(raw)
    key_h = hash_api_key(raw)

    con = sqlite3.connect(sqlite_path)
    try:
        # Exact hash match: key already exists — just re-enable and sync scopes.
        existing = con.execute(
            "SELECT prefix FROM api_keys WHERE key_hash=? LIMIT 1", (key_h,)
        ).fetchone()
        if existing:
            con.execute(
                "UPDATE api_keys SET enabled=1, scopes_csv=? WHERE key_hash=?",
                (scopes_csv, key_h),
            )
            con.commit()
            print(
                f"ok existing key_hash match prefix={existing[0]} scopes={scopes_csv}"
            )
            return

        # Prefix match: same prefix, different secret — replace hash and scopes.
        prefix_row = con.execute(
            "SELECT id FROM api_keys WHERE prefix=? LIMIT 1", (prefix,)
        ).fetchone()
        if prefix_row:
            con.execute(
                "UPDATE api_keys SET key_hash=?, scopes_csv=?, enabled=1 WHERE id=?",
                (key_h, scopes_csv, prefix_row[0]),
            )
            con.commit()
            print(f"ok upserted prefix={prefix} scopes={scopes_csv}")
            return

        # No match: insert new row with minimal required fields.
        # created_at defaults via SQLite server_default (func.now()).
        con.execute(
            "INSERT INTO api_keys(prefix, key_hash, scopes_csv, enabled)"
            " VALUES (?, ?, ?, 1)",
            (prefix, key_h, scopes_csv),
        )
        con.commit()
        print(f"ok upserted prefix={prefix} scopes={scopes_csv}")
    finally:
        con.close()


def main() -> None:
    for raw, scopes in _pairs_from_env():
        upsert_key(raw, scopes)


if __name__ == "__main__":
    main()
