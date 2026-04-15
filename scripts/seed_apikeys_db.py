#!/usr/bin/env python3
from __future__ import annotations

import os
import sqlite3
import time
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


def _deterministic_key_name(prefix: str) -> str:
    return f"seed:{prefix}"


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
    deterministic_name = _deterministic_key_name(prefix)

    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        col_names = [row[1] for row in cols]
        required_no_default = {
            row[1] for row in cols if int(row[3] or 0) == 1 and row[4] is None
        }
        now_ts = int(time.time())

        # Exact hash match: key already exists — just re-enable and sync scopes.
        existing = con.execute(
            "SELECT prefix FROM api_keys WHERE key_hash=? LIMIT 1", (key_h,)
        ).fetchone()
        if existing:
            update_cols = ["enabled=1", "scopes_csv=?"]
            params: list[object] = [scopes_csv]
            if "name" in col_names:
                update_cols.append("name=?")
                params.append(deterministic_name)
            con.execute(
                f"UPDATE api_keys SET {', '.join(update_cols)} WHERE key_hash=?",
                (*params, key_h),
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
            update_cols = ["key_hash=?", "scopes_csv=?", "enabled=1"]
            params = [key_h, scopes_csv]
            if "name" in col_names:
                update_cols.append("name=?")
                params.append(deterministic_name)
            con.execute(
                f"UPDATE api_keys SET {', '.join(update_cols)} WHERE id=?",
                (*params, prefix_row[0]),
            )
            con.commit()
            print(f"ok upserted prefix={prefix} scopes={scopes_csv}")
            return

        # No match: insert new row with all required non-null fields.
        values: dict[str, object] = {
            "prefix": prefix,
            "key_hash": key_h,
            "scopes_csv": scopes_csv,
            "enabled": 1,
        }
        if "name" in col_names:
            values["name"] = deterministic_name
        if "created_at" in required_no_default and "created_at" in col_names:
            values["created_at"] = now_ts
        if "version" in required_no_default and "version" in col_names:
            values["version"] = 1
        if "use_count" in required_no_default and "use_count" in col_names:
            values["use_count"] = 0

        missing_required = sorted(
            col
            for col in required_no_default
            if col not in values and col not in {"id"}
        )
        if missing_required:
            raise SystemExit(
                "api_keys schema requires unsupported columns for seed insert: "
                + ",".join(missing_required)
            )

        ordered_cols = [c for c in col_names if c in values]
        marks = ",".join(["?"] * len(ordered_cols))
        insert_params = tuple(values[c] for c in ordered_cols)
        con.execute(
            f"INSERT INTO api_keys({','.join(ordered_cols)}) VALUES ({marks})",
            insert_params,
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
