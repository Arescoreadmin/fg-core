#!/usr/bin/env python3
"""
tools/scripts/migrate_auth_sqlite_to_postgres.py

One-shot migration of existing SQLite api_keys rows into Postgres.

Usage:
    python tools/scripts/migrate_auth_sqlite_to_postgres.py [--dry-run]

Required env:
    FG_SQLITE_PATH  Path to the SQLite auth store file.
    FG_DB_URL       Postgres DSN (postgresql+psycopg://...).

Column conversions:
    created_at INTEGER  → UTC TIMESTAMPTZ
    expires_at INTEGER  → UTC TIMESTAMPTZ
    last_used_at INTEGER → UTC TIMESTAMPTZ
    hash_params TEXT JSON → JSONB dict
    enabled 1/0 → bool
    name NULL → "default"

Idempotent: INSERT ... ON CONFLICT (key_hash) DO NOTHING.

Does NOT modify the SQLite source.
Does NOT recompute key hashes.
Exits non-zero on any fatal error with a safe, secret-free message.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Optional


def _to_utc_dt(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _to_hash_params(value) -> Optional[dict]:
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


def _read_sqlite_rows(sqlite_path: str) -> list[dict]:
    con = sqlite3.connect(sqlite_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM api_keys").fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def _build_pg_row(row: dict) -> dict:
    return {
        "name": row.get("name") or "default",
        "prefix": row["prefix"],
        "key_hash": row["key_hash"],
        "key_lookup": row.get("key_lookup"),
        "hash_alg": row.get("hash_alg", "argon2id"),
        "hash_params": _to_hash_params(row.get("hash_params")),
        "scopes_csv": row.get("scopes_csv") or "",
        "enabled": bool(row.get("enabled", 1)),
        "tenant_id": row.get("tenant_id") or "unknown",
        "created_at": _to_utc_dt(row.get("created_at")),
        "expires_at": _to_utc_dt(row.get("expires_at")),
        "last_used_at": _to_utc_dt(row.get("last_used_at")),
        "version": int(row.get("version") or 1),
        "use_count": int(row.get("use_count") or 0),
        "created_by": row.get("created_by"),
        "description": row.get("description"),
        "rotated_from": row.get("rotated_from"),
    }


def run(dry_run: bool) -> None:
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    db_url = (os.getenv("FG_DB_URL") or "").strip()

    if not sqlite_path:
        print("ERROR: FG_SQLITE_PATH is not set.", file=sys.stderr)
        sys.exit(1)
    if not db_url:
        print("ERROR: FG_DB_URL is not set.", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(sqlite_path):
        print(f"ERROR: SQLite file not found: {sqlite_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading rows from SQLite: {sqlite_path}")
    try:
        rows = _read_sqlite_rows(sqlite_path)
    except sqlite3.Error as exc:
        print(f"ERROR: Failed to read SQLite: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)

    print(f"Rows read: {len(rows)}")

    if dry_run:
        print("[dry-run] Would attempt to insert the following rows into Postgres:")
        for r in rows:
            pg = _build_pg_row(r)
            print(
                f"  prefix={pg['prefix']!r} tenant_id={pg['tenant_id']!r} enabled={pg['enabled']}"
            )
        print("[dry-run] No changes made.")
        return

    try:
        from sqlalchemy import create_engine, text
    except ImportError:
        print("ERROR: sqlalchemy is required. Install it first.", file=sys.stderr)
        sys.exit(1)

    try:
        engine = create_engine(db_url, future=True)
    except Exception as exc:
        print(
            f"ERROR: Failed to create Postgres engine: {type(exc).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)

    inserted = 0
    skipped_existing = 0
    failed = 0

    for raw_row in rows:
        pg_row = _build_pg_row(raw_row)
        try:
            with engine.begin() as conn:
                # Set RLS context to the row's tenant_id before insert.
                conn.execute(
                    text("SELECT set_config('app.tenant_id', :tid, true)"),
                    {"tid": pg_row["tenant_id"]},
                )
                result = conn.execute(
                    text(
                        """
                        INSERT INTO api_keys
                          (name, prefix, key_hash, key_lookup, hash_alg, hash_params,
                           scopes_csv, enabled, tenant_id, created_at, expires_at,
                           last_used_at, version, use_count, created_by, description,
                           rotated_from)
                        VALUES
                          (:name, :prefix, :key_hash, :key_lookup, :hash_alg,
                           :hash_params, :scopes_csv, :enabled, :tenant_id,
                           :created_at, :expires_at, :last_used_at, :version,
                           :use_count, :created_by, :description, :rotated_from)
                        ON CONFLICT (key_hash) DO NOTHING
                        """
                    ),
                    pg_row,
                )
                if result.rowcount > 0:
                    inserted += 1
                else:
                    skipped_existing += 1
        except Exception as exc:
            failed += 1
            print(
                f"ERROR: Insert failed for prefix={raw_row.get('prefix', '?')!r}: "
                f"{type(exc).__name__}",
                file=sys.stderr,
            )

    print(
        f"\nMigration complete:\n"
        f"  rows_read:        {len(rows)}\n"
        f"  inserted:         {inserted}\n"
        f"  skipped_existing: {skipped_existing}\n"
        f"  failed:           {failed}"
    )

    if failed > 0:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Migrate api_keys from SQLite to Postgres."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read SQLite rows and print summary without writing to Postgres.",
    )
    args = parser.parse_args()
    run(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
